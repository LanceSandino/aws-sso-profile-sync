// Package cli coordinates explicit login, discovery, read-only plans and safe sync.
// All side effects follow command authorization and validated isolated endpoint policy.
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/auth"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/awsclient"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/configstore"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/discovery"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/planner"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

type Options struct {
	Command, StartURL, Session, SSORegion, Region, Prefix, Output, Config, State, Format, Endpoint, TestRoot, SettingsFile, Context string
	Roles                                                                                                                           stringsFlag
	AutoPrefix, DryRun, Open, Probe, SessionExplicit, OverrideProfileSettings, RegionFromSettings                                   bool
	Timeout                                                                                                                         time.Duration
}
type Change struct {
	Section string  `json:"section"`
	Key     string  `json:"key"`
	Before  *string `json:"before"`
	After   string  `json:"after"`
}
type Envelope struct {
	SchemaVersion int                          `json:"schema_version"`
	Command       string                       `json:"command"`
	Status        string                       `json:"status"`
	Results       []domain.Result              `json:"results"`
	Assignments   []domain.Assignment          `json:"assignments"`
	Counts        map[string]int               `json:"counts"`
	Error         *domain.Error                `json:"error,omitempty"`
	Warnings      []domain.Warning             `json:"warnings,omitempty"`
	Explanation   string                       `json:"explanation,omitempty"`
	Changes       map[string]map[string]string `json:"changes,omitempty"`
	Diff          []Change                     `json:"diff,omitempty"`
	ConfigBefore  string                       `json:"config_hash_before,omitempty"`
	ConfigAfter   string                       `json:"config_hash_after,omitempty"`
	Version       string                       `json:"version,omitempty"`
}

const help = `aws-sso-profile-sync [login|discover|plan|sync|list|doctor] [flags]
login is explicit; plan/discover/list/doctor never log in or write token caches.
Legacy flags-only invocation maps to sync; --dry-run maps sync to plan.
Use --role repeatedly when multiple distinct roles are assigned.
--format json emits schema_version 1; --output controls AWS profile output.
AWS CLI uses its own SSO cache; sign in with aws sso login when needed.
`

func Parse(args []string, stderr io.Writer) (Options, error) {
	o := Options{Command: "sync"}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		o.Command = args[0]
		args = args[1:]
	}
	f := flag.NewFlagSet("aws-sso-profile-sync", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.Usage = func() { fmt.Fprint(stderr, help); f.PrintDefaults() }
	f.StringVar(&o.StartURL, "sso-start-url", "", "SSO tenant start URL (never guessed)")
	f.StringVar(&o.Session, "sso-session-name", "default", "named SSO session")
	f.StringVar(&o.SSORegion, "sso-region", "us-east-1", "SSO service region")
	f.StringVar(&o.Region, "region", "", "profile region: flag, AWS_REGION, AWS_DEFAULT_REGION, [default], us-east-2")
	f.Var(&o.Roles, "role", "selected role (repeatable)")
	f.StringVar(&o.Prefix, "prefix", "", "custom prefix; identity suffix prevents collisions")
	f.BoolVar(&o.AutoPrefix, "auto-prefix", true, "prefix from role name")
	f.BoolVar(&o.OverrideProfileSettings, "override-profile-settings", false, "explicitly replace existing managed profile region and output")
	f.StringVar(&o.Output, "output", "json", "AWS profile output format")
	f.StringVar(&o.Config, "config-file", os.Getenv("AWS_CONFIG_FILE"), "shared config path")
	f.StringVar(&o.State, "state-dir", "", "private tool token state directory")
	f.StringVar(&o.SettingsFile, "settings-file", "", "optional nonsecret JSON settings file")
	f.StringVar(&o.Context, "context", "", "named settings context; defaults file to ~/.aws-sso-profile-sync/settings.json")
	f.StringVar(&o.Format, "format", "table", "table or json")
	f.BoolVar(&o.DryRun, "dry-run", false, "strict read-only plan")
	f.BoolVar(&o.Open, "open", true, "open verification URL during explicit login")
	f.BoolVar(&o.Probe, "probe", false, "doctor: explicitly probe discovery")
	f.DurationVar(&o.Timeout, "timeout", 2*time.Minute, "bounded invocation deadline")
	f.StringVar(&o.Endpoint, "test-endpoint", "", "local emulator URL; requires --test-root and isolated env")
	f.StringVar(&o.TestRoot, "test-root", "", "disposable HOME root for local emulation")
	version := f.Bool("version", false, "print version")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	explicit := map[string]bool{}
	f.Visit(func(v *flag.Flag) {
		explicit[v.Name] = true
		if v.Name == "sso-session-name" {
			o.SessionExplicit = true
		}
	})
	if *version {
		o.Command = "version"
	}
	if f.NArg() != 0 {
		return o, domain.Fail("config_invalid", "unexpected positional arguments")
	}
	if o.Format != "json" && o.Format != "table" {
		return o, domain.Fail("config_invalid", "--format must be table or json")
	}
	if o.DryRun {
		if o.Command == "sync" {
			o.Command = "plan"
		} else if o.Command != "plan" {
			return o, domain.Fail("config_invalid", "--dry-run is valid only for plan or sync")
		}
	}
	switch o.Command {
	case "login", "discover", "plan", "sync", "list", "doctor", "version":
	default:
		return o, domain.Fail("config_invalid", "unknown command; use --help")
	}
	if o.Timeout <= 0 || o.Timeout > 10*time.Minute {
		return o, domain.Fail("config_invalid", "--timeout must be positive and at most 10m")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return o, domain.Fail("config_invalid", "HOME is required")
	}
	if err := applySettings(&o, explicit, home); err != nil {
		return o, err
	}
	if o.Config == "" {
		o.Config = filepath.Join(home, ".aws", "config")
	}
	if o.State == "" {
		o.State = filepath.Join(home, ".aws-sso-profile-sync")
	}
	o.Config, err = filepath.Abs(o.Config)
	if err != nil {
		return o, domain.Fail("config_invalid", "invalid config path")
	}
	o.State, err = filepath.Abs(o.State)
	if err != nil {
		return o, domain.Fail("config_invalid", "invalid state path")
	}
	return o, nil
}
func ResolveRegion(explicit string, s configstore.Snapshot) (string, string) {
	if explicit != "" {
		return explicit, "flag"
	}
	for _, key := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := os.Getenv(key); v != "" {
			return v, key + " env"
		}
	}
	if v := s.Sections["default"]["region"]; v != "" {
		return v, "existing [default] profile"
	}
	return "us-east-2", "default"
}
func ResolveSession(o Options, s configstore.Snapshot) (domain.Session, error) {
	session := domain.Session{Name: o.Session, StartURL: o.StartURL, Region: o.SSORegion}.Normalized()
	if session.StartURL == "" {
		return session, domain.Fail("config_invalid", "--sso-start-url is required for network commands")
	}
	u, err := url.Parse(session.StartURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return session, domain.Fail("config_invalid", "SSO start URL must be an HTTPS URL without credentials, query or fragment")
	}
	for _, v := range []string{session.Name, session.Region, session.StartURL} {
		if v == "" || strings.ContainsAny(v, "\r\n\x1b[]") {
			return session, domain.Fail("config_invalid", "unsafe or missing session value")
		}
	}
	if o.Session == "default" && !o.SessionExplicit {
		names := []string{}
		for name, keys := range s.Sections {
			if strings.HasPrefix(name, "sso-session ") && strings.TrimRight(keys["sso_start_url"], "/") == session.StartURL && keys["sso_region"] == session.Region {
				names = append(names, strings.TrimPrefix(name, "sso-session "))
			}
		}
		sort.Strings(names)
		if len(names) > 1 {
			return session, domain.Fail("conflict", "multiple matching sessions; choose --sso-session-name")
		}
		if len(names) == 1 {
			session.Name = names[0]
		}
	}
	if keys, ok := s.Sections["sso-session "+session.Name]; ok && (strings.TrimRight(keys["sso_start_url"], "/") != session.StartURL || keys["sso_region"] != session.Region) {
		return session, domain.Fail("conflict", "named session is bound to another URL or region")
	}
	return session, nil
}
func browser(ctx context.Context, u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", u)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", u)
	}
	return cmd.Run()
}
func Execute(ctx context.Context, o Options, stderr io.Writer) (Envelope, error) {
	out := Envelope{SchemaVersion: 1, Command: o.Command, Status: "ok", Results: []domain.Result{}, Assignments: []domain.Assignment{}, Counts: map[string]int{}}
	if o.Command == "version" {
		out.Version = Version
		return out, nil
	}
	if o.Endpoint != "" || o.TestRoot != "" {
		if err := awsclient.ValidateTestMode(o.TestRoot, o.Endpoint); err != nil {
			return out, err
		}
		for _, path := range []string{o.Config, o.State} {
			if err := awsclient.WithinTestRoot(o.TestRoot, path); err != nil {
				return out, err
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	store := configstore.Store{Path: o.Config}
	snapshot, err := store.Read()
	if err != nil {
		return out, err
	}
	if o.Command == "list" || o.Command == "doctor" {
		out.Warnings = configstore.DuplicateProfiles(snapshot.Sections)
	}
	if o.Command == "list" || o.Command == "doctor" && !o.Probe {
		names := []string{}
		for n := range snapshot.Sections {
			if strings.HasPrefix(n, "profile ") {
				names = append(names, strings.TrimPrefix(n, "profile "))
			}
		}
		sort.Strings(names)
		for _, n := range names {
			p, owned := snapshot.Owned[n]
			reason := "unmanaged profile; preserved"
			if !owned {
				p = domain.Profile{Name: n}
			} else {
				reason = "tool-owned profile"
			}
			out.Results = append(out.Results, domain.Result{Profile: p, Status: "unchanged", Reason: reason})
		}
		if o.Command == "doctor" {
			out.Explanation = "Config parses strictly; offline diagnostics performed. Use --probe explicitly for network discovery."
		}
		count(&out)
		return out, nil
	}
	session, err := ResolveSession(o, snapshot)
	if err != nil {
		return out, err
	}
	cfg, err := awsclient.New(session.Region, o.Endpoint, o.TestRoot)
	if err != nil {
		return out, err
	}
	tokenStore := auth.Store{Root: filepath.Join(o.State, "auth"), Session: session, Endpoint: o.Endpoint}
	portal := sso.NewFromConfig(cfg)
	manager := auth.Manager{Client: ssooidc.NewFromConfig(cfg), Store: tokenStore, Validate: func(ctx context.Context, token string) error {
		_, e := (discovery.Service{Client: portal, Workers: 4}).Discover(ctx, token)
		return e
	}, Notify: func(u string) error {
		parsed, e := url.Parse(u)
		if e != nil || parsed.User != nil || parsed.Host == "" {
			return domain.Fail("auth_invalid", "invalid device verification URL")
		}
		if o.Endpoint != "" {
			local, _ := url.Parse(o.Endpoint)
			ip := net.ParseIP(parsed.Hostname())
			if parsed.Scheme != "http" || (parsed.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) || parsed.Path != "/device" || parsed.Query().Get("user_code") == "" || len(parsed.Query()) != 1 {
				return awsclient.GuardError()
			}
			parsed.Scheme = local.Scheme
			parsed.Host = local.Host
			u = parsed.String()
		} else if parsed.Scheme != "https" {
			return domain.Fail("auth_invalid", "device URL must use HTTPS")
		}
		fmt.Fprintln(stderr, "Authorize this explicit login:", u)
		if o.Open && o.Endpoint == "" {
			if e := browser(ctx, u); e != nil {
				fmt.Fprintln(stderr, "Browser could not open; use the verification URL above.")
			}
		}
		return nil
	}}
	if o.Command == "login" {
		err = manager.Login(ctx)
		if err == nil {
			out.Explanation = "Named session cached securely. AWS CLI uses its own SSO cache; sign in with aws sso login when needed."
		}
		return out, err
	}
	token, err := manager.Access(ctx, false)
	if err != nil {
		return out, err
	}
	assignments, err := (discovery.Service{Client: portal, Workers: 4}).Discover(ctx, token)
	if err != nil {
		return out, err
	}
	out.Assignments = assignments
	if o.Command == "discover" || o.Command == "doctor" {
		return out, nil
	}
	region, source := ResolveRegion(o.Region, snapshot)
	if o.RegionFromSettings && source == "flag" {
		source = "settings context"
	}
	plan, err := planner.Build(snapshot, assignments, planner.Options{Session: session, Region: region, Output: o.Output, Prefix: o.Prefix, AutoPrefix: o.AutoPrefix, Roles: o.Roles, OverrideProfileSettings: o.OverrideProfileSettings})
	if err != nil {
		return out, err
	}
	out.Results = plan.Results
	out.Warnings = plan.Warnings
	out.Explanation = plan.Explanation + " Profile region from " + source
	out.Changes = plan.Sections
	out.Diff = diff(snapshot, plan.Sections)
	out.ConfigBefore = snapshot.Hash
	after, err := configstore.Preview(snapshot, plan.Sections)
	if err != nil {
		return out, err
	}
	out.ConfigAfter = fmt.Sprintf("%x", sha256.Sum256(after))
	if plan.HasConflicts() {
		count(&out)
		return out, domain.Fail("conflict", "plan contains conflicting profiles; configuration was not changed")
	}
	if o.Command == "sync" {
		if err = store.Apply(ctx, snapshot, plan.Sections, plan.Owned); err != nil {
			for i := range out.Results {
				if out.Results[i].Status == "created" || out.Results[i].Status == "updated" {
					out.Results[i].Status = "failed"
					out.Results[i].Reason = "transaction did not establish a verified commit"
				}
			}
			count(&out)
			return out, err
		}
	}
	if o.Command == "plan" {
		out.Status = "planned"
	}
	count(&out)
	return out, nil
}
func count(out *Envelope) {
	for _, r := range out.Results {
		out.Counts[r.Status]++
	}
}
func emit(out Envelope, format string, stdout io.Writer) error {
	if format == "json" {
		return json.NewEncoder(stdout).Encode(out)
	}
	if out.Version != "" {
		_, e := fmt.Fprintln(stdout, out.Version)
		return e
	}
	fmt.Fprintf(stdout, "%s (%s)\n", out.Command, out.Status)
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tSTATUS\tACCOUNT\tROLE\tREASON")
	for _, r := range out.Results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", display(r.Profile.Name), r.Status, display(r.Profile.Assignment.AccountID), display(r.Profile.Assignment.RoleName), display(r.Reason))
	}
	for _, a := range out.Assignments {
		fmt.Fprintf(w, "\tassigned\t%s\t%s\t%s\n", a.AccountID, planner.SafeName(a.RoleName), planner.SafeName(a.AccountName))
	}
	if len(out.Diff) > 0 {
		fmt.Fprintln(w, "SECTION\tKEY\tBEFORE\tAFTER")
		for _, d := range out.Diff {
			before := "<absent>"
			if d.Before != nil {
				before = display(*d.Before)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", display(d.Section), d.Key, before, display(d.After))
		}
	}
	if len(out.Warnings) > 0 {
		fmt.Fprintln(w, "WARNING\tPROFILES\tFIELD\tEXISTING\tREQUESTED\tIDENTITY")
		for _, warning := range out.Warnings {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", display(warning.Code), display(strings.Join(warning.Profiles, ", ")), display(warning.Field), display(warning.Existing), display(warning.Requested), display(warning.IdentityKey))
		}
	}
	if e := w.Flush(); e != nil {
		return e
	}
	_, e := fmt.Fprintln(stdout, out.Explanation)
	return e
}
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, err := Parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	out := Envelope{SchemaVersion: 1, Command: o.Command, Results: []domain.Result{}, Assignments: []domain.Assignment{}, Counts: map[string]int{}}
	if err == nil {
		out, err = Execute(ctx, o, stderr)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = domain.Fail("canceled", "operation canceled")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			err = domain.Fail("timed_out", "operation deadline exceeded")
		}
		for i, a := range args {
			if a == "--format=json" || a == "-format=json" || (a == "--format" || a == "-format") && i+1 < len(args) && args[i+1] == "json" {
				o.Format = "json"
			}
		}
		code := domain.ErrorCode(err)
		msg := err.Error()
		var typed *domain.Error
		if !errors.As(err, &typed) {
			msg = "invalid arguments or operation failed; use --help"
		}
		msg = display(msg)
		out.Status = code
		out.Error = &domain.Error{Code: code, Message: msg}
		fmt.Fprintln(stderr, msg)
	}
	if e := emit(out, o.Format, stdout); e != nil {
		fmt.Fprintln(stderr, "output failed")
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func display(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

func diff(snapshot configstore.Snapshot, sections map[string]map[string]string) []Change {
	changes := []Change{}
	names := []string{}
	for n := range sections {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		keys := []string{}
		for k := range sections[n] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, exists := snapshot.Sections[n][k]
			after := sections[n][k]
			if exists && v == after {
				continue
			}
			c := Change{Section: n, Key: k, After: after}
			if exists {
				c.Before = &v
			}
			changes = append(changes, c)
		}
	}
	return changes
}
