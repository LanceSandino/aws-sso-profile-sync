package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/auth"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/configstore"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	t.Setenv("HOME", root)
	t.Setenv("AWS_CONFIG_FILE", root+"/.aws/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", root+"/credentials")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_SSO", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(key, "")
	}
	return root
}
func run(t *testing.T, args ...string) (Envelope, string, int) {
	t.Helper()
	var out, err bytes.Buffer
	code := Run(context.Background(), args, &out, &err)
	var e Envelope
	if er := json.Unmarshal(out.Bytes(), &e); er != nil {
		t.Fatalf("JSON %q: %v", out.String(), er)
	}
	return e, err.String(), code
}
func TestL01L02L03CLI(t *testing.T) {
	env(t)
	var out, err bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, &out, &err); code != 0 || !strings.Contains(err.String(), "AWS CLI uses its own SSO cache; sign in with aws sso login when needed.") {
		t.Fatal(code, err.String())
	}
	e, _, code := run(t, "--version", "--format", "json")
	if code != 0 || e.Version != Version {
		t.Fatal(code, e)
	}
	for _, args := range [][]string{{"--bad", "--format", "json"}, {"bogus", "--format", "json"}, {"list", "extra", "--format", "json"}, {"list", "--timeout", "0", "--format", "json"}, {"login", "--dry-run", "--format", "json"}} {
		var a, b bytes.Buffer
		if Run(context.Background(), args, &a, &b) == 0 {
			t.Fatal(args)
		}
	}
	e, _, code = run(t, "--dry-run", "--format", "json", "--sso-start-url", "https://sample.invalid/start")
	if code == 0 || e.Command != "plan" || e.Error.Code != "login_required" {
		t.Fatal(code, e)
	}
	t.Setenv("NO_COLOR", "1")
	var a, b bytes.Buffer
	Run(context.Background(), []string{"list"}, &a, &b)
	if strings.Contains(a.String(), "\x1b") || !strings.Contains(a.String(), "PROFILE") {
		t.Fatal(a.String())
	}
}
func TestA07OfflineAndInvalidInputs(t *testing.T) {
	root := env(t)
	for _, command := range []string{"list", "doctor"} {
		e, _, code := run(t, command, "--format", "json")
		if code != 0 || e.Status != "ok" {
			t.Fatal(code, e)
		}
		if _, err := os.Stat(root + "/.aws-sso-profile-sync"); !os.IsNotExist(err) {
			t.Fatal("offline wrote")
		}
	}
	for _, start := range []string{"", "http://sample.invalid", "https://user:pass@sample.invalid", "https://sample.invalid/?secret=x"} {
		e, _, code := run(t, "plan", "--format", "json", "--sso-start-url", start)
		if code == 0 || e.Error.Code != "config_invalid" {
			t.Fatal(start, code, e)
		}
	}
	e, _, code := run(t, "plan", "--format", "json", "--sso-start-url", "https://sample.invalid/start", "--test-endpoint", "https://aws.example:443")
	if code == 0 || e.Error.Code != "unsupported_endpoint" {
		t.Fatal(e)
	}
}
func TestC02OfflineMalformedAndL03ControlOutput(t *testing.T) {
	root := env(t)
	p := root + "/config"
	os.WriteFile(p, []byte("[bad"), 0600)
	e, _, code := run(t, "doctor", "--config-file", p, "--format", "json")
	if code == 0 || e.Error.Code != "config_invalid" {
		t.Fatal(e)
	}
	os.WriteFile(p, []byte("[profile bad\x1b[31m]\nregion=x\n"), 0600)
	var a, b bytes.Buffer
	Run(context.Background(), []string{"list", "--config-file", p}, &a, &b)
	if strings.Contains(a.String(), "\x1b") {
		t.Fatal("ANSI")
	}
}
func TestP10ResolveSessionRegion(t *testing.T) {
	env(t)
	s := configstore.Snapshot{Sections: map[string]map[string]string{"default": {"region": "eu-west-1"}, "sso-session old": {"sso_start_url": "https://sample.invalid/start", "sso_region": "us-east-1"}}}
	o := Options{Session: "default", StartURL: "https://sample.invalid/start/", SSORegion: "us-east-1"}
	session, e := ResolveSession(o, s)
	if e != nil || session.Name != "old" {
		t.Fatal(e, session)
	}
	s.Sections["sso-session other"] = s.Sections["sso-session old"]
	if _, e = ResolveSession(o, s); domain.ErrorCode(e) != "conflict" {
		t.Fatal(e)
	}
	o.Session = "old"
	o.SSORegion = "other"
	if _, e = ResolveSession(o, s); domain.ErrorCode(e) != "conflict" {
		t.Fatal(e)
	}
	o.Session = "\n"
	if _, e = ResolveSession(o, s); domain.ErrorCode(e) != "config_invalid" {
		t.Fatal(e)
	}
	if r, _ := ResolveRegion("ap-south-1", s); r != "ap-south-1" {
		t.Fatal(r)
	}
	t.Setenv("AWS_REGION", "us-west-1")
	if r, _ := ResolveRegion("", s); r != "us-west-1" {
		t.Fatal(r)
	}
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	if r, _ := ResolveRegion("", s); r != "us-west-2" {
		t.Fatal(r)
	}
	t.Setenv("AWS_DEFAULT_REGION", "")
	if r, _ := ResolveRegion("", s); r != "eu-west-1" {
		t.Fatal(r)
	}
}
func TestLocalCLIJourneyP08P09A08(t *testing.T) {
	testLocalCLIJourney(t, "AWSReadOnlyAccess")
}

func TestLocalCLIJourneyRoleNamesWithEquals(t *testing.T) {
	testLocalCLIJourney(t, "Team=ReadOnly")
}

func testLocalCLIJourney(t *testing.T, role string) {
	t.Helper()
	root := env(t)
	calls := 0
	invalid := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if invalid {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"__type":"UnauthorizedException"}`)
			return
		}
		switch r.URL.Path {
		case "/assignment/accounts":
			fmt.Fprint(w, `{"accountList":[{"accountId":"111111111111","accountName":"Sample Dev"}]}`)
		case "/assignment/roles":
			if err := json.NewEncoder(w).Encode(map[string]any{"roleList": []map[string]string{{"roleName": role}}}); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	base := []string{"--format", "json", "--sso-start-url", "https://sample.invalid/start", "--sso-session-name", "sample", "--test-root", root, "--test-endpoint", server.URL, "--open=false"}
	tokenStore := auth.Store{Root: root + "/.aws-sso-profile-sync/auth", Session: domain.Session{Name: "sample", StartURL: "https://sample.invalid/start", Region: "us-east-1"}, Endpoint: server.URL}
	if err := tokenStore.Save(auth.Token{AccessToken: "synthetic-token", ExpiresAt: time.Now().Add(time.Hour), Session: tokenStore.Session, Endpoint: server.URL}); err != nil {
		t.Fatal(err)
	}
	cacheBefore, _ := os.ReadFile(tokenStore.Path())
	settingsPath := writeSettings(t, root, `{"schema_version":1,"contexts":{"sample":{"sso_start_url":"https://sample.invalid/start","sso_session_name":"sample","region":"us-east-2","roles":["`+role+`"],"config_file":".aws/config","state_dir":".aws-sso-profile-sync"}}}`)
	configuredPlan, _, configuredCode := run(t, "plan", "--settings-file", settingsPath, "--test-root", root, "--test-endpoint", server.URL, "--format", "json")
	if configuredCode != 0 || len(configuredPlan.Results) != 1 || configuredPlan.Results[0].Status != "created" || !strings.Contains(configuredPlan.Explanation, "settings context") {
		t.Fatal("configured context did not drive isolated plan", configuredPlan)
	}
	e, _, code := run(t, append([]string{"plan"}, base...)...)
	if code != 0 || len(e.Results) != 1 || e.Results[0].Status != "created" || e.ConfigBefore == e.ConfigAfter {
		t.Fatal(code, e)
	}
	if _, err := os.Stat(root + "/.aws/config"); !os.IsNotExist(err) {
		t.Fatal("plan wrote")
	}
	cacheAfter, _ := os.ReadFile(tokenStore.Path())
	if !bytes.Equal(cacheBefore, cacheAfter) {
		t.Fatal("cache changed")
	}
	e, _, code = run(t, append([]string{"sync"}, base...)...)
	if code != 0 || e.Counts["created"] != 1 {
		t.Fatal(code, e)
	}
	configBefore, _ := os.ReadFile(root + "/.aws/config")
	sections, err := configstore.Parse(configBefore)
	if err != nil || sections["profile "+e.Results[0].Profile.Name]["sso_role_name"] != role {
		t.Fatal("saved role failed exact configuration round trip", err, sections)
	}
	e, _, code = run(t, "sync", "--settings-file", settingsPath, "--test-root", root, "--test-endpoint", server.URL, "--format", "json")
	configAfter, _ := os.ReadFile(root + "/.aws/config")
	if code != 0 || e.Counts["unchanged"] != 1 || !bytes.Equal(configBefore, configAfter) {
		t.Fatal(code, e)
	}
	e, _, code = run(t, append([]string{"discover"}, base...)...)
	if code != 0 || len(e.Assignments) != 1 {
		t.Fatal(e)
	}
	e, _, code = run(t, append([]string{"doctor", "--probe"}, base...)...)
	if code != 0 || len(e.Assignments) != 1 {
		t.Fatal(e)
	}
	e, _, code = run(t, append([]string{"list"}, base...)...)
	if code != 0 || len(e.Results) != 1 {
		t.Fatal(e)
	}
	t.Run("LoginGuidanceUsesSeparateAWSCLICache", func(t *testing.T) {
		var stderr string
		e, stderr, code = run(t, append([]string{"login"}, base...)...)
		want := "Named session cached securely. AWS CLI uses its own SSO cache; sign in with aws sso login when needed."
		if code != 0 || e.Explanation != want {
			t.Fatal("cached login did not explain the separate AWS CLI cache", code, e)
		}
		cacheAfterLogin, err := os.ReadFile(tokenStore.Path())
		if err != nil || !bytes.Equal(cacheBefore, cacheAfterLogin) || stderr != "" {
			t.Fatal("cached login changed tokens or requested device authorization", err, stderr)
		}
	})
	invalid = true
	e, _, code = run(t, append([]string{"sync"}, base...)...)
	if code == 0 || e.Error.Code != "auth_invalid" {
		t.Fatal(e)
	}
	invalid = false
	edited := bytes.ReplaceAll(configBefore, []byte("region = us-east-2"), []byte("region = us-west-1"))
	os.WriteFile(root+"/.aws/config", edited, 0600)
	infoBefore, _ := os.Stat(root + "/.aws/config")
	e, _, code = run(t, append([]string{"sync"}, base...)...)
	if code != 0 || e.Counts["unchanged"] != 1 || len(e.Warnings) == 0 || e.Warnings[0].Code != "setting_preserved" {
		t.Fatal("mutable region was not preserved with warning", e)
	}
	got, _ := os.ReadFile(root + "/.aws/config")
	infoAfter, _ := os.Stat(root + "/.aws/config")
	if !bytes.Equal(got, edited) || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("default sync rewrote preserved profile settings")
	}
	e, _, code = run(t, append([]string{"plan", "--override-profile-settings", "--region", "eu-west-1"}, base...)...)
	if code != 0 || e.Counts["updated"] != 1 || len(e.Diff) != 1 || e.Diff[0].Key != "region" || e.Diff[0].After != "eu-west-1" {
		t.Fatal("explicit managed-region override not planned", e)
	}
	// Identity edits still block synchronization, even with override authorization.
	os.WriteFile(root+"/.aws/config", bytes.ReplaceAll(configBefore, []byte("sso_role_name = "+role), []byte("sso_role_name = PowerUser")), 0600)
	e, _, code = run(t, append([]string{"sync", "--override-profile-settings"}, base...)...)
	if code == 0 || e.Counts["conflict"] != 1 {
		t.Fatal(e)
	}
	os.WriteFile(root+"/.aws/config", configBefore, 0600)
	os.Chmod(root+"/.aws", 0500)
	defer os.Chmod(root+"/.aws", 0700)
	e, _, code = run(t, append([]string{"sync", "--override-profile-settings", "--region", "eu-west-1", "--timeout", "30ms"}, base...)...)
	if code == 0 || e.Counts["failed"] != 1 {
		t.Fatal(e)
	}
	if calls == 0 {
		t.Fatal("no network tests")
	}
}

type badWriter struct{}

func (badWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write error") }
func TestL03OutputFailure(t *testing.T) {
	env(t)
	if Run(context.Background(), []string{"--version"}, badWriter{}, &bytes.Buffer{}) == 0 {
		t.Fatal("output succeeded")
	}
	if _, e := Parse([]string{"--format", "bad"}, &bytes.Buffer{}); e == nil {
		t.Fatal("bad format")
	}
	if _, e := Parse([]string{"--help"}, &bytes.Buffer{}); !errors.Is(e, flag.ErrHelp) {
		t.Fatal(e)
	}
}

func TestPlanExactDiffAndExplicitDefault(t *testing.T) {
	env(t)
	s := configstore.Snapshot{Sections: map[string]map[string]string{"profile sample": {"region": "us-east-1", "unknown": "private-secret"}}}
	changes := diff(s, map[string]map[string]string{"profile sample": {"region": "us-west-1", "output": "json"}})
	if len(changes) != 2 || changes[0].Before != nil || changes[1].Before == nil || *changes[1].Before != "us-east-1" {
		t.Fatal(changes)
	}
	var table bytes.Buffer
	e := emit(Envelope{Command: "plan", Status: "planned", Diff: changes, Results: []domain.Result{{Profile: domain.Profile{Name: "\x1bBAD"}, Status: "updated"}}, Assignments: []domain.Assignment{{AccountID: "111111111111", AccountName: "Sample", RoleName: "ReadOnly"}}}, "table", &table)
	if e != nil || strings.Contains(table.String(), "private-secret") || strings.Contains(table.String(), "\x1b") || !strings.Contains(table.String(), "BEFORE") {
		t.Fatal(e, table.String())
	}
	o, e := Parse([]string{"plan", "--sso-session-name", "default", "--sso-start-url", "https://sample.invalid/start"}, &bytes.Buffer{})
	if e != nil || !o.SessionExplicit {
		t.Fatal(e, o)
	}
	s.Sections["sso-session other"] = map[string]string{"sso_start_url": o.StartURL, "sso_region": o.SSORegion}
	session, e := ResolveSession(o, s)
	if e != nil || session.Name != "default" {
		t.Fatal(e, session)
	}
	if len(SafeDisplayProbe()) == 0 {
		t.Fatal("display")
	}
}
func SafeDisplayProbe() string { return display("normal\t\x1b") }
