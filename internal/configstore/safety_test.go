package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

func TestC01NestedAndInlineComments(t *testing.T) {
	b := []byte("[profile dev]\r\ns3 =\r\n  region = child\r\nregion  = old  # retain\r\nx = unknown\r\n")
	out, e := render(b, map[string]map[string]string{"profile dev": {"region": "new", "output": "json"}})
	if e != nil || !strings.Contains(string(out), "  region = child\r\nregion  = new  # retain\r\n") || !strings.Contains(string(out), "x = unknown\r\n") {
		t.Fatal(string(out), e)
	}
	parsed, e := Parse(out)
	if e != nil || parsed["profile dev"]["region"] != "new" || !strings.Contains(parsed["profile dev"]["s3"], "child") {
		t.Fatal(parsed, e)
	}
	out, e = render([]byte("[profile dev]\nregion=old"), map[string]map[string]string{"profile dev": {"region": "new", "output": "json"}})
	if e != nil || string(out) != "[profile dev]\nregion=new\noutput = json\n" {
		t.Fatal(string(out), e)
	}
	for _, b := range []string{"\x00", "[]\n", "[a]\nx = value ; comment\n"} {
		_, _ = Parse([]byte(b))
	}
	for _, up := range []map[string]map[string]string{{"bad\nname": {"k": "v"}}, {"profile p": {"bad key": "v"}}, {"profile p": {"k": "bad\nvalue"}}} {
		if _, e = render(nil, up); e == nil {
			t.Fatal("accepted injection")
		}
	}
}

func TestC05NewFileModes(t *testing.T) {
	s, b, up, owned := fixture(t)
	preview, e := Preview(b, up)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Dir(s.Path)); !os.IsNotExist(e) {
		t.Fatal("preview wrote", e)
	}
	if e := s.Apply(context.Background(), b, up, owned); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(s.Path)
	if e != nil || string(got) != string(preview) {
		t.Fatal("preview differs", e)
	}
	for _, path := range []string{s.Path, s.Path + ".aws-sso-sync.json"} {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal(info, e)
		}
	}
}

func TestC08ConcurrentWriters(t *testing.T) {
	s, b, up, owned := fixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Apply(context.Background(), b, up, owned) }()
	}
	wg.Wait()
	close(errs)
	passed, conflicted := 0, 0
	for e := range errs {
		if e == nil {
			passed++
		} else if domain.ErrorCode(e) == "conflict" {
			conflicted++
		} else {
			t.Fatal(e)
		}
	}
	if passed != 1 || conflicted != 1 {
		t.Fatal(passed, conflicted)
	}
	got, e := s.Read()
	if e != nil || len(got.Owned) != 1 || len(got.Sections) != 2 {
		t.Fatal(got, e)
	}
}

func TestC08LockDeadlineAndCancellation(t *testing.T) {
	s, b, up, owned := fixture(t)
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	unlock, e := lock(context.Background(), s.Path+".aws-sso-sync.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	started := time.Now()
	if e := s.Apply(context.Background(), b, up, owned); domain.ErrorCode(e) != "timed_out" {
		t.Fatal(e)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("unbounded lock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.Apply(ctx, b, up, owned); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestC08LockReleasedAfterProcessDeath(t *testing.T) {
	if child := os.Getenv("AWS_SSO_SYNC_LOCK_CHILD"); child != "" {
		release, e := lock(context.Background(), child)
		if e != nil {
			t.Fatal(e)
		}
		defer release()
		if e = os.WriteFile(child+".ready", nil, 0600); e != nil {
			t.Fatal(e)
		}
		time.Sleep(5 * time.Second)
		return
	}
	s, _, _, _ := fixture(t)
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	path := s.Path + ".aws-sso-sync.lock"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestC08LockReleasedAfterProcessDeath$")
	cmd.Env = append(os.Environ(), "AWS_SSO_SYNC_LOCK_CHILD="+path)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Process.Kill()
	ready := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(path + ".ready"); e == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("child did not acquire lock")
	}
	if e := cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	cmd.Wait()
	unlock, e := lock(ctx, path)
	if e != nil {
		t.Fatal("crash retained lock", e)
	}
	unlock()
}

func TestC07OnlySystemAliasesAllowed(t *testing.T) {
	if runtime.GOOS != "darwin" {
		return
	}
	root, e := os.MkdirTemp("/private/tmp", "aws-sso-alias-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	s := Store{Path: strings.Replace(root, "/private/tmp", "/tmp", 1) + "/config"}
	if _, e = s.Read(); e != nil {
		t.Fatal("system tmp alias refused", e)
	}
	canonical := tempRoot(t)
	if strings.HasPrefix(canonical, "/private/var/") {
		s.Path = strings.Replace(canonical, "/private/var", "/var", 1) + "/config"
		if _, e = s.Read(); e != nil {
			t.Fatal("system var alias refused", e)
		}
	}
}

func TestC09MidCommitExternalEdit(t *testing.T) {
	s, b, up, owned := fixture(t)
	s.Fault = func(stage string) error {
		if stage == "rename" {
			return os.WriteFile(s.Path, []byte("[default]\nregion=external\n"), 0600)
		}
		return nil
	}
	if e := s.Apply(context.Background(), b, up, owned); domain.ErrorCode(e) != "conflict" {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(s.Path)
	if string(got) != "[default]\nregion=external\n" {
		t.Fatal(string(got))
	}
	if _, e := s.Read(); domain.ErrorCode(e) != "conflict" {
		t.Fatal("uncertain intent not diagnosed", e)
	}
}

func TestC12ReadbackFailureAndUncommittedRecovery(t *testing.T) {
	for _, stage := range []string{"readback", "temp_write"} {
		t.Run(stage, func(t *testing.T) {
			s, b, up, owned := fixture(t)
			s.Fault = func(v string) error {
				if v == stage {
					return errors.New("injected")
				}
				return nil
			}
			if e := s.Apply(context.Background(), b, up, owned); e == nil {
				t.Fatal("false success")
			}
			s.Fault = nil
			snap, e := s.Read()
			if e != nil {
				t.Fatal(e)
			}
			if e = s.Apply(context.Background(), snap, up, owned); e != nil {
				t.Fatal(e)
			}
			if _, e = s.Read(); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestC02CorruptStateAndDirectories(t *testing.T) {
	for _, suffix := range []string{"", ".aws-sso-sync.json", ".aws-sso-sync.intent"} {
		s, _, _, _ := fixture(t)
		os.MkdirAll(filepath.Dir(s.Path), 0700)
		os.Mkdir(s.Path+suffix, 0700)
		if _, e := s.Read(); e == nil {
			t.Fatal("accepted directory", suffix)
		}
	}
	for _, suffix := range []string{".aws-sso-sync.json", ".aws-sso-sync.intent"} {
		s, _, _, _ := fixture(t)
		os.MkdirAll(filepath.Dir(s.Path), 0700)
		os.WriteFile(s.Path+suffix, []byte("{"), 0600)
		if _, e := s.Read(); e == nil {
			t.Fatal("accepted bad state")
		}
	}
	s, b, up, owned := fixture(t)
	if e := s.Apply(context.Background(), b, up, owned); e != nil {
		t.Fatal(e)
	}
	os.Chmod(s.Path+".aws-sso-sync.json", 0666)
	if _, e := s.Read(); e == nil {
		t.Fatal("accepted writable state")
	}
	if _, e := (Store{}).Read(); e == nil {
		t.Fatal("empty path")
	}
	s, _, _, _ = fixture(t)
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	os.WriteFile(s.Path, []byte("broken"), 0600)
	if _, e := s.Read(); domain.ErrorCode(e) != "config_invalid" {
		t.Fatal(e)
	}
}

func TestC13OwnershipIntentGuards(t *testing.T) {
	s, b, up, owned := fixture(t)
	other := b
	other.Path += "other"
	if e := s.Apply(context.Background(), other, up, owned); e == nil {
		t.Fatal("path guard")
	}
	if e := s.Apply(context.Background(), b, map[string]map[string]string{"default": {"region": "x"}}, owned); e == nil {
		t.Fatal("default takeover")
	}
	if e := s.Apply(context.Background(), b, up, map[string]domain.Profile{}); e == nil {
		t.Fatal("missing ownership")
	}
	if e := s.Apply(context.Background(), b, map[string]map[string]string{}, owned); e == nil {
		t.Fatal("ownership without update")
	}
	if e := s.Apply(context.Background(), b, up, owned); e != nil {
		t.Fatal(e)
	}
	b, _ = s.Read()
	metadata := map[string]domain.Profile{}
	for k, p := range owned {
		p.Region = "changed"
		metadata[k] = p
	}
	if e := s.Apply(context.Background(), b, nil, metadata); e == nil {
		t.Fatal("metadata changed without config update")
	}
	if e := s.Apply(context.Background(), b, nil, map[string]domain.Profile{}); e == nil {
		t.Fatal("ownership deletion")
	}
	changed := map[string]domain.Profile{}
	for k, p := range owned {
		p.Assignment.RoleName = "Other"
		changed[k] = p
	}
	if e := s.Apply(context.Background(), b, up, changed); e == nil {
		t.Fatal("identity rebind")
	}
	os.WriteFile(s.Path, []byte(strings.ReplaceAll(string(b.Data), "sso_role_name = ReadOnly", "sso_role_name = changed")), 0600)
	b, _ = s.Read()
	if e := s.Apply(context.Background(), b, up, owned); e == nil {
		t.Fatal("external identity overwritten")
	}
}

func TestC13UnknownSettingsAndSessionMismatch(t *testing.T) {
	for _, kind := range []string{"profile", "session", "metadata", "render"} {
		t.Run(kind, func(t *testing.T) {
			s, b, up, owned := fixture(t)
			switch kind {
			case "profile":
				up["profile dev"]["credential_process"] = "injected"
			case "session":
				up["sso-session local"]["unknown"] = "injected"
			case "metadata":
				up["sso-session local"]["sso_region"] = "other"
			case "render":
				up["profile dev"]["region"] = "injected\nvalue"
				p := owned["dev"]
				p.Region = "injected\nvalue"
				owned["dev"] = p
			}
			if e := s.Apply(context.Background(), b, up, owned); e == nil {
				t.Fatal("unsafe update accepted")
			}
			if _, e := os.Stat(s.Path); !os.IsNotExist(e) {
				t.Fatal("invalid operation wrote config", e)
			}
		})
	}
}

func TestC13NormalizedExistingSessionURL(t *testing.T) {
	s, _, up, owned := fixture(t)
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	old := "[sso-session local]\nsso_start_url = https://example.invalid/start/\nsso_region = us-east-1\n"
	if e := os.WriteFile(s.Path, []byte(old), 0600); e != nil {
		t.Fatal(e)
	}
	delete(up, "sso-session local")
	b, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Apply(context.Background(), b, up, owned); e != nil {
		t.Fatal("normalized matching session rejected", e)
	}
	got, _ := os.ReadFile(s.Path)
	if !strings.HasPrefix(string(got), old) {
		t.Fatal("matching session rewritten")
	}
}

func TestC02PreviewAndEmptyManifest(t *testing.T) {
	s, b, _, _ := fixture(t)
	if _, e := Preview(b, map[string]map[string]string{"bad\nsection": {"k": "v"}}); e == nil {
		t.Fatal("invalid preview accepted")
	}
	b.Data = []byte("broken")
	if _, e := Preview(b, nil); e == nil {
		t.Fatal("invalid config preview accepted")
	}
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	os.WriteFile(s.Path+".aws-sso-sync.json", []byte{}, 0600)
	if _, e := s.Read(); e == nil {
		t.Fatal("empty manifest accepted")
	}
}

func TestC03CancelBeforeRename(t *testing.T) {
	s, b, up, owned := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Fault = func(stage string) error {
		if stage == "temp_write" {
			cancel()
		}
		return nil
	}
	if e := s.Apply(ctx, b, up, owned); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := os.Stat(s.Path); !os.IsNotExist(e) {
		t.Fatal("canceled apply wrote config", e)
	}
}

func TestC12NoopDiscardOldIntent(t *testing.T) {
	s, b, _, _ := fixture(t)
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	st := state{Version: 1, Path: s.Path, Hash: "not-committed", Before: b.Hash, Owned: map[string]domain.Profile{}}
	bytes, _ := json.Marshal(st)
	os.WriteFile(s.Path+".aws-sso-sync.intent", bytes, 0600)
	b, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Apply(context.Background(), b, nil, b.Owned); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(s.Path + ".aws-sso-sync.intent"); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}

func TestC03FilesystemPermissionFailures(t *testing.T) {
	s, b, up, owned := fixture(t)
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	os.Chmod(filepath.Dir(s.Path), 0500)
	defer os.Chmod(filepath.Dir(s.Path), 0700)
	if e := s.Apply(context.Background(), b, up, owned); e == nil {
		t.Fatal("read-only parent accepted")
	}
	os.Chmod(filepath.Dir(s.Path), 0700)
	os.WriteFile(s.Path, []byte("[default]\nregion=keep\n"), 0000)
	defer os.Chmod(s.Path, 0600)
	if _, e := s.Read(); e == nil {
		t.Fatal("unreadable config accepted")
	}
}
