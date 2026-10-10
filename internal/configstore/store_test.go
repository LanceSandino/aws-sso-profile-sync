package configstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
)

func tempRoot(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func fixture(t *testing.T) (Store, Snapshot, map[string]map[string]string, map[string]domain.Profile) {
	t.Helper()
	path := filepath.Join(tempRoot(t), "aws", "config")
	t.Setenv("HOME", filepath.Dir(filepath.Dir(path)))
	s := Store{Path: path}
	b, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	p := domain.Profile{Name: "dev", Session: domain.Session{Name: "local", StartURL: "https://example.invalid/start", Region: "us-east-1"}, Assignment: domain.Assignment{AccountID: "111111111111", RoleName: "ReadOnly"}, Region: "us-west-2", Output: "json"}
	return s, b, map[string]map[string]string{"profile dev": {"sso_session": "local", "sso_account_id": "111111111111", "sso_role_name": "ReadOnly", "region": "us-west-2", "output": "json"}, "sso-session local": {"sso_start_url": p.Session.StartURL, "sso_region": "us-east-1", "sso_registration_scopes": "sso:account:access"}}, map[string]domain.Profile{"dev": p}
}

func TestC02StrictParser(t *testing.T) {
	for _, v := range []string{"oops", "[broken", "[a]\nx=1\n[a]\ny=2\n", "[a]\nx=1\nx=2\n", "x=1\n", "[a]\n=bad\n", "[a]\nkey\n"} {
		if _, e := Parse([]byte(v)); e == nil {
			t.Fatalf("accepted %q", v)
		}
	}
	sections, e := Parse([]byte("# comment\r\n[default]\r\nregion = us-east-1\r\n"))
	if e != nil || sections["default"]["region"] != "us-east-1" {
		t.Fatal(sections, e)
	}
}

func TestC01C05C06C10C11Preservation(t *testing.T) {
	s, _, desired, owned := fixture(t)
	if e := os.MkdirAll(filepath.Dir(s.Path), 0700); e != nil {
		t.Fatal(e)
	}
	old := "# leading\n[default]\nregion = keep\n\n[profile manual]\ncredential_process = arbitrary command\n# tail\n"
	if e := os.WriteFile(s.Path, []byte(old), 0640); e != nil {
		t.Fatal(e)
	}
	before, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Apply(context.Background(), before, desired, owned); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(s.Path)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(string(got), old) {
		t.Fatal(string(got))
	}
	info, _ := os.Stat(s.Path)
	if info.Mode().Perm() != 0640 {
		t.Fatal(info.Mode())
	}
	parent, _ := os.Stat(filepath.Dir(s.Path))
	if parent.Mode().Perm() != 0700 {
		t.Fatal(parent.Mode())
	}
	before, e = s.Read()
	if e != nil || len(before.Owned) != 1 {
		t.Fatal(before, e)
	}
	s.Fault = func(stage string) error { t.Fatalf("no-op entered write stage %s", stage); return nil }
	if e = s.Apply(context.Background(), before, desired, owned); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(s.Path)
	if string(after) != string(got) {
		t.Fatal("no-op churn")
	}
}

func TestC03C04FaultsPreserveOriginal(t *testing.T) {
	for _, stage := range []string{"temp_create", "temp_write", "temp_sync", "rename"} {
		t.Run(stage, func(t *testing.T) {
			s, _, desired, owned := fixture(t)
			os.MkdirAll(filepath.Dir(s.Path), 0700)
			old := []byte("[default]\nregion=keep\n")
			os.WriteFile(s.Path, old, 0600)
			b, _ := s.Read()
			s.Fault = func(v string) error {
				if v == stage {
					return errors.New("injected")
				}
				return nil
			}
			if e := s.Apply(context.Background(), b, desired, owned); e == nil {
				t.Fatal("false success")
			}
			got, _ := os.ReadFile(s.Path)
			if string(got) != string(old) {
				t.Fatal("lost original")
			}
			entries, _ := filepath.Glob(filepath.Join(filepath.Dir(s.Path), ".aws-sso-sync-*"))
			if len(entries) != 0 {
				t.Fatal(entries)
			}
		})
	}
}

func TestC07Symlinks(t *testing.T) {
	s, _, _, _ := fixture(t)
	target := tempRoot(t)
	os.Symlink(target, filepath.Dir(s.Path))
	if _, e := s.Read(); e == nil {
		t.Fatal("accepted parent link")
	}
	s.Path = filepath.Join(tempRoot(t), "config")
	os.Symlink(filepath.Join(target, "config"), s.Path)
	if _, e := s.Read(); e == nil {
		t.Fatal("accepted file link")
	}
}

func TestC08C09StaleAndLock(t *testing.T) {
	s, b, desired, owned := fixture(t)
	os.MkdirAll(filepath.Dir(s.Path), 0700)
	os.WriteFile(s.Path, []byte("[default]\nregion=external\n"), 0600)
	if e := s.Apply(context.Background(), b, desired, owned); domain.ErrorCode(e) != "conflict" {
		t.Fatal(e)
	}
	b, _ = s.Read()
	unlock, e := lock(context.Background(), s.Path+".aws-sso-sync.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if e := s.Apply(ctx, b, desired, owned); e == nil {
		t.Fatal("lock ignored")
	}
}

func TestC12CrashRecoveryReadOnly(t *testing.T) {
	s, b, desired, owned := fixture(t)
	s.Fault = func(v string) error {
		if v == "manifest" {
			return errors.New("crash")
		}
		return nil
	}
	if e := s.Apply(context.Background(), b, desired, owned); e == nil {
		t.Fatal("false success")
	}
	entriesBefore, _ := os.ReadDir(filepath.Dir(s.Path))
	snap, e := s.Read()
	if e != nil || len(snap.Owned) != 1 {
		t.Fatal(snap, e)
	}
	entriesAfter, _ := os.ReadDir(filepath.Dir(s.Path))
	if len(entriesBefore) != len(entriesAfter) {
		t.Fatal("Read wrote")
	}
	s.Fault = nil
	if e = s.Apply(context.Background(), snap, desired, owned); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(s.Path + ".aws-sso-sync.intent"); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}

func TestC13UnownedAndSessionConflicts(t *testing.T) {
	for _, old := range []string{"[profile dev]\nsso_session=local\nsso_account_id=111111111111\nsso_role_name=ReadOnly\n", "[sso-session local]\nsso_start_url=https://other.invalid\nsso_region=us-east-1\n"} {
		s, _, desired, owned := fixture(t)
		os.MkdirAll(filepath.Dir(s.Path), 0700)
		os.WriteFile(s.Path, []byte(old), 0600)
		b, _ := s.Read()
		if e := s.Apply(context.Background(), b, desired, owned); domain.ErrorCode(e) != "conflict" {
			t.Fatal(e)
		}
		got, _ := os.ReadFile(s.Path)
		if string(got) != old {
			t.Fatal("conflict wrote")
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"[default]\nregion=us-east-1\n", "[profile x]\n# hi\n", "[broken"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) })
}

func TestC02PreviewRejectsValueSemanticInjection(t *testing.T) {
	before := Snapshot{Sections: map[string]map[string]string{}}
	for _, v := range []string{"ReadOnly # injected", "json ; injected"} {
		if _, e := Preview(before, map[string]map[string]string{"profile synthetic": {"sso_role_name": v}}); e == nil {
			t.Fatal("preview accepted a value that INI interprets differently")
		}
	}
}
