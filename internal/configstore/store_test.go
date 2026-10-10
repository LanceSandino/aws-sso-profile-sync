package configstore

import (
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"os"
	"path/filepath"
	"testing"
)

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
