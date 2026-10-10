package auth

import (
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func store(t *testing.T) Store {
	return Store{Root: filepath.Join(t.TempDir(), "tokens"), Session: domain.Session{Name: "test", StartURL: "https://synthetic.example/start", Region: "us-east-1"}, Endpoint: "http://localhost:123"}
}
func valid(s Store) Token {
	return Token{AccessToken: "access", RefreshToken: "refresh", ClientID: "client", ClientSecret: "secret", ExpiresAt: time.Now().Add(time.Hour), RegistrationExpiresAt: time.Now().Add(time.Hour), Session: s.Session, Endpoint: s.Endpoint}
}
func TestA09RejectInsecureAndMalformedCache(t *testing.T) {
	s := store(t)
	tok := valid(s)
	if e := s.Save(tok); e != nil {
		t.Fatal(e)
	}
	for _, contents := range []string{`{"unknown":"value"}`, `{} {}`, `{"accessToken":"access"}`} {
		if e := os.WriteFile(s.Path(), []byte(contents), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := s.Read(); e == nil {
			t.Fatal("invalid accepted")
		}
	}
	os.Remove(s.Path())
	if e := s.Save(tok); e != nil {
		t.Fatal(e)
	}
	os.Chmod(s.Path(), 0644)
	if _, e := s.Read(); e == nil {
		t.Fatal("insecure file")
	}
	os.Chmod(s.Path(), 0600)
	os.Chmod(s.Root, 0755)
	if _, e := s.Read(); e == nil {
		t.Fatal("insecure dir")
	}
	if e := s.Save(tok); e == nil {
		t.Fatal("insecure dir save")
	}
	os.Chmod(s.Root, 0700)
	os.Remove(s.Path())
	os.Mkdir(s.Path(), 0700)
	if e := s.Save(tok); e == nil {
		t.Fatal("directory target")
	}
	relative := s
	relative.Root = "relative"
	if _, e := relative.Read(); e == nil {
		t.Fatal("relative read")
	}
	if e := relative.Save(tok); e == nil {
		t.Fatal("relative save")
	}
	root := filepath.Join(t.TempDir(), "root")
	if e := os.Symlink(s.Root, root); e != nil {
		t.Fatal(e)
	}
	s.Root = root
	if _, e := s.Read(); e == nil {
		t.Fatal("symlink root")
	}
}
func TestA09FilesystemFailuresKeepOriginal(t *testing.T) {
	s := store(t)
	if e := s.Save(valid(s)); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(s.Path())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(s.Root, 0500); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(s.Root, 0700)
	if e = s.Save(valid(s)); domain.ErrorCode(e) != "failed" {
		t.Fatal(e)
	}
	after, e := os.ReadFile(s.Path())
	if e != nil || string(after) != string(original) {
		t.Fatal("original changed")
	}
	s2 := store(t)
	if e = os.WriteFile(s2.Root, []byte("regular"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = s2.Save(valid(s2)); e == nil {
		t.Fatal("regular root")
	}
	if _, e = s2.Read(); e == nil {
		t.Fatal("regular root read")
	}
	s3 := store(t)
	if e = os.MkdirAll(s3.Root, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(s3.Path(), make([]byte, (1<<20)+1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s3.Read(); e == nil {
		t.Fatal("unbounded cache read")
	}
}
