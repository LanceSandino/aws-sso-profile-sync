package configstore

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
