package configstore

import (
	"os"
	"runtime"
	"strings"
	"testing"
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
