package configstore

import (
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
