package compatibility

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDEF01MalformedConfigPreserved(t *testing.T) {
	saveGlobals(t)
	p := filepath.Join(t.TempDir(), "config")
	original := []byte("[default\nregion = us-west-1\n")
	if err := os.WriteFile(p, original, 0600); err != nil {
		t.Fatal(err)
	}
	ssoConfigFile = p
	dryRun = false
	ssoSessionConfigName = "synthetic"
	profileRegion = "us-east-2"
	err := writeProfileToConfig("synthetic", CombinedRole{AccountId: "111111111111", RoleName: "ReadOnly"})
	got, _ := os.ReadFile(p)
	if err == nil || string(got) != string(original) {
		t.Fatalf("DEF-01: malformed config silently replaced; error=%v preserved=%v", err, string(got) == string(original))
	}
}
func TestDEF03DryRunNeverLogin(t *testing.T) {
	saveGlobals(t)
	ssoConfigFile = filepath.Join(t.TempDir(), "config")
	dryRun = true
	ssoStartURL = "https://sample.invalid/start"
	ssoSessionConfigName = "synthetic"
	oldGet, oldLogin := getAccessTokenFunc, runAwsSsoLogin
	defer func() { getAccessTokenFunc = oldGet; runAwsSsoLogin = oldLogin }()
	getAccessTokenFunc = func() (string, string, error) { return "", "", errors.New("no synthetic token") }
	called := false
	runAwsSsoLogin = func(string) error { called = true; return errors.New("synthetic login blocked") }
	_ = login()
	if called {
		t.Fatal("DEF-03: dry-run invoked interactive login")
	}
}
func TestDEF06PrefixRoleCollision(t *testing.T) {
	saveGlobals(t)
	profilePrefix = "custom_"
	a := CombinedRole{AccountId: "111111111111", AccountName: "Sample", RoleName: "ReadOnly"}
	b := a
	b.RoleName = "PowerUser"
	if getProfileNameFromRole(a) == getProfileNameFromRole(b) {
		t.Fatal("DEF-06: different roles silently share profile name")
	}
}

func saveGlobals(t *testing.T) {
	a, b, c, d, e, f, g, h, i, j := profilePrefix, ssoConfigFile, ssoSessionConfigName, ssoRegion, profileRegion, profileOutput, ssoStartURL, dryRun, useAutoPrefix, 0
	_ = j
	t.Cleanup(func() {
		profilePrefix = a
		ssoConfigFile = b
		ssoSessionConfigName = c
		ssoRegion = d
		profileRegion = e
		profileOutput = f
		ssoStartURL = g
		dryRun = h
		useAutoPrefix = i
	})
}
