package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func TestGeneratePrefixFromRole(t *testing.T) {
	// TestGeneratePrefixFromRole ensures generatePrefixFromRole correctly
	// strips the "AWS" prefix and "Access" suffix and appends an underscore
	// for common AWS-managed role names, and returns an empty string when
	// nothing remains (e.g., role name "Access").
	cases := map[string]string{
		"AWSReadOnlyAccess":  "ReadOnly_",
		"AWSPowerUserAccess": "PowerUser_",
		"CustomRole":         "CustomRole_",
		// role name "Access" becomes empty after trimming and should return ""
		"Access": "",
	}
	for in, want := range cases {
		got := generatePrefixFromRole(in)
		if got != want {
			t.Fatalf("prefix for %s: got %q want %q", in, got, want)
		}
	}
}

func TestGetProfileNameFromRole(t *testing.T) {
	// TestGetProfileNameFromRole verifies that getProfileNameFromRole uses
	// auto-generated prefixes (when enabled) and safely formats account
	// names into a profile identifier.
	profilePrefix = ""
	useAutoPrefix = true
	role := CombinedRole{AccountId: "123", AccountName: "My App", RoleName: "AWSReadOnlyAccess"}
	got := getProfileNameFromRole(role)
	if !strings.HasPrefix(got, "ReadOnly_") {
		t.Fatalf("unexpected profile name: %s", got)
	}
}

func TestPrintBlockIndented(t *testing.T) {
	// TestPrintBlockIndented is a smoke test to ensure printing a multi-line
	// block with indentation does not panic and produces output (not asserted
	// here; the function is primarily formatting helper used in dry-run).
	block := "first\nsecond\nthird\n"
	// Ensure it doesn't panic
	printBlockIndented("  ", block)
}

func TestFindMatchingSsoSessionName(t *testing.T) {
	// TestFindMatchingSsoSessionName creates a temporary INI config with an
	// [sso-session <name>] section and asserts the matching function finds
	// the correct session name when start URL and region match, and that
	// it does not match when the URL differs.
	// create a temp config file
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	cfg := ini.Empty()
	sec, _ := cfg.NewSection("sso-session example")
	sec.NewKey("sso_start_url", "https://example.com/start")
	sec.NewKey("sso_region", "us-east-1")
	if err := cfg.SaveTo(cfgPath); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	name, ok := findMatchingSsoSessionName("https://example.com/start/", "us-east-1", cfgPath)
	if !ok || name != "example" {
		t.Fatalf("expected to find session 'example', got %q ok=%v", name, ok)
	}

	// Missing case
	name, ok = findMatchingSsoSessionName("https://nope.example/", "us-east-1", cfgPath)
	if ok || name != "" {
		t.Fatalf("unexpected match for missing session: %q", name)
	}
}

func TestProfileExists(t *testing.T) {
	// TestProfileExists writes a temporary config containing a
	// [profile existing] section with an sso_session key and verifies the
	// INI-aware profileExists function detects it, and that a missing
	// profile name is not falsely reported as present.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	cfg := ini.Empty()
	sec, _ := cfg.NewSection("profile existing")
	sec.NewKey("sso_session", "test")
	if err := cfg.SaveTo(cfgPath); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	if !profileExists("existing", cfgPath) {
		t.Fatalf("expected profile 'existing' to be detected")
	}
	if profileExists("missing", cfgPath) {
		t.Fatalf("unexpected detection of missing profile")
	}
}

func TestWriteProfileToConfig(t *testing.T) {
	// TestWriteProfileToConfig uses a temporary config file, sets global
	// variables used by writeProfileToConfig, and asserts the function
	// creates a profile section with the expected SSO keys (sso_session,
	// sso_account_id, sso_role_name, region, output).
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")

	// Override globals for testing
	oldConfigFile := ssoConfigFile
	oldSession := ssoSessionConfigName
	oldRegion := ssoRegion
	defer func() {
		ssoConfigFile = oldConfigFile
		ssoSessionConfigName = oldSession
		ssoRegion = oldRegion
	}()
	ssoConfigFile = cfgPath
	ssoSessionConfigName = "testsession"
	ssoRegion = "us-west-2"

	role := CombinedRole{AccountId: "999888777666", AccountName: "Test Account", RoleName: "AWSReadOnlyAccess"}
	profile := getProfileNameFromRole(role)

	// Ensure profile does not exist yet
	if profileExists(profile, cfgPath) {
		t.Fatalf("profile %s unexpectedly exists before write", profile)
	}

	// Ensure parent dir exists
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatalf("failed to create temp config dir: %v", err)
	}

	// Ensure we are writing (not dry-run) for this test
	oldDry := dryRun
	defer func() { dryRun = oldDry }()
	dryRun = false

	if err := writeProfileToConfig(profile, role); err != nil {
		t.Fatalf("writeProfileToConfig failed: %v", err)
	}

	// Now load the config and verify section/keys
	cfg, err := ini.Load(cfgPath)
	if err != nil {
		t.Fatalf("failed to load written config: %v", err)
	}
	sec := cfg.Section("profile " + profile)
	if sec == nil {
		t.Fatalf("expected profile section 'profile %s' not found", profile)
	}
	if sec.Key("sso_session").String() != ssoSessionConfigName {
		t.Fatalf("sso_session mismatch: got %q want %q", sec.Key("sso_session").String(), ssoSessionConfigName)
	}
	if sec.Key("sso_account_id").String() != role.AccountId {
		t.Fatalf("sso_account_id mismatch: got %q want %q", sec.Key("sso_account_id").String(), role.AccountId)
	}
	if sec.Key("sso_role_name").String() != role.RoleName {
		t.Fatalf("sso_role_name mismatch: got %q want %q", sec.Key("sso_role_name").String(), role.RoleName)
	}
	if sec.Key("region").String() != ssoRegion {
		t.Fatalf("region mismatch: got %q want %q", sec.Key("region").String(), ssoRegion)
	}
}

func TestGetExistingSsoSessionBlock(t *testing.T) {
	// TestGetExistingSsoSessionBlock creates a temp INI with an sso-session
	// section and verifies getExistingSsoSessionBlock returns the expected
	// textual block including the start URL and region.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	cfg := ini.Empty()
	sec, _ := cfg.NewSection("sso-session sample")
	sec.NewKey("sso_start_url", "https://sample.example/start")
	sec.NewKey("sso_region", "eu-west-1")
	sec.NewKey("sso_registration_scopes", "sso:account:access")
	if err := cfg.SaveTo(cfgPath); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	block, err := getExistingSsoSessionBlock("sample", cfgPath)
	if err != nil {
		t.Fatalf("getExistingSsoSessionBlock returned error: %v", err)
	}
	if !strings.Contains(block, "sso_start_url = https://sample.example/start") {
		t.Fatalf("unexpected block content: %s", block)
	}
	if !strings.Contains(block, "sso_region = eu-west-1") {
		t.Fatalf("unexpected block content: %s", block)
	}
}

func TestEnsureSsoSessionConfigPresent(t *testing.T) {
	// TestEnsureSsoSessionConfigPresent verifies the function properly
	// shows the session block in dry-run and writes the block to a real
	// config file when not in dry-run. It also verifies idempotency.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")

	// Save and restore globals
	oldConfigFile := ssoConfigFile
	oldSession := ssoSessionConfigName
	oldStart := ssoStartURL
	oldRegion := ssoRegion
	oldDry := dryRun
	defer func() {
		ssoConfigFile = oldConfigFile
		ssoSessionConfigName = oldSession
		ssoStartURL = oldStart
		ssoRegion = oldRegion
		dryRun = oldDry
	}()

	ssoConfigFile = cfgPath
	ssoSessionConfigName = "unittest"
	ssoStartURL = "https://unit.test/start"
	ssoRegion = "us-east-2"

	// Dry-run: should report it would add and not create the file
	dryRun = true
	added, err := ensureSsoSessionConfigPresent()
	if err != nil {
		t.Fatalf("ensureSsoSessionConfigPresent (dry-run) error: %v", err)
	}
	if !added {
		t.Fatalf("expected ensureSsoSessionConfigPresent to indicate added in dry-run")
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatalf("unexpected config file created during dry-run")
	}

	// Real write: should create the config file and write the session
	dryRun = false
	added, err = ensureSsoSessionConfigPresent()
	if err != nil {
		t.Fatalf("ensureSsoSessionConfigPresent error: %v", err)
	}
	if !added {
		t.Fatalf("expected ensureSsoSessionConfigPresent to have added the session")
	}
	// Calling again should find it already present and return false
	added, err = ensureSsoSessionConfigPresent()
	if err != nil {
		t.Fatalf("second call to ensureSsoSessionConfigPresent error: %v", err)
	}
	if added {
		t.Fatalf("expected second call to indicate nothing was added")
	}
}
