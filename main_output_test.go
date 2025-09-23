package main

import (
	"path/filepath"
	"testing"

	"gopkg.in/ini.v1"
)

// Test that writeProfileToConfig writes the configured output value into the
// profile section when profileOutput is set.
func TestWriteProfileUsesConfiguredOutput(t *testing.T) {
	// Create a temp directory for the config file
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")

	// Point the global ssoConfigFile to our temp path
	oldConfig := ssoConfigFile
	defer func() { ssoConfigFile = oldConfig }()
	ssoConfigFile = cfgPath

	// Set a known sso-session name and region for completeness
	oldSession := ssoSessionConfigName
	defer func() { ssoSessionConfigName = oldSession }()
	ssoSessionConfigName = "default"

	// Set a custom profileOutput and call writeProfileToConfig
	oldOutput := profileOutput
	defer func() { profileOutput = oldOutput }()
	profileOutput = "text"

	role := CombinedRole{AccountId: "123456789012", RoleName: "AWSReadOnlyAccess", AccountName: "Example"}
	profileName := "Example_123456789012"

	if err := writeProfileToConfig(profileName, role); err != nil {
		t.Fatalf("writeProfileToConfig failed: %v", err)
	}

	// Load the resulting config and verify the output key
	cfg, err := ini.Load(cfgPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	section := cfg.Section("profile " + profileName)
	if section == nil {
		t.Fatalf("profile section not found")
	}
	got := section.Key("output").String()
	if got != "text" {
		t.Fatalf("expected output 'text', got '%s'", got)
	}
}
