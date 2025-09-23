package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestDryRunNoToken ensures that when there is no SSO token and dry-run is
// enabled, the program prints the "Would add SSO session configuration" block
// exactly once (the block is printed right before invoking the login flow).
func TestDryRunNoToken(t *testing.T) {
	// Arrange: stub token fetch to simulate no token present
	origGet := getAccessTokenFunc
	origRun := runAwsSsoLogin
	defer func() {
		getAccessTokenFunc = origGet
		runAwsSsoLogin = origRun
	}()

	// Simulate token arriving only after the interactive login finishes.
	tokenArrived := false
	getAccessTokenFunc = func() (string, string, error) {
		if tokenArrived {
			return "fake-token", "/tmp/fake-token.json", nil
		}
		return "", "", io.EOF
	}
	// stub login command to flip the token arrival flag
	runAwsSsoLogin = func(session string) error { tokenArrived = true; return nil }

	// Accept the fake token as valid to avoid real AWS calls
	origIsValid := isSsoTokenValidFunc
	defer func() { isSsoTokenValidFunc = origIsValid }()
	isSsoTokenValidFunc = func(accessToken string) bool { return accessToken == "fake-token" }

	// Stub out the high-level configure step to avoid AWS calls during the
	// dry-run test; it will simply return nil.
	origConfigure := configureSsoProfilesFunc
	defer func() { configureSsoProfilesFunc = origConfigure }()
	configureSsoProfilesFunc = func(accessToken string) error { return nil }

	// Set up flags/environment for the test
	oldDry := dryRun
	defer func() { dryRun = oldDry }()
	dryRun = true
	// Use neutral, synthetic start URL and session name for tests
	ssoStartURL = "https://unit.test/start"
	ssoRegion = "us-east-1"
	ssoSessionConfigName = "unittest"
	// Use a temp config file path that does not exist
	tmpFile := os.TempDir() + "/nonexistent_aws_config_for_test"
	ssoConfigFile = tmpFile

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Act
	if err := login(); err != nil {
		t.Fatalf("login() returned error: %v", err)
	}

	// Restore stdout and read output
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = old

	out := buf.String()
	// Assert: the 'Would add SSO session configuration' line should appear once
	occurrences := strings.Count(out, "Would add SSO session configuration")
	if occurrences != 1 {
		t.Fatalf("expected 1 occurrence of session add message, got %d. Output:\n%s", occurrences, out)
	}
}
