package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIProfileSettingsOverrideRequiresExplicitFlag(t *testing.T) {
	root := env(t)
	o, err := Parse([]string{"plan", "--override-profile-settings"}, &bytes.Buffer{})
	if err != nil || !o.OverrideProfileSettings {
		t.Fatal("explicit override flag missing", o, err)
	}
	if defaults, err := Parse([]string{"plan"}, &bytes.Buffer{}); err != nil || defaults.OverrideProfileSettings {
		t.Fatal("override enabled by default", defaults, err)
	}
	// The settings schema must not permit an action authorizing replacement.
	path := writeSettings(t, root, `{"schema_version":1,"contexts":{"work":{"override_profile_settings":true}}}`)
	if _, err := Parse([]string{"plan", "--settings-file", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("settings authorized override", o)
	}
}
func TestCLIOfflineDuplicateProfilesAreWarnings(t *testing.T) {
	root := env(t)
	path := filepath.Join(root, ".aws", "config")
	os.MkdirAll(filepath.Dir(path), 0700)
	original := []byte("[sso-session work]\nsso_start_url=https://example.invalid/start\nsso_region=us-east-1\n[profile alias-one]\nsso_session=work\nsso_account_id=111111111111\nsso_role_name=ReadOnly\nregion=us-east-1\n[profile alias-two]\nsso_session=work\nsso_account_id=111111111111\nsso_role_name=ReadOnly\nregion=eu-west-1\n")
	os.WriteFile(path, original, 0600)
	before, _ := os.Stat(path)
	for _, command := range []string{"doctor", "list"} {
		e, _, code := run(t, command, "--format", "json")
		if code != 0 {
			t.Fatal(command, e)
		}
		data, _ := json.Marshal(e)
		var document map[string]json.RawMessage
		json.Unmarshal(data, &document)
		warnings := string(document["warnings"])
		if !strings.Contains(warnings, `"code":"duplicate_profiles"`) || !strings.Contains(warnings, "alias-one") || !strings.Contains(warnings, "alias-two") || !strings.Contains(warnings, "identity_key") {
			t.Fatal("duplicate warning missing", string(data))
		}
		var out, stderr bytes.Buffer
		if Run(t.Context(), []string{command}, &out, &stderr) != 0 || !strings.Contains(out.String(), "duplicate_profiles") || !strings.Contains(out.String(), "alias-one") || !strings.Contains(out.String(), "alias-two") {
			t.Fatal("table warning missing", out.String(), stderr.String())
		}
	}
	after, _ := os.Stat(path)
	got, _ := os.ReadFile(path)
	if !bytes.Equal(original, got) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("duplicate diagnostics changed aliases")
	}
	if _, err := os.Stat(path + ".aws-sso-sync.json"); !os.IsNotExist(err) {
		t.Fatal("diagnostics wrote ownership", err)
	}
}
