package settings

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

func settingsFile(t *testing.T, data string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	path := filepath.Join(root, "settings.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestSettingsContextSelectionAndRelativePaths(t *testing.T) {
	for _, selection := range []string{"", "work"} {
		path := settingsFile(t, `{"schema_version":1,"contexts":{"work":{"sso_start_url":"https://example.invalid/start","sso_session_name":"work","sso_region":"us-east-1","region":"us-west-2","roles":["ReadOnly","PowerUser"],"prefix":"team_","auto_prefix":false,"output":"json","config_file":"aws/config","state_dir":"state"}}}`)
		original, _ := os.ReadFile(path)
		if err := os.Chmod(path, 0400); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Stat(path)
		context, err := Load(path, selection)
		if err != nil {
			t.Fatal(err)
		}
		if *context.StartURL != "https://example.invalid/start" || *context.Session != "work" || *context.SSORegion != "us-east-1" || *context.Region != "us-west-2" || *context.Prefix != "team_" || *context.Output != "json" || *context.AutoPrefix || !reflect.DeepEqual(*context.Roles, []string{"ReadOnly", "PowerUser"}) {
			t.Fatal(context)
		}
		if *context.ConfigFile != filepath.Join(filepath.Dir(path), "aws/config") || *context.StateDir != filepath.Join(filepath.Dir(path), "state") {
			t.Fatal(context)
		}
		after, _ := os.Stat(path)
		got, _ := os.ReadFile(path)
		if !before.ModTime().Equal(after.ModTime()) || !bytes.Equal(got, original) || after.Mode().Perm() != 0400 {
			t.Fatal("settings read modified file")
		}
	}
	path := settingsFile(t, `{"schema_version":1,"default_context":"two","contexts":{"one":{"region":"us-east-1"},"two":{"region":"eu-west-1"}}}`)
	if c, err := Load(path, ""); err != nil || *c.Region != "eu-west-1" {
		t.Fatal(c, err)
	}
	if c, err := Load(path, "one"); err != nil || *c.Region != "us-east-1" {
		t.Fatal(c, err)
	}
}
func TestSettingsInvalidContentIsRedacted(t *testing.T) {
	for _, data := range []string{
		`{"schema_version":1,"contexts":{"a":{},"b":{}}}`,
		`{"schema_version":1,"contexts":{}}`,
		`{"schema_version":2,"contexts":{"a":{}}}`,
		`{"schema_version":1,"default_context":"missing","contexts":{"a":{}}}`,
		`{"schema_version":1,"default_context":"","contexts":{"a":{}}}`,
		`{"schema_version":1,"contexts":{"":{"region":"us-east-1"}}}`,
		`{"schema_version":1,"schema_version":1,"contexts":{"a":{}}}`,
		`{"SCHEMA_VERSION":1,"contexts":{"a":{}}}`,
		`{"schema_version":1,"contexts":{"a":{"REGION":"us-east-1"}}}`,
		`{"schema_version":1,"contexts":{"a":{"region":"us-east-1","REGION":"us-west-2"}}}`,
		`{"schema_version":1,"contexts":{"a":{},"a":{}}}`,
		`{"schema_version":1,"contexts":{"a":{"region":"us-east-1","region":"us-west-2"}}}`,
		`{"schema_version":1,"secret":"DO_NOT_ECHO","contexts":{"a":{}}}`,
		`{"schema_version":1,"contexts":{"a":{"access_token":"DO_NOT_ECHO"}}}`,
		`{"schema_version":1,"contexts":{"a":{"test_endpoint":"http://127.0.0.1"}}}`,
		`{"schema_version":1,"contexts":{"a":{"open":true}}}`,
		`{"schema_version":1,"contexts":{"a":{"sso_start_url":"https://user:DO_NOT_ECHO@example.invalid/start"}}}`,
		`{"schema_version":1,"contexts":{"a":{"sso_start_url":"http://example.invalid/start"}}}`,
		`{"schema_version":1,"contexts":{"a":{"region":""}}}`,
		`{"schema_version":1,"contexts":{"a":{"sso_region":"bad"}}}`,
		`{"schema_version":1,"contexts":{"a":{"sso_session_name":"bad\nname"}}}`,
		`{"schema_version":1,"contexts":{"a":{"roles":[""]}}}`,
		`{"schema_version":1,"contexts":{"a":{"roles":["Bad\u001b[31m"]}}}`,
		`{"schema_version":1,"contexts":{"a":{"roles":null}}}`,
		`{"schema_version":1,"contexts":{"a":{"config_file":""}}}`,
		`{"schema_version":1,"contexts":{"a":{"output":"xml"}}}`,
		`{"schema_version":1,"contexts":{"a":{"prefix":"bad\nname"}}}`,
		`{"schema_version":1,"contexts":{"a":{"auto_prefix":"DO_NOT_ECHO"}}}`,
		`{"schema_version":1,"contexts":{"a":{}}} {"secret":"DO_NOT_ECHO"}`,
		`{"schema_version":1,"contexts":{"a":{}}`,
		`"DO_NOT_ECHO"`,
	} {
		t.Run(data, func(t *testing.T) {
			path := settingsFile(t, data)
			if _, err := Load(path, ""); domain.ErrorCode(err) != "config_invalid" || strings.Contains(err.Error(), "DO_NOT_ECHO") || strings.Contains(err.Error(), data) {
				t.Fatalf("unredacted/accepted settings: %v", err)
			}
		})
	}
	path := settingsFile(t, `{"schema_version":1,"contexts":{"work":{}}}`)
	if _, err := Load(path, "missing"); domain.ErrorCode(err) != "config_invalid" {
		t.Fatal(err)
	}
}
func TestSettingsFileSafety(t *testing.T) {
	path := settingsFile(t, `{"schema_version":1,"contexts":{"a":{}}}`)
	if _, err := Load(path+".missing", ""); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := Load(filepath.Dir(path), ""); err == nil {
		t.Fatal("directory accepted")
	}
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, ""); err == nil {
		t.Fatal("group-writable file accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(filepath.Dir(path), "link")
	os.Symlink(path, link)
	if _, err := Load(link, ""); err == nil {
		t.Fatal("file symlink accepted")
	}
	parent := filepath.Join(filepath.Dir(path), "parent")
	os.Symlink(filepath.Dir(path), parent)
	if _, err := Load(filepath.Join(parent, "settings.json"), ""); err == nil {
		t.Fatal("ancestor symlink accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", 1<<20)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, ""); err == nil {
		t.Fatal("oversized file accepted")
	}
}
