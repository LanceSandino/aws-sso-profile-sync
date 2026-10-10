package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeSettings(t *testing.T, root, data string) string {
	t.Helper()
	path := filepath.Join(root, "settings.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const configured = `{"schema_version":1,"contexts":{"work":{"sso_start_url":"https://example.invalid/start","sso_session_name":"work","sso_region":"us-west-2","region":"eu-west-1","roles":["ReadOnly","PowerUser"],"prefix":"team_","auto_prefix":false,"output":"text","config_file":"aws/config","state_dir":"state"}}}`

func TestSettingsCLIExplicitFlagsOverrideContext(t *testing.T) {
	root := env(t)
	path := writeSettings(t, root, configured)
	o, err := Parse([]string{"plan", "--settings-file", path}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if o.StartURL != "https://example.invalid/start" || o.Session != "work" || !o.SessionExplicit || o.SSORegion != "us-west-2" || o.Region != "eu-west-1" || !o.RegionFromSettings || o.Prefix != "team_" || o.AutoPrefix || o.Output != "text" || !reflect.DeepEqual([]string(o.Roles), []string{"ReadOnly", "PowerUser"}) || o.Config != filepath.Join(root, "aws/config") || o.State != filepath.Join(root, "state") {
		t.Fatalf("context defaults not applied: %+v", o)
	}
	args := []string{"plan", "--settings-file", path, "--context", "work", "--sso-start-url", "https://override.invalid/start", "--sso-session-name", "default", "--sso-region", "us-east-1", "--region", "us-east-2", "--role", "Admin", "--role", "Audit", "--prefix", "", "--auto-prefix=true", "--output", "json", "--config-file", "cli-config", "--state-dir", "cli-state"}
	o, err = Parse(args, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	config, _ := filepath.Abs("cli-config")
	state, _ := filepath.Abs("cli-state")
	if o.StartURL != "https://override.invalid/start" || o.Session != "default" || !o.SessionExplicit || o.SSORegion != "us-east-1" || o.Region != "us-east-2" || o.RegionFromSettings || o.Prefix != "" || !o.AutoPrefix || o.Output != "json" || !reflect.DeepEqual([]string(o.Roles), []string{"Admin", "Audit"}) || o.Config != config || o.State != state {
		t.Fatalf("explicit flags lost: %+v", o)
	}
	path = writeSettings(t, root, strings.ReplaceAll(configured, `"auto_prefix":false`, `"auto_prefix":true`))
	o, err = Parse([]string{"plan", "--settings-file", path, "--auto-prefix=false"}, &bytes.Buffer{})
	if err != nil || o.AutoPrefix {
		t.Fatal(o, err)
	}
}
func TestSettingsCLILoadOnlyWhenRequested(t *testing.T) {
	root := env(t)
	dir := filepath.Join(root, ".aws-sso-profile-sync")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`invalid DO_NOT_ECHO`), 0600)
	if _, err := Parse([]string{"doctor"}, &bytes.Buffer{}); err != nil {
		t.Fatal("unused settings read", err)
	}
	e, _, code := run(t, "doctor", "--format", "json")
	if code != 0 {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"doctor", "--context", "work"}, {"doctor", "--settings-file", ""}, {"doctor", "--context", ""}} {
		if _, err := Parse(args, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "DO_NOT_ECHO") {
			t.Fatal(args, err)
		}
	}
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte(configured), 0600)
	o, err := Parse([]string{"doctor", "--context", "work", "--state-dir", filepath.Join(root, "other")}, &bytes.Buffer{})
	if err != nil || o.Session != "work" {
		t.Fatal(o, err)
	}
	if o.Config != filepath.Join(dir, "aws/config") || o.State != filepath.Join(root, "other") {
		t.Fatal("wrong default file or path precedence", o)
	}
}
func TestSettingsCLIPreviewsRemainReadOnly(t *testing.T) {
	root := env(t)
	path := writeSettings(t, root, configured)
	before, _ := os.Stat(path)
	data, _ := os.ReadFile(path)
	for _, command := range []string{"doctor", "list", "plan", "discover", "sync"} {
		args := []string{command, "--settings-file", path, "--format", "json"}
		if command == "sync" {
			args = append(args, "--dry-run")
		}
		e, _, code := run(t, args...)
		if command == "doctor" || command == "list" {
			if code != 0 {
				t.Fatal(command, e)
			}
		} else if code != 1 || e.Error.Code != "login_required" {
			t.Fatal(command, e)
		}
	}
	after, _ := os.Stat(path)
	got, _ := os.ReadFile(path)
	if !bytes.Equal(data, got) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("settings modified")
	}
	for _, name := range []string{"state", "aws"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("preview wrote", name, err)
		}
	}
}
