//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/configstore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

func TestFlociCLIJourney(t *testing.T) {
	if os.Getenv("AWS_SSO_TEST_DOCKER_ABSENCE_HELPER") == "1" {
		startFloci(t, t.TempDir(), "11111111-2222-3333-4444-555555555555")
		t.Fatal("unavailable Docker unexpectedly started a fixture")
	}
	suite := t
	var f fixture
	var c client
	var login execution
	var sync execution
	if !t.Run("F01_PinnedSDKFixture", func(t *testing.T) { f = seedFixture(suite) }) {
		t.FailNow()
	}
	if !t.Run("F02_CompiledCLIDeviceLogin", func(t *testing.T) {
		c = newClient(suite, buildCLI(suite), f.endpoint)
		login = c.login(t)
		if _, err := os.Stat(c.config()); !os.IsNotExist(err) {
			t.Fatal("login wrote AWS config")
		}
	}) {
		t.FailNow()
	}
	t.Run("F03_OnlyAssignedAccountsAndRoles", func(t *testing.T) {
		cache := readCache(t, c)
		token := cache.token["accessToken"].(string)
		portal := sso.NewFromConfig(localConfig(f.endpoint))
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pairs := map[string]bool{}
		paginator := sso.NewListAccountsPaginator(portal, &sso.ListAccountsInput{AccessToken: aws.String(token), MaxResults: aws.Int32(1)})
		pages := 0
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			pages++
			for _, account := range page.AccountList {
				roles := sso.NewListAccountRolesPaginator(portal, &sso.ListAccountRolesInput{AccessToken: aws.String(token), AccountId: account.AccountId, MaxResults: aws.Int32(1)})
				for roles.HasMorePages() {
					page, err := roles.NextPage(ctx)
					if err != nil {
						t.Fatal(err)
					}
					for _, role := range page.RoleList {
						pairs[aws.ToString(account.AccountId)+"/"+aws.ToString(role.RoleName)] = true
					}
				}
			}
		}
		if pages != 2 || !reflect.DeepEqual(pairs, fixtureWantPairs()) {
			t.Fatalf("portal assignments/pages differ: %v pages=%d", pairs, pages)
		}
		_, err := portal.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{AccessToken: aws.String(token), AccountId: aws.String("111111111111"), RoleName: aws.String("UnassignedRole")})
		if err == nil {
			t.Fatal("unassigned role credentials allowed")
		}
	})
	t.Run("F04_CompiledDiscoverPlanSync", func(t *testing.T) {
		settingsPath := filepath.Join(c.root, "settings.json")
		settingsData, err := json.Marshal(map[string]any{"schema_version": 1, "contexts": map[string]any{"sample": map[string]any{"roles": []string{readRole, powerRole}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settingsPath, settingsData, 0600); err != nil {
			t.Fatal(err)
		}
		before := snapshotRoot(t, c.root)
		discover := c.run(t, "discover")
		mustSuccess(t, discover)
		if len(discover.data.Assignments) != 4 {
			t.Fatalf("expected four accessible assignments, got %d", len(discover.data.Assignments))
		}
		missingChoice := c.run(t, "plan")
		if missingChoice.err == nil {
			t.Fatal("multiple roles silently auto-selected")
		}
		plan := c.run(t, "plan", "--role", readRole, "--role", powerRole, "--region", "eu-west-2")
		mustSuccess(t, plan)
		if len(plan.data.Results) != 4 {
			t.Fatal("plan does not contain four profiles")
		}
		configuredPlan := c.run(t, "plan", "--settings-file", settingsPath, "--region", "eu-west-2")
		mustSuccess(t, configuredPlan)
		if !reflect.DeepEqual(plan.data.Results, configuredPlan.data.Results) {
			t.Fatal("settings role selection differs from explicit flags")
		}
		if !reflect.DeepEqual(before, snapshotRoot(t, c.root)) {
			t.Fatal("discover/plan wrote files/cache/state")
		}
		sync = c.run(t, "sync", "--settings-file", settingsPath, "--region", "eu-west-2")
		mustSuccess(t, sync)
		if sync.data.Counts["created"] != 4 {
			t.Fatalf("created count=%d", sync.data.Counts["created"])
		}
		bytes, err := os.ReadFile(c.config())
		if err != nil {
			t.Fatal(err)
		}
		sections, err := configstore.Parse(bytes)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range sync.data.Results {
			if r.Status != "created" || !strings.Contains(string(bytes), "[profile "+r.Profile.Name+"]") || r.Profile.Region != "eu-west-2" {
				t.Fatal("saved profiles disagree with results/region")
			}
			if sections["profile "+r.Profile.Name]["sso_role_name"] != r.Profile.Assignment.RoleName {
				t.Fatal("saved role differs from discovered permission-set name")
			}
		}
		if !strings.Contains(string(bytes), "[sso-session sample]") {
			t.Fatal("named SSO session missing")
		}
	})
	t.Run("F05_SecondSyncAndPreviewZeroWrites", func(t *testing.T) {
		before := snapshotRoot(t, c.root)
		repeat := c.run(t, "sync", "--role", readRole, "--role", powerRole, "--region", "eu-west-2")
		mustSuccess(t, repeat)
		if repeat.data.Counts["unchanged"] != 4 {
			t.Fatal("repeat sync not unchanged")
		}
		dry := c.run(t, "sync", "--dry-run", "--role", readRole, "--role", powerRole, "--region", "eu-west-2")
		mustSuccess(t, dry)
		for _, command := range []string{"plan", "list", "doctor", "discover"} {
			r := c.run(t, command, "--role", readRole, "--role", powerRole, "--region", "eu-west-2")
			mustSuccess(t, r)
			assertSecretFree(t, r, c.root)
		}
		if !reflect.DeepEqual(before, snapshotRoot(t, c.root)) {
			t.Fatal("repeat sync/readonly commands changed bytes, modes or mtimes")
		}
	})
	t.Run("F06_MachineJSONAndSecretRedaction", func(t *testing.T) {
		assertSecretFree(t, login, c.root)
		assertSecretFree(t, sync, c.root)
		assertSecretFree(t, c.run(t, "discover"), c.root)
	})
	t.Run("F07_RejectUnsafeTestBoundary", func(t *testing.T) {
		tests := []struct {
			name   string
			change func(*client, []string) []string
		}{{"nonloopback", func(c *client, e []string) []string { c.endpoint = "https://sso.us-east-1.amazonaws.com"; return e }}, {"wrong-home", func(c *client, e []string) []string { return append(e, "HOME="+filepath.Dir(c.root)) }}, {"real-credentials", func(c *client, e []string) []string { return append(e, "AWS_ACCESS_KEY_ID=AKIAEXAMPLEPRODUCTION") }}, {"inherited-profile", func(c *client, e []string) []string { return append(e, "AWS_PROFILE=personal") }}}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				copy := c
				env := test.change(&copy, c.env())
				before := snapshotRoot(t, c.root)
				r := copy.execute(t, "discover", env)
				if r.err == nil || r.data.Error == nil || r.data.Error.Code != "unsupported_endpoint" {
					t.Fatal("unsafe test environment was not rejected")
				}
				if !reflect.DeepEqual(before, snapshotRoot(t, c.root)) {
					t.Fatal("unsafe boundary wrote files")
				}
			})
		}
	})
	t.Run("F08_InvalidTokenAndConflictLeaveConfig", func(t *testing.T) {
		cache := readCache(t, c)
		cache.token["accessToken"] = "synthetic-invalid-token"
		b, _ := json.Marshal(cache.token)
		if err := os.WriteFile(cache.path, b, 0600); err != nil {
			t.Fatal(err)
		}
		before := snapshotRoot(t, c.root)
		r := c.run(t, "sync", "--role", readRole)
		if r.err == nil || r.data.Error == nil || r.data.Error.Code != "auth_invalid" {
			t.Fatal("invalid token did not fail explicitly")
		}
		if !reflect.DeepEqual(before, snapshotRoot(t, c.root)) {
			t.Fatal("invalid token modified configuration/cache")
		}
		// Explicit login must recover a revoked/invalid bearer via a fresh
		// real device flow while preserving the existing configuration.
		configBefore, err := os.Stat(c.config())
		if err != nil {
			t.Fatal(err)
		}
		bytesBefore, err := os.ReadFile(c.config())
		if err != nil {
			t.Fatal(err)
		}
		recovered := c.login(t)
		assertSecretFree(t, recovered, c.root)
		newCache := readCache(t, c)
		if newCache.token["accessToken"] == "synthetic-invalid-token" {
			t.Fatal("explicit re-login preserved invalid bearer")
		}
		configAfter, err := os.Stat(c.config())
		if err != nil {
			t.Fatal(err)
		}
		bytesAfter, err := os.ReadFile(c.config())
		if err != nil {
			t.Fatal(err)
		}
		if string(bytesBefore) != string(bytesAfter) || !configBefore.ModTime().Equal(configAfter.ModTime()) || configBefore.Mode() != configAfter.Mode() {
			t.Fatal("explicit authentication recovery modified configuration")
		}
		// Simulate an external identity change to a tool-owned profile. Ownership
		// provenance never licenses overwriting this different account identity.
		original, err := os.ReadFile(c.config())
		if err != nil {
			t.Fatal(err)
		}
		changed := strings.Replace(string(original), "sso_account_id = 111111111111", "sso_account_id = 999999999999", 1)
		if changed == string(original) {
			t.Fatal("fixture profile identity key missing")
		}
		if err := os.WriteFile(c.config(), []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
		before = snapshotRoot(t, c.root)
		r = c.run(t, "sync", "--role", readRole, "--role", powerRole, "--region", "eu-west-2")
		if r.err == nil {
			t.Fatal("changed owned identity was overwritten")
		}
		if !reflect.DeepEqual(before, snapshotRoot(t, c.root)) {
			t.Fatal("conflicted sync wrote files")
		}
		if err := os.WriteFile(c.config(), original, 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("F09_SecondSessionRegionAndRefreshIsolated", func(t *testing.T) {
		second := c
		second.session = "sample-other"
		second.region = "eu-west-1"
		before := snapshotRoot(t, c.root)
		r := second.run(t, "plan", "--role", readRole)
		if r.err == nil || r.data.Error == nil || r.data.Error.Code != "login_required" {
			t.Fatal("different session/region reused first cache")
		}
		if !reflect.DeepEqual(before, snapshotRoot(t, c.root)) {
			t.Fatal("missing-session preview wrote files")
		}
		second.login(t)
		r = second.run(t, "discover")
		mustSuccess(t, r)
		if len(r.data.Assignments) != 4 {
			t.Fatal("second session visibility differs")
		}
		cache := readCache(t, second)
		oldAccess := cache.token["accessToken"]
		cache.token["expiresAt"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		b, _ := json.Marshal(cache.token)
		if err := os.WriteFile(cache.path, b, 0600); err != nil {
			t.Fatal(err)
		}
		before = snapshotRoot(t, c.root)
		r = second.run(t, "discover")
		if r.err == nil || r.data.Error == nil || r.data.Error.Code != "login_required" {
			t.Fatal("expired token reused outside explicit login")
		}
		if !reflect.DeepEqual(before, snapshotRoot(t, c.root)) {
			t.Fatal("expired discover secretly refreshed")
		}
		r = second.run(t, "login")
		mustSuccess(t, r)
		fresh := readCache(t, second)
		if fresh.token["accessToken"] == oldAccess {
			t.Fatal("explicit refresh did not rotate access token")
		}
		assertSecretFree(t, r, c.root)
		r = second.run(t, "plan", "--role", readRole, "--region", "ap-south-1")
		mustSuccess(t, r)
		if len(r.data.Results) != 2 {
			t.Fatal("selected role does not yield two profiles")
		}
		for _, result := range r.data.Results {
			if result.Profile.Session.Name != second.session || result.Profile.Session.Region != second.region || result.Profile.Region != "ap-south-1" || result.Profile.Assignment.RoleName != readRole {
				t.Fatal("second session/role/region lost isolation")
			}
		}
	})
	t.Run("F10_RequiredPrerequisitesAndCleanup", func(t *testing.T) {
		if f.endpoint == "" || c.binary == "" {
			t.Fatal("required Docker/seed/binary prerequisites absent")
		}
		requireUnavailableDockerFailure(t)
	})
}

func TestFlociDockerAbsenceFailure(t *testing.T) { requireUnavailableDockerFailure(t) }

func requireUnavailableDockerFailure(t *testing.T) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	missing := filepath.Join(root, "no-docker.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestFlociCLIJourney$", "-test.v", "-test.timeout=15s")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "DOCKER_HOST=unix://" + missing, "AWS_SSO_TEST_DOCKER_ABSENCE_HELPER=1"}
	if value := os.Getenv("TMPDIR"); value != "" {
		cmd.Env = append(cmd.Env, "TMPDIR="+value)
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("Docker-absence subprocess exceeded bounded deadline")
	}
	if err == nil || !strings.Contains(string(output), "F10 FAIL: explicitly selected Docker host unavailable; no fallback or skip") || !strings.Contains(string(output), "--- FAIL: TestFlociCLIJourney") || strings.Contains(string(output), "--- SKIP") {
		t.Fatal("unavailable Docker was not observed as a fixture FAIL")
	}
	t.Log("observed missing suite-selected Docker socket: fixture subprocess FAIL, nonzero exit, no skip, no fallback")
}

type cachedToken struct {
	path  string
	bytes []byte
	token map[string]any
}

func readCache(t *testing.T, c client) cachedToken {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(c.state(), "auth", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var token map[string]any
		if json.Unmarshal(b, &token) != nil {
			t.Fatal("invalid token JSON")
		}
		session, ok := token["session"].(map[string]any)
		if ok && session["name"] == c.session && session["sso_region"] == c.region {
			info, err := os.Stat(file)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("cache file mode not 0600")
			}
			return cachedToken{file, b, token}
		}
	}
	t.Fatal("named-session cache not found")
	return cachedToken{}
}
