// Compatibility adapters preserve existing behavioral assertions while using modular code.
package main

import (
	"context"
	"fmt"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/cli"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/configstore"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/planner"
	"os"
	"strings"
	"testing"
)

const defaultProfileRegion = "us-east-2"

var profilePrefix, ssoConfigFile, ssoSessionConfigName, ssoRegion, profileRegion, profileOutput, ssoStartURL string
var dryRun, useAutoPrefix bool
var getAccessTokenFunc = func() (string, string, error) { return "", "", fmt.Errorf("login_required") }
var runAwsSsoLogin = func(string) error { return fmt.Errorf("test login blocked") }

type CombinedRole struct{ AccountId, AccountName, RoleName string }

func generatePrefixFromRole(s string) string { return planner.Prefix(s) }
func getProfileNameFromRole(r CombinedRole) string {
	return planner.Name(domain.Assignment{AccountID: r.AccountId, AccountName: r.AccountName, RoleName: r.RoleName}, planner.Options{Session: session(), Prefix: profilePrefix, AutoPrefix: useAutoPrefix})
}
func session() domain.Session {
	url := ssoStartURL
	if url == "" {
		url = "https://sample.invalid/start"
	}
	region := ssoRegion
	if region == "" {
		region = "us-east-1"
	}
	name := ssoSessionConfigName
	if name == "" {
		name = "default"
	}
	return domain.Session{Name: name, StartURL: url, Region: region}.Normalized()
}
func profileExists(name, path string) bool {
	s, e := (configstore.Store{Path: path}).Read()
	return e == nil && s.Sections["profile "+name]["sso_session"] != ""
}
func writeProfileToConfig(name string, r CombinedRole) error {
	store := configstore.Store{Path: ssoConfigFile}
	s, e := store.Read()
	if e != nil {
		return e
	}
	if dryRun {
		return nil
	}
	out := profileOutput
	if out == "" {
		out = "json"
	}
	p := domain.Profile{Name: name, Session: session(), Assignment: domain.Assignment{AccountID: r.AccountId, AccountName: r.AccountName, RoleName: r.RoleName}, Region: profileRegion, Output: out}
	owned := map[string]domain.Profile{}
	for n, v := range s.Owned {
		owned[n] = v
	}
	owned[name] = p
	ss := session()
	return store.Apply(context.Background(), s, map[string]map[string]string{"profile " + name: planner.Keys(p), "sso-session " + ss.Name: {"sso_start_url": ss.StartURL, "sso_region": ss.Region, "sso_registration_scopes": "sso:account:access"}}, owned)
}
func ensureSsoSessionConfigPresent() (bool, error) {
	store := configstore.Store{Path: ssoConfigFile}
	s, e := store.Read()
	if e != nil {
		return false, e
	}
	ss := session()
	if s.Sections["sso-session "+ss.Name] != nil {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	return true, store.Apply(context.Background(), s, map[string]map[string]string{"sso-session " + ss.Name: {"sso_start_url": ss.StartURL, "sso_region": ss.Region, "sso_registration_scopes": "sso:account:access"}}, s.Owned)
}
func findMatchingSsoSessionName(url, region, path string) (string, bool) {
	s, e := (configstore.Store{Path: path}).Read()
	if e != nil {
		return "", false
	}
	for n, k := range s.Sections {
		if strings.HasPrefix(n, "sso-session ") && strings.TrimRight(k["sso_start_url"], "/") == strings.TrimRight(url, "/") && k["sso_region"] == region {
			return strings.TrimPrefix(n, "sso-session "), true
		}
	}
	return "", false
}
func getExistingSsoSessionBlock(name, path string) (string, error) {
	s, e := (configstore.Store{Path: path}).Read()
	if e != nil {
		return "", e
	}
	k, ok := s.Sections["sso-session "+name]
	if !ok {
		return "", fmt.Errorf("missing")
	}
	return fmt.Sprintf("[sso-session %s]\nsso_start_url = %s\nsso_region = %s\n", name, k["sso_start_url"], k["sso_region"]), nil
}
func printBlockIndented(indent, block string) {
	for _, line := range strings.Split(strings.TrimSuffix(block, "\n"), "\n") {
		fmt.Println(indent + line)
	}
}
func resolveProfileRegion(explicit, path string) (string, string) {
	s, _ := (configstore.Store{Path: path}).Read()
	return cli.ResolveRegion(explicit, s)
}
func singleRoleFromDistinctRoles(roles []string) (string, bool) {
	if len(roles) == 1 {
		return roles[0], true
	}
	return "", false
}
func login() error {
	if dryRun {
		return domain.Fail("login_required", "run explicit login")
	}
	return fmt.Errorf("test login blocked")
}
func TestMain(m *testing.M) {
	root, e := os.MkdirTemp("", "sso-legacy-tests-")
	if e != nil {
		panic(e)
	}
	defer os.RemoveAll(root)
	os.Setenv("HOME", root)
	os.Setenv("AWS_CONFIG_FILE", root+"/config")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", root+"/credentials")
	os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}
