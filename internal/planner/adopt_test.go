package planner

import (
	"testing"

	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/configstore"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
)

// legacySetup mirrors a config written by v1: named session plus an unsuffixed profile.
func legacySetup() (configstore.Snapshot, []domain.Assignment, Options) {
	s, a, o := setup()
	o.AutoPrefix = false
	s.Sections["sso-session sample"] = map[string]string{"sso_start_url": "https://sample.invalid/start", "sso_region": "us-east-1", "sso_registration_scopes": "sso:account:access"}
	s.Sections["profile Sample-Dev_111111111111"] = map[string]string{"sso_session": "sample", "sso_account_id": "111111111111", "sso_role_name": "AWSReadOnlyAccess", "region": "us-east-2", "output": "json"}
	return s, a, o
}

func TestAdoptExistingIsOptIn(t *testing.T) {
	s, a, o := legacySetup()
	p, e := Build(s, a, o)
	if e != nil || len(p.Results) != 1 || p.Results[0].Status != "created" || p.Results[0].Profile.Name == "Sample-Dev_111111111111" {
		t.Fatalf("default behavior changed: %+v %v", p, e)
	}
	if len(p.Warnings) != 1 || p.Warnings[0].Code != "duplicate_profiles" {
		t.Fatalf("duplicate not reported: %+v", p.Warnings)
	}
}

func TestAdoptExistingMatchingLegacyProfile(t *testing.T) {
	s, a, o := legacySetup()
	o.AdoptExisting = true
	p, e := Build(s, a, o)
	if e != nil || p.HasConflicts() {
		t.Fatalf("adopt failed: %+v %v", p, e)
	}
	name := "Sample-Dev_111111111111"
	if len(p.Results) != 1 || p.Results[0].Status != "adopted" || p.Results[0].Profile.Name != name {
		t.Fatalf("not adopted: %+v", p.Results)
	}
	if len(p.Sections) != 1 || p.Sections["profile "+name] == nil {
		t.Fatalf("unexpected sections: %+v", p.Sections)
	}
	for k, v := range p.Sections["profile "+name] {
		if s.Sections["profile "+name][k] != v {
			t.Fatalf("adoption rewrote %s: %q", k, v)
		}
	}
	if got := p.Owned[name]; got.Name != name || got.Assignment.AccountID != "111111111111" || got.Session.Name != "sample" {
		t.Fatalf("ownership missing: %+v", p.Owned)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", p.Warnings)
	}
	// Once the manifest records the adoption, the next plan is a no-op.
	s.Owned = p.Owned
	p, e = Build(s, a, o)
	if e != nil || len(p.Results) != 1 || p.Results[0].Status != "unchanged" || len(p.Sections) != 0 {
		t.Fatalf("second run not idempotent: %+v %v", p, e)
	}
}

func TestAdoptExistingPreservesSettingsUnlessOverride(t *testing.T) {
	s, a, o := legacySetup()
	name := "Sample-Dev_111111111111"
	s.Sections["profile "+name]["region"] = "eu-west-1"
	o.AdoptExisting = true
	p, e := Build(s, a, o)
	if e != nil || p.Results[0].Status != "adopted" || p.Owned[name].Region != "eu-west-1" || p.Sections["profile "+name]["region"] != "eu-west-1" {
		t.Fatalf("region not preserved: %+v %v", p, e)
	}
	if len(p.Warnings) != 1 || p.Warnings[0].Code != "setting_preserved" || p.Warnings[0].Field != "region" {
		t.Fatalf("missing preserve warning: %+v", p.Warnings)
	}
	o.OverrideProfileSettings = true
	p, e = Build(s, a, o)
	if e != nil || p.Results[0].Status != "adopted" || p.Sections["profile "+name]["region"] != "us-east-2" {
		t.Fatalf("override ignored: %+v %v", p, e)
	}
}

func TestAdoptExistingRequiresExactIdentity(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"other role", "sso_role_name", "AWSPowerUserAccess"},
		{"other account", "sso_account_id", "222222222222"},
		{"other session", "sso_session", "elsewhere"},
		{"inline legacy sso", "sso_session", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, a, o := legacySetup()
			o.AdoptExisting = true
			kv := s.Sections["profile Sample-Dev_111111111111"]
			if tc.value == "" {
				delete(kv, tc.key)
				kv["sso_start_url"] = "https://sample.invalid/start"
				kv["sso_region"] = "us-east-1"
			} else {
				kv[tc.key] = tc.value
			}
			p, e := Build(s, a, o)
			if e != nil || len(p.Results) != 1 || p.Results[0].Status != "created" || p.Results[0].Profile.Name == "Sample-Dev_111111111111" {
				t.Fatalf("adopted non-matching profile: %+v %v", p, e)
			}
		})
	}
}

func TestAdoptExistingPrefersOwnedAndIsDeterministic(t *testing.T) {
	s, a, o := legacySetup()
	o.AdoptExisting = true
	s.Sections["profile Alias"] = map[string]string{"sso_session": "sample", "sso_account_id": "111111111111", "sso_role_name": "AWSReadOnlyAccess"}
	for i := 0; i < 20; i++ {
		p, e := Build(s, a, o)
		if e != nil || p.Results[0].Status != "adopted" || p.Results[0].Profile.Name != "Alias" {
			t.Fatalf("nondeterministic adoption: %+v %v", p, e)
		}
		if len(p.Warnings) != 1 || p.Warnings[0].Code != "duplicate_profiles" {
			t.Fatalf("remaining alias not reported: %+v", p.Warnings)
		}
	}
	owned, e := Build(configstore.Snapshot{Sections: map[string]map[string]string{"sso-session sample": s.Sections["sso-session sample"]}, Owned: map[string]domain.Profile{}}, a, o)
	if e != nil {
		t.Fatal(e)
	}
	name := owned.Results[0].Profile.Name
	s.Sections["profile "+name] = owned.Sections["profile "+name]
	s.Owned = owned.Owned
	p, e := Build(s, a, o)
	if e != nil || len(p.Results) != 1 || p.Results[0].Status != "unchanged" || p.Results[0].Profile.Name != name {
		t.Fatalf("managed profile not preferred: %+v %v", p, e)
	}
}
