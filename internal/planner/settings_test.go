package planner

import (
	"reflect"
	"testing"

	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/configstore"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
)

func managedSettings(t *testing.T) (configstore.Snapshot, []domain.Assignment, Options, string) {
	t.Helper()
	s, a, o := setup()
	p, e := Build(s, a, o)
	if e != nil {
		t.Fatal(e)
	}
	s.Sections = p.Sections
	s.Owned = p.Owned
	return s, a, o, p.Results[0].Profile.Name
}

func TestProfileSettingsPreservedUnlessExplicitOverride(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "requested differs", true: "owner edited"}[external], func(t *testing.T) {
			s, a, o, name := managedSettings(t)
			if external {
				s.Sections["profile "+name]["region"] = "eu-west-1"
				s.Sections["profile "+name]["output"] = "text"
			}
			beforeRegion, beforeOutput := s.Sections["profile "+name]["region"], s.Sections["profile "+name]["output"]
			o.Region = "ap-south-1"
			o.Output = "yaml"
			p, e := Build(s, a, o)
			if e != nil || p.HasConflicts() {
				t.Fatalf("preserve rejected: %+v %v", p, e)
			}
			if len(p.Results) != 1 || p.Results[0].Status != "unchanged" || p.Results[0].Profile.Region != beforeRegion || p.Results[0].Profile.Output != beforeOutput {
				t.Fatalf("settings lost: %+v", p)
			}
			want := []domain.Warning{{Code: "setting_preserved", Profiles: []string{name}, Field: "output", Existing: beforeOutput, Requested: "yaml"}, {Code: "setting_preserved", Profiles: []string{name}, Field: "region", Existing: beforeRegion, Requested: "ap-south-1"}}
			if !reflect.DeepEqual(p.Warnings, want) {
				t.Fatalf("warnings %+v want %+v", p.Warnings, want)
			}
			if p.Owned[name].Region != beforeRegion || p.Owned[name].Output != beforeOutput {
				t.Fatalf("manifest incoherent %+v", p.Owned[name])
			}
			if external && (p.Sections["profile "+name]["region"] != beforeRegion || p.Sections["profile "+name]["output"] != beforeOutput) {
				t.Fatal("missing metadata reconciliation intent")
			}
			if s.Sections["profile "+name]["region"] != beforeRegion {
				t.Fatal("snapshot mutated")
			}
			o.OverrideProfileSettings = true
			p, e = Build(s, a, o)
			if e != nil || p.HasConflicts() || p.Results[0].Status != "updated" || p.Results[0].Profile.Region != o.Region || p.Results[0].Profile.Output != o.Output || len(p.Warnings) != 0 {
				t.Fatalf("override failed: %+v %v", p, e)
			}
		})
	}
}

func TestProfileSettingsOverrideCannotBypassIdentityOrOwnership(t *testing.T) {
	for _, field := range []string{"sso_session", "sso_account_id", "sso_role_name", "unowned", "session_url", "session_region"} {
		t.Run(field, func(t *testing.T) {
			s, a, o, name := managedSettings(t)
			o.OverrideProfileSettings = true
			o.Region = "eu-west-1"
			switch field {
			case "unowned":
				delete(s.Owned, name)
			case "session_url":
				s.Sections["sso-session sample"]["sso_start_url"] = "https://other.invalid/start"
			case "session_region":
				s.Sections["sso-session sample"]["sso_region"] = "eu-west-1"
			default:
				s.Sections["profile "+name][field] = "changed"
			}
			p, e := Build(s, a, o)
			if e == nil && !p.HasConflicts() {
				t.Fatalf("override bypassed %s: %+v", field, p)
			}
		})
	}
}

func TestDuplicateWarningsUseProjectedSectionsAndRetainAliases(t *testing.T) {
	s, a, o := setup()
	s.Sections["default"] = map[string]string{"sso_start_url": o.Session.StartURL, "sso_region": o.Session.Region, "sso_account_id": a[0].AccountID, "sso_role_name": a[0].RoleName}
	p, e := Build(s, a, o)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Warnings) != 1 || p.Warnings[0].Code != "duplicate_profiles" || len(p.Warnings[0].Profiles) != 2 || p.Warnings[0].Profiles[1] != "default" {
		t.Fatalf("projected duplicate missing %+v", p.Warnings)
	}
	if len(s.Sections) != 1 || s.Sections["default"] == nil || p.Sections["default"] != nil {
		t.Fatal("alias changed or snapshot mutated")
	}
}

func TestMissingMutableSettingsReceiveRequestedDefaults(t *testing.T) {
	s, a, o, name := managedSettings(t)
	delete(s.Sections["profile "+name], "region")
	delete(s.Sections["profile "+name], "output")
	p, e := Build(s, a, o)
	if e != nil || p.HasConflicts() || p.Results[0].Status != "updated" || len(p.Warnings) != 0 || p.Results[0].Profile.Region != o.Region || p.Results[0].Profile.Output != o.Output {
		t.Fatalf("defaults missing: %+v %v", p, e)
	}
}
