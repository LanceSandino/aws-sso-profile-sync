package planner

import (
	"fmt"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/configstore"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
	"reflect"
	"testing"
)

func TestP01DeterministicP02DistinctRoles(t *testing.T) {
	s := domain.Session{Name: "sample", StartURL: "https://sample.invalid/start", Region: "us-east-1"}
	a := []domain.Assignment{{AccountID: "111111111111", AccountName: "Same", RoleName: "ReadOnly"}, {AccountID: "111111111111", AccountName: "Same", RoleName: "PowerUser"}}
	o := Options{Session: s, Region: "us-east-2", Output: "json", Prefix: "custom_", Roles: []string{"ReadOnly", "PowerUser"}}
	p, e := Build(configstore.Snapshot{}, a, o)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Results) != 2 || p.Results[0].Profile.Name == p.Results[1].Profile.Name {
		t.Fatal(p)
	}
	a[0], a[1] = a[1], a[0]
	q, e := Build(configstore.Snapshot{}, a, o)
	if e != nil || !reflect.DeepEqual(p, q) {
		t.Fatalf("nondeterministic %v", e)
	}
}

func setup() (configstore.Snapshot, []domain.Assignment, Options) {
	return configstore.Snapshot{Sections: map[string]map[string]string{}, Owned: map[string]domain.Profile{}}, []domain.Assignment{{AccountID: "111111111111", AccountName: "Sample Dev", RoleName: "AWSReadOnlyAccess"}}, Options{Session: domain.Session{Name: "sample", StartURL: "https://sample.invalid/start/", Region: "us-east-1"}, Region: "us-east-2", Output: "json", AutoPrefix: true}
}
func TestP04P05OwnershipAndEdits(t *testing.T) {
	s, a, o := setup()
	p, e := Build(s, a, o)
	if e != nil {
		t.Fatal(e)
	}
	r := p.Results[0]
	s.Sections["profile "+r.Profile.Name] = Keys(r.Profile)
	p, e = Build(s, a, o)
	if e != nil || !p.HasConflicts() {
		t.Fatal("unmanaged takeover", e, p)
	}
	s.Owned[r.Profile.Name] = r.Profile
	p, e = Build(s, a, o)
	if e != nil || p.HasConflicts() || p.Results[0].Status != "unchanged" {
		t.Fatal(e, p)
	}
	s.Sections["profile "+r.Profile.Name]["sso_role_name"] = "PowerUser"
	p, e = Build(s, a, o)
	if e != nil || !p.HasConflicts() {
		t.Fatal(e, p)
	}
	s.Sections["profile "+r.Profile.Name] = Keys(r.Profile)
	o.Region = "eu-west-1"
	o.OverrideProfileSettings = true
	p, e = Build(s, a, o)
	if e != nil || p.Results[0].Status != "updated" {
		t.Fatal(e, p)
	}
	delete(s.Sections, "profile "+r.Profile.Name)
	p, e = Build(s, a, o)
	if e != nil || !p.HasConflicts() {
		t.Fatal(e, p)
	}
}
func TestP07StaleP03ChangingAccountName(t *testing.T) {
	s, a, o := setup()
	p, _ := Build(s, a, o)
	r := p.Results[0]
	s.Owned[r.Profile.Name] = r.Profile
	s.Sections["profile "+r.Profile.Name] = Keys(r.Profile)
	a[0].AccountName = "Renamed\n\x1b[31m"
	p, e := Build(s, a, o)
	if e != nil || p.Results[0].Profile.Name != r.Profile.Name || p.Results[0].Status != "unchanged" {
		t.Fatal(e, p)
	}
	b := a[0]
	b.AccountID = "222222222222"
	p, e = Build(s, []domain.Assignment{b}, o)
	if e != nil || len(p.Results) != 2 {
		t.Fatal(e, p)
	}
	found := false
	for _, r := range p.Results {
		found = found || r.Status == "stale"
	}
	if !found {
		t.Fatal(p)
	}
}
func TestP10RoleSelectionD02D03(t *testing.T) {
	s, a, o := setup()
	p, e := Build(s, a, o)
	if e != nil || p.Explanation == "" {
		t.Fatal(e, p)
	}
	b := a[0]
	b.RoleName = "PowerUser"
	a = append(a, b)
	if _, e = Build(s, a, o); domain.ErrorCode(e) != "role_selection_required" {
		t.Fatal(e)
	}
	o.Roles = []string{"Missing"}
	if _, e = Build(s, a, o); domain.ErrorCode(e) != "role_selection_required" {
		t.Fatal(e)
	}
	o.Roles = []string{"PowerUser"}
	p, e = Build(s, a, o)
	if e != nil || len(p.Results) != 1 || p.Results[0].Profile.Assignment.RoleName != "PowerUser" {
		t.Fatal(e, p)
	}
	o.Roles = []string{"PowerUser", "AWSReadOnlyAccess"}
	a = append(a, b)
	p, e = Build(s, a, o)
	if e != nil || len(p.Results) != 2 {
		t.Fatal(e, p)
	}
}
func TestC13InvalidInputs(t *testing.T) {
	s, a, o := setup()
	s.Sections["sso-session sample"] = map[string]string{"sso_start_url": "https://other.invalid/start", "sso_region": "us-east-1"}
	if _, e := Build(s, a, o); domain.ErrorCode(e) != "conflict" {
		t.Fatal(e)
	}
	delete(s.Sections, "sso-session sample")
	for _, edit := range []func(*Options){func(o *Options) { o.Session.Name = "" }, func(o *Options) { o.Region = "" }, func(o *Options) { o.Output = "\n[default]" }} {
		_, _, x := setup()
		edit(&x)
		if _, e := Build(s, a, x); domain.ErrorCode(e) != "config_invalid" {
			t.Fatal(e)
		}
	}
	a[0].AccountID = "bad"
	if _, e := Build(s, a, o); domain.ErrorCode(e) != "config_invalid" {
		t.Fatal(e)
	}
}
func TestP03SafeNames(t *testing.T) {
	for in, want := range map[string]string{"\x1b[31mBad Name]": "31mBad-Name", "...": "account", "": "account"} {
		if got := SafeName(in); got != want {
			t.Fatal(in, got, want)
		}
	}
	if len(SafeName(string(make([]byte, 200)))) > 48 {
		t.Fatal("long")
	}
	if Prefix("Access") != "" || Prefix("AWSReadOnlyAccess") != "ReadOnly_" {
		t.Fatal("prefix")
	}
	s, a, o := setup()
	a[0].AccountName = string(make([]byte, 200))
	p, e := Build(s, a, o)
	if e != nil || len(p.Results) != 1 {
		t.Fatal(e, p)
	}
}
func TestP01DuplicateOwnedIdentityAndUnsafeRoleFail(t *testing.T) {
	s, a, o := setup()
	p, _ := Build(s, a, o)
	profile := p.Results[0].Profile
	s.Owned[profile.Name] = profile
	other := profile
	other.Name = "another"
	s.Owned[other.Name] = other
	if _, e := Build(s, a, o); domain.ErrorCode(e) != "conflict" {
		t.Fatal(e)
	}
	s.Owned = map[string]domain.Profile{}
	bad := a[0]
	bad.RoleName = "Admin\x1b[31m"
	a = append(a, bad)
	if _, e := Build(s, a, o); domain.ErrorCode(e) != "config_invalid" {
		t.Fatal(e)
	}
}

func TestRoleNamesWithEqualsRemainExact(t *testing.T) {
	for _, role := range []string{"Team=ReadOnly", "Team+=,.@-ReadOnly"} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/explicit=%t", role, explicit), func(t *testing.T) {
				s, a, o := setup()
				a[0].RoleName = role
				if explicit {
					o.Roles = []string{role}
				}
				plan, err := Build(s, a, o)
				if err != nil || len(plan.Results) != 1 {
					t.Fatalf("valid assigned role rejected: %+v %v", plan, err)
				}
				profile := plan.Results[0].Profile
				if profile.Assignment.RoleName != role || plan.Sections["profile "+profile.Name]["sso_role_name"] != role {
					t.Fatalf("role value changed: %+v", plan)
				}
			})
		}
	}
}

func TestRoleNamesWithEqualsStillRejectConfigInjection(t *testing.T) {
	for _, role := range []string{"Team=ReadOnly\nregion=evil", "Team=ReadOnly\rregion=evil", "Team=ReadOnly\x1b", "Team=[default]", "Team=ReadOnly;comment"} {
		s, a, o := setup()
		a[0].RoleName = role
		if _, err := Build(s, a, o); domain.ErrorCode(err) != "config_invalid" {
			t.Fatalf("unsafe role accepted: %q %v", role, err)
		}
	}
}

func TestP07AllAssignmentsRemovedRetainsStaleProfiles(t *testing.T) {
	for name, roles := range map[string][]string{"implicit": nil, "explicit": {"AWSReadOnlyAccess"}} {
		t.Run(name, func(t *testing.T) {
			s, a, o := setup()
			initial, e := Build(s, a, o)
			if e != nil {
				t.Fatal(e)
			}
			profile := initial.Results[0].Profile
			s.Owned[profile.Name] = profile
			for section, keys := range initial.Sections {
				s.Sections[section] = keys
			}
			o.Roles = roles
			plan, e := Build(s, []domain.Assignment{}, o)
			if e != nil {
				t.Fatalf("complete empty discovery with roles %v rejected: %v", roles, e)
			}
			if len(plan.Results) != 1 || plan.Results[0].Status != "stale" || plan.Results[0].Profile != profile {
				t.Fatalf("stale profile not retained: %+v", plan)
			}
			if len(plan.Sections) != 0 || !reflect.DeepEqual(plan.Owned, s.Owned) {
				t.Fatalf("empty discovery proposes config/ownership changes: %+v", plan)
			}
		})
	}
}

func TestP07EmptyInitialDiscoveryIsEmptyPlan(t *testing.T) {
	for name, roles := range map[string][]string{"implicit": nil, "explicit": {"AWSReadOnlyAccess"}} {
		t.Run(name, func(t *testing.T) {
			s, _, o := setup()
			o.Roles = roles
			plan, e := Build(s, []domain.Assignment{}, o)
			if e != nil || len(plan.Results) != 0 || len(plan.Sections) != 0 || len(plan.Owned) != 0 {
				t.Fatalf("empty initial discovery with roles %v: %+v %v", roles, plan, e)
			}
		})
	}
}
