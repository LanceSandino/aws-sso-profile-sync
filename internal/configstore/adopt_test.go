package configstore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
)

// v1Config is the aligned layout v1 wrote: named session plus unsuffixed profiles.
const v1Config = "[sso-session local]\nsso_start_url           = https://example.invalid/start\nsso_region              = us-east-1\nsso_registration_scopes = sso:account:access\n\n[profile dev]\nsso_session    = local\nsso_account_id = 111111111111\nsso_role_name  = ReadOnly\nregion         = us-west-2\noutput         = json\n"

func adoptFixture(t *testing.T, config string) (Store, Snapshot, map[string]map[string]string, map[string]domain.Profile) {
	t.Helper()
	s, _, desired, owned := fixture(t)
	if e := os.MkdirAll(filepath.Dir(s.Path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(s.Path, []byte(config), 0600); e != nil {
		t.Fatal(e)
	}
	before, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	delete(desired, "sso-session local")
	return s, before, desired, owned
}

func TestAdoptRequiresExplicitStorePermission(t *testing.T) {
	s, before, desired, owned := adoptFixture(t, v1Config)
	if e := s.Apply(context.Background(), before, desired, owned); domain.ErrorCode(e) != "conflict" {
		t.Fatalf("unmanaged takeover allowed without adoption: %v", e)
	}
	if _, e := os.Stat(s.Path + ".aws-sso-sync.json"); !os.IsNotExist(e) {
		t.Fatalf("manifest written on refusal: %v", e)
	}
}

func TestAdoptRecordsOwnershipWithoutRewritingConfig(t *testing.T) {
	s, before, desired, owned := adoptFixture(t, v1Config)
	s.AllowAdopt = true
	if e := s.Apply(context.Background(), before, desired, owned); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(s.Path)
	if e != nil || string(got) != v1Config {
		t.Fatalf("config rewritten: %q %v", got, e)
	}
	after, e := s.Read()
	if e != nil || after.Owned["dev"].Identity() != owned["dev"].Identity() {
		t.Fatalf("ownership not recorded: %+v %v", after.Owned, e)
	}
	if _, e := os.Stat(s.Path + ".aws-sso-sync.intent"); !os.IsNotExist(e) {
		t.Fatalf("intent left behind: %v", e)
	}
}

func TestAdoptRefusesIdentityMismatch(t *testing.T) {
	for _, edit := range []struct{ from, to string }{
		{"sso_role_name  = ReadOnly", "sso_role_name  = PowerUser"},
		{"sso_account_id = 111111111111", "sso_account_id = 222222222222"},
		{"sso_session    = local", "sso_session    = other"},
	} {
		t.Run(edit.to, func(t *testing.T) {
			config := strings.Replace(v1Config, edit.from, edit.to, 1)
			s, before, desired, owned := adoptFixture(t, config)
			s.AllowAdopt = true
			if e := s.Apply(context.Background(), before, desired, owned); domain.ErrorCode(e) != "conflict" {
				t.Fatalf("adopted mismatched profile: %v", e)
			}
			got, _ := os.ReadFile(s.Path)
			if string(got) != config {
				t.Fatalf("config changed on refusal: %q", got)
			}
		})
	}
}
