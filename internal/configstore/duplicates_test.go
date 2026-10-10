package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

func TestDuplicateProfilesCanonicalIdentityRetainsManualAliases(t *testing.T) {
	sections := map[string]map[string]string{
		"sso-session sample":  {"sso_start_url": "https://sample.invalid/start/", "sso_region": "us-east-1"},
		"profile z":           {"sso_session": "sample", "sso_account_id": "111111111111", "sso_role_name": "ReadOnly", "region": "eu-west-1"},
		"profile alias":       {"sso_start_url": "https://sample.invalid/start", "sso_region": "us-east-1", "sso_account_id": "111111111111", "sso_role_name": "ReadOnly", "output": "text"},
		"default":             {"sso_session": "sample", "sso_account_id": "111111111111", "sso_role_name": "ReadOnly"},
		"profile otherRole":   {"sso_session": "sample", "sso_account_id": "111111111111", "sso_role_name": "Admin"},
		"profile incomplete":  {"sso_session": "missing", "sso_account_id": "111111111111", "sso_role_name": "ReadOnly"},
		"profile incomplete2": {"sso_account_id": "111111111111", "sso_role_name": "ReadOnly"},
		"services unrelated":  {"sso_start_url": "https://sample.invalid/start", "sso_region": "us-east-1", "sso_account_id": "111111111111", "sso_role_name": "ReadOnly"},
	}
	original, _ := json.Marshal(sections)
	tuple, _ := json.Marshal([4]string{"https://sample.invalid/start", "us-east-1", "111111111111", "ReadOnly"})
	hash := sha256.Sum256(tuple)
	want := []domain.Warning{{Code: "duplicate_profiles", Profiles: []string{"alias", "default", "z"}, IdentityKey: hex.EncodeToString(hash[:])}}
	for i := 0; i < 10; i++ {
		if got := DuplicateProfiles(sections); !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
	after, _ := json.Marshal(sections)
	if string(original) != string(after) {
		t.Fatal("inspection mutated config")
	}
	for _, edit := range []struct{ key, value string }{{"sso_start_url", "https://other.invalid/start"}, {"sso_region", "eu-west-1"}, {"sso_account_id", "222222222222"}, {"sso_role_name", "Admin"}} {
		t.Run(edit.key, func(t *testing.T) {
			a := map[string]string{"sso_start_url": "https://sample.invalid/start", "sso_region": "us-east-1", "sso_account_id": "111111111111", "sso_role_name": "ReadOnly"}
			b := map[string]string{}
			for k, v := range a {
				b[k] = v
			}
			b[edit.key] = edit.value
			if len(DuplicateProfiles(map[string]map[string]string{"default": a, "profile alias": b})) != 0 {
				t.Fatal("distinct identities collapsed")
			}
		})
	}
	if got := DuplicateProfiles(nil); got == nil || len(got) != 0 {
		t.Fatal("empty contract", got)
	}
}

func TestDuplicateProfilesSessionLabelsDoNotChangeIdentityAndWarningsSorted(t *testing.T) {
	sections := map[string]map[string]string{
		"sso-session a": {"sso_start_url": "https://sample.invalid/start", "sso_region": "us-east-1"},
		"sso-session b": {"sso_start_url": "https://sample.invalid/start/", "sso_region": "us-east-1"},
	}
	for _, role := range []string{"ReadOnly", "PowerUser"} {
		for _, name := range []string{"a", "b"} {
			sections["profile "+role+"-"+name] = map[string]string{"sso_session": name, "sso_account_id": "111111111111", "sso_role_name": role}
		}
	}
	warnings := DuplicateProfiles(sections)
	if len(warnings) != 2 || warnings[0].IdentityKey >= warnings[1].IdentityKey {
		t.Fatalf("warnings not sorted distinct groups: %+v", warnings)
	}
	for _, w := range warnings {
		if len(w.Profiles) != 2 || w.Profiles[0] >= w.Profiles[1] {
			t.Fatalf("session aliases not grouped/sorted: %+v", w)
		}
	}
	for i := 0; i < 10; i++ {
		if !reflect.DeepEqual(warnings, DuplicateProfiles(sections)) {
			t.Fatal("unstable ordering")
		}
	}
}
