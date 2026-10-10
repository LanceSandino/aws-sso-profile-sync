// Duplicate inspection reports complete SSO identities without changing aliases.
// Legacy profiles and named sessions share an unambiguous stable identity hash.
package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
)

// DuplicateProfiles reports aliases for the same tenant, SSO region, account and role.
// Profile region, output, session label and ownership do not distinguish identity.
func DuplicateProfiles(sections map[string]map[string]string) []domain.Warning {
	groups := map[string][]string{}
	for section, kv := range sections {
		name := strings.TrimPrefix(section, "profile ")
		if section != "default" && (!strings.HasPrefix(section, "profile ") || name == "") {
			continue
		}
		identity := kv
		if session := kv["sso_session"]; session != "" {
			identity = sections["sso-session "+session]
		}
		tuple := [4]string{strings.TrimRight(identity["sso_start_url"], "/"), identity["sso_region"], kv["sso_account_id"], kv["sso_role_name"]}
		complete := true
		for _, v := range tuple {
			if v == "" {
				complete = false
			}
		}
		if !complete {
			continue
		}
		encoded, _ := json.Marshal(tuple)
		sum := sha256.Sum256(encoded)
		key := hex.EncodeToString(sum[:])
		groups[key] = append(groups[key], name)
	}
	warnings := []domain.Warning{}
	for key, names := range groups {
		if len(names) > 1 {
			sort.Strings(names)
			warnings = append(warnings, domain.Warning{Code: "duplicate_profiles", Profiles: names, IdentityKey: key})
		}
	}
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].IdentityKey < warnings[j].IdentityKey })
	return warnings
}
