// Package planner computes deterministic, ownership-aware configuration changes.
// Pure assignment inputs and snapshots produce sorted changes without side effects.
package planner

import (
	"crypto/sha256"
	"fmt"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/configstore"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"regexp"
	"sort"
	"strings"
)

type Options struct {
	Session                 domain.Session
	Region, Output, Prefix  string
	AutoPrefix              bool
	Roles                   []string
	OverrideProfileSettings bool
}
type Plan struct {
	Results     []domain.Result              `json:"results"`
	Sections    map[string]map[string]string `json:"sections"`
	Owned       map[string]domain.Profile    `json:"-"`
	Explanation string                       `json:"explanation,omitempty"`
	Warnings    []domain.Warning             `json:"warnings"`
}

var unsafe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

func SafeName(s string) string {
	s = unsafe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-.")
	if len(s) > 48 {
		s = s[:48]
	}
	if s == "" {
		s = "account"
	}
	return s
}
func Prefix(role string) string {
	s := strings.TrimSuffix(strings.TrimPrefix(role, "AWS"), "Access")
	if s != "" {
		return s + "_"
	}
	return ""
}
func Name(a domain.Assignment, o Options) string {
	prefix := o.Prefix
	if prefix == "" && o.AutoPrefix {
		prefix = Prefix(a.RoleName)
	}
	p := domain.Profile{Assignment: a, Session: o.Session}
	h := sha256.Sum256([]byte(p.Identity()))
	return fmt.Sprintf("%s_%s_%x", SafeName(prefix+a.AccountName), a.AccountID, h[:5])
}
func Keys(p domain.Profile) map[string]string {
	return map[string]string{"sso_session": p.Session.Name, "sso_account_id": p.Assignment.AccountID, "sso_role_name": p.Assignment.RoleName, "region": p.Region, "output": p.Output}
}
func Build(s configstore.Snapshot, assignments []domain.Assignment, o Options) (Plan, error) {
	p := Plan{Results: []domain.Result{}, Sections: map[string]map[string]string{}, Owned: map[string]domain.Profile{}, Warnings: []domain.Warning{}}
	o.Session = o.Session.Normalized()
	if o.Session.Name == "" || o.Session.Region == "" || o.Region == "" || o.Output == "" {
		return p, domain.Fail("config_invalid", "session, region and output must be explicit")
	}
	for _, v := range []string{o.Session.Name, o.Session.Region, o.Region, o.Output, o.Session.StartURL} {
		if strings.ContainsAny(v, "\r\n\x1b[]") {
			return p, domain.Fail("config_invalid", "unsafe session/config value")
		}
	}
	ownedIDs := map[string]bool{}
	for n, v := range s.Owned {
		id := v.Identity() + "|" + v.Session.Name
		if ownedIDs[id] {
			return p, domain.Fail("conflict", "duplicate managed ownership identity")
		}
		ownedIDs[id] = true
		p.Owned[n] = v
	}
	available := map[string]bool{}
	for _, a := range assignments {
		if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(a.AccountID) || a.RoleName == "" || strings.ContainsAny(a.RoleName, "\r\n\x1b[];") {
			return p, domain.Fail("config_invalid", "invalid discovered account or role")
		}
		available[a.RoleName] = true
	}
	if len(o.Roles) == 0 {
		if len(available) > 1 {
			names := []string{}
			for n := range available {
				names = append(names, n)
			}
			sort.Strings(names)
			return p, domain.Fail("role_selection_required", "select --role from: "+strings.Join(names, ", "))
		}
		for n := range available {
			o.Roles = []string{n}
			p.Explanation = "Auto-selected the only available role: " + SafeName(n)
		}
	}
	selected := map[string]bool{}
	for _, r := range o.Roles {
		if len(available) == 0 {
			continue
		}
		if !available[r] {
			return p, domain.Fail("role_selection_required", "selected role is not assigned: "+SafeName(r))
		}
		selected[r] = true
	}
	sessionName := "sso-session " + o.Session.Name
	session := s.Sections[sessionName]
	if session != nil && (strings.TrimRight(session["sso_start_url"], "/") != o.Session.StartURL || session["sso_region"] != o.Session.Region) {
		return p, domain.Fail("conflict", "named SSO session belongs to a different URL or region")
	}
	if session == nil && len(assignments) > 0 {
		p.Sections[sessionName] = map[string]string{"sso_start_url": o.Session.StartURL, "sso_region": o.Session.Region, "sso_registration_scopes": "sso:account:access"}
	}
	seen := map[string]bool{}
	seenName := map[string]string{}
	allIDs := map[string]bool{}
	for _, a := range assignments {
		profile := domain.Profile{Session: o.Session, Assignment: a, Region: o.Region, Output: o.Output}
		id := profile.Identity()
		allIDs[id] = true
		if !selected[a.RoleName] || seen[id] {
			continue
		}
		seen[id] = true
		profile.Name = Name(a, o)
		for name, old := range s.Owned {
			if old.Identity() == id && old.Session.Name == o.Session.Name {
				profile.Name = name
				break
			}
		}
		if prev, ok := seenName[profile.Name]; ok && prev != id {
			return p, domain.Fail("conflict", "profile naming collision")
		}
		seenName[profile.Name] = id
		r := domain.Result{Profile: profile, Status: "created", Reason: "assigned account and role"}
		existing := s.Sections["profile "+profile.Name]
		owned, isOwned := s.Owned[profile.Name]
		if existing != nil {
			if !isOwned || owned.Identity() != id || owned.Session.Name != profile.Session.Name {
				r.Status = "conflict"
				r.Reason = "existing profile is not owned by this assignment"
			} else {
				r.Status = "unchanged"
				r.Reason = "managed identity and configuration match"
				for k, v := range Keys(owned) {
					if k != "region" && k != "output" && existing[k] != v {
						r.Status = "conflict"
						r.Reason = "managed profile was edited externally"
					}
				}
				if r.Status != "conflict" {
					if !o.OverrideProfileSettings {
						for _, field := range []string{"output", "region"} {
							requested := profile.Region
							if field == "output" {
								requested = profile.Output
							}
							if actual := existing[field]; actual != "" {
								if actual != requested {
									p.Warnings = append(p.Warnings, domain.Warning{Code: "setting_preserved", Profiles: []string{profile.Name}, Field: field, Existing: actual, Requested: requested})
								}
								if field == "region" {
									profile.Region = actual
								} else {
									profile.Output = actual
								}
							}
						}
					}
					r.Profile = profile
					for k, v := range Keys(profile) {
						if existing[k] != v {
							r.Status = "updated"
							r.Reason = "managed profile settings changed"
						}
					}
				}
			}
		} else if isOwned {
			r.Status = "conflict"
			r.Reason = "managed profile was removed externally"
		}
		p.Results = append(p.Results, r)
		if r.Status == "created" || r.Status == "updated" || (r.Status == "unchanged" && (owned.Region != profile.Region || owned.Output != profile.Output)) {
			p.Sections["profile "+profile.Name] = Keys(profile)
			p.Owned[profile.Name] = profile
		}
	}
	for _, old := range s.Owned {
		if old.Session.Normalized() == o.Session && !allIDs[old.Identity()] {
			p.Results = append(p.Results, domain.Result{Profile: old, Status: "stale", Reason: "assignment no longer visible; profile retained"})
		}
	}
	// Inspect the complete proposed configuration; unowned aliases remain intact.
	projected := map[string]map[string]string{}
	for section, keys := range s.Sections {
		projected[section] = map[string]string{}
		for key, value := range keys {
			projected[section][key] = value
		}
	}
	for section, keys := range p.Sections {
		if projected[section] == nil {
			projected[section] = map[string]string{}
		}
		for key, value := range keys {
			projected[section][key] = value
		}
	}
	p.Warnings = append(p.Warnings, configstore.DuplicateProfiles(projected)...)
	sort.Slice(p.Warnings, func(i, j int) bool {
		a, b := p.Warnings[i], p.Warnings[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.IdentityKey != b.IdentityKey {
			return a.IdentityKey < b.IdentityKey
		}
		if a.Profiles[0] != b.Profiles[0] {
			return a.Profiles[0] < b.Profiles[0]
		}
		return a.Field < b.Field
	})
	sort.Slice(p.Results, func(i, j int) bool { return p.Results[i].Profile.Name < p.Results[j].Profile.Name })
	return p, nil
}
func (p Plan) HasConflicts() bool {
	for _, r := range p.Results {
		if r.Status == "conflict" {
			return true
		}
	}
	return false
}
