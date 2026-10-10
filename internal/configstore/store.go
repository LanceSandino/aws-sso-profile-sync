// Config storage uses a read-only snapshot and a recoverable two-file commit.
// Explicit paths, ownership metadata and typed errors define the storage boundary.
package configstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

type Snapshot struct {
	Path     string
	Data     []byte
	Hash     string
	Sections map[string]map[string]string
	Owned    map[string]domain.Profile
}
type Store struct {
	Path  string
	Fault func(stage string) error
}
type state struct {
	Version int                       `json:"version"`
	Path    string                    `json:"path"`
	Hash    string                    `json:"config_hash"`
	Before  string                    `json:"before_hash,omitempty"`
	Owned   map[string]domain.Profile `json:"owned"`
}

func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func (s Store) paths() (string, string, string, string, error) {
	p, e := filepath.Abs(s.Path)
	if e != nil || s.Path == "" {
		return "", "", "", "", domain.Fail("config_invalid", "explicit config path required")
	}
	return p, p + ".aws-sso-sync.json", p + ".aws-sso-sync.intent", p + ".aws-sso-sync.lock", nil
}

func checkPath(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if e == nil && info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			trusted := runtime.GOOS == "darwin" && err == nil && ((p == "/var" && target == "private/var") || (p == "/tmp" && target == "private/tmp") || (p == "/var" && target == "/private/var") || (p == "/tmp" && target == "/private/tmp"))
			if !trusted {
				return domain.Fail("config_invalid", "symlink component refused: "+p)
			}
		}
		if e == nil && p == path && !info.Mode().IsRegular() {
			return domain.Fail("config_invalid", "config/state must be a regular file")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func readFile(path string) ([]byte, error) {
	if e := checkPath(path); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	return b, e
}
func readState(path, config string) (*state, error) {
	b, e := readFile(path)
	if e != nil || b == nil {
		return nil, e
	}
	var st state
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, domain.Fail("config_invalid", "ownership state is writable by other users")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return nil, domain.Fail("config_invalid", "ownership state belongs to another user")
	}
	if e = json.Unmarshal(b, &st); e != nil || st.Version != 1 || st.Path != config || st.Owned == nil {
		return nil, domain.Fail("config_invalid", "invalid ownership state")
	}
	return &st, nil
}

// Read never creates locks, directories, state, or files. A completed intent supplies
// ownership in memory; only the next explicit Apply reconciles the durable manifest.
func (s Store) Read() (Snapshot, error) {
	p, m, j, _, e := s.paths()
	if e != nil {
		return Snapshot{}, domain.Fail("config_invalid", e.Error())
	}
	b, e := readFile(p)
	if e != nil {
		return Snapshot{}, domain.Fail("config_invalid", e.Error())
	}
	sections, e := Parse(b)
	if e != nil {
		return Snapshot{}, e
	}
	snap := Snapshot{Path: p, Data: b, Hash: digest(b), Sections: sections, Owned: map[string]domain.Profile{}}
	st, e := readState(m, p)
	if e != nil {
		return Snapshot{}, e
	}
	if st != nil {
		snap.Owned = st.Owned
	}
	intent, e := readState(j, p)
	if e != nil {
		return Snapshot{}, e
	}
	if intent != nil {
		switch snap.Hash {
		case intent.Hash:
			snap.Owned = intent.Owned
		case intent.Before:
		default:
			return Snapshot{}, domain.Fail("conflict", "interrupted transaction differs from both known config hashes; inspect config and intent")
		}
	}
	return snap, nil
}

func identityMatches(kv map[string]string, p domain.Profile) bool {
	return kv["sso_session"] == p.Session.Name && kv["sso_account_id"] == p.Assignment.AccountID && kv["sso_role_name"] == p.Assignment.RoleName
}
func authorize(before Snapshot, updates map[string]map[string]string, owned map[string]domain.Profile) error {
	for name, p := range before.Owned {
		next, ok := owned[name]
		if !ok || p.Identity() != next.Identity() || p.Session.Name != next.Session.Name {
			return domain.Fail("conflict", "owned profile identity cannot be removed or rebound: "+name)
		}
		if next.Region != p.Region || next.Output != p.Output {
			kv := updates["profile "+name]
			if kv["region"] != next.Region || kv["output"] != next.Output {
				return domain.Fail("conflict", "ownership metadata change lacks corresponding config update: "+name)
			}
		}
	}
	for section, kv := range updates {
		existing, exists := before.Sections[section]
		if strings.HasPrefix(section, "sso-session ") {
			for key := range kv {
				if key != "sso_start_url" && key != "sso_region" && key != "sso_registration_scopes" {
					return domain.Fail("conflict", "unknown session setting cannot be managed: "+key)
				}
			}
			if exists && (strings.TrimRight(existing["sso_start_url"], "/") != strings.TrimRight(kv["sso_start_url"], "/") || existing["sso_region"] != kv["sso_region"]) {
				return domain.Fail("conflict", "named SSO session is already bound: "+section)
			}
			continue
		}
		if !strings.HasPrefix(section, "profile ") {
			return domain.Fail("conflict", "only explicit managed profiles and SSO sessions may change")
		}
		name := strings.TrimPrefix(section, "profile ")
		for key := range kv {
			switch key {
			case "sso_session", "sso_account_id", "sso_role_name", "region", "output":
			default:
				return domain.Fail("conflict", "unknown profile setting cannot be managed: "+key)
			}
		}
		p, ok := owned[name]
		if !ok || p.Name != name || !identityMatches(kv, p) || kv["region"] != p.Region || kv["output"] != p.Output {
			return domain.Fail("conflict", "profile lacks matching ownership intent: "+name)
		}
		session := before.Sections["sso-session "+p.Session.Name]
		if desired, ok := updates["sso-session "+p.Session.Name]; ok {
			session = desired
		}
		if strings.TrimRight(session["sso_start_url"], "/") != p.Session.Normalized().StartURL || session["sso_region"] != p.Session.Region {
			return domain.Fail("conflict", "profile ownership does not match named session: "+name)
		}
		if exists {
			prior, ok := before.Owned[name]
			if !ok || prior.Identity() != p.Identity() || !identityMatches(existing, prior) || existing["region"] != prior.Region || existing["output"] != prior.Output {
				return domain.Fail("conflict", "existing profile is unowned or changed: "+name)
			}
		}
	}
	for name, p := range owned {
		if _, ok := before.Owned[name]; !ok {
			if !identityMatches(updates["profile "+name], p) {
				return domain.Fail("conflict", "ownership cannot be adopted without a managed profile transaction")
			}
		}
	}
	return nil
}

func (s Store) fail(stage string) error {
	if s.Fault != nil {
		return s.Fault(stage)
	}
	return nil
}
func writeState(path string, st state) error {
	b, e := json.MarshalIndent(st, "", "  ")
	if e != nil {
		return e
	}
	return atomic(path, append(b, '\n'), 0600, func(string) error { return nil })
}

// Apply requires the exact read-only snapshot and uses a durable intent before the
// config rename. Post-rename failures return uncertain status, never false success.
func (s Store) Apply(ctx context.Context, before Snapshot, updates map[string]map[string]string, owned map[string]domain.Profile) error {
	p, m, j, l, e := s.paths()
	if e != nil {
		return e
	}
	if before.Path != p {
		return domain.Fail("conflict", "snapshot path differs from target")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = checkPath(p); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	unlock, e := lock(ctx, l)
	if e != nil {
		return e
	}
	defer unlock()
	current, e := s.Read()
	if e != nil {
		return e
	}
	if current.Hash != before.Hash || !reflect.DeepEqual(current.Owned, before.Owned) {
		return domain.Fail("conflict", "config or ownership changed after plan")
	}
	if e = authorize(current, updates, owned); e != nil {
		return e
	}
	data, e := Preview(current, updates)
	if e != nil {
		return e
	}
	intent, e := readState(j, p)
	if e != nil {
		return e
	}
	if bytes.Equal(data, current.Data) && reflect.DeepEqual(owned, current.Owned) {
		if intent != nil {
			if current.Hash == intent.Hash {
				if e = writeState(m, *intent); e != nil {
					return e
				}
			}
			return os.Remove(j)
		}
		return nil
	}
	mode := os.FileMode(0600)
	if info, err := os.Stat(p); err == nil {
		mode = info.Mode().Perm()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
			return domain.Fail("config_invalid", "config owned by another user; refusing replacement")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	st := state{Version: 1, Path: p, Hash: digest(data), Before: current.Hash, Owned: owned}
	if e = writeState(j, st); e != nil {
		return e
	}
	// Last digest check immediately before replacement detects cooperating and
	// externally visible edits; external writers do not participate in our lock.
	fault := func(stage string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := s.fail(stage); e != nil {
			return e
		}
		if stage == "rename" {
			b, e := readFile(p)
			if e != nil {
				return e
			}
			if digest(b) != current.Hash {
				return domain.Fail("conflict", "config changed during apply")
			}
		}
		return nil
	}
	if e = atomic(p, data, mode, fault); e != nil {
		b, readErr := readFile(p)
		if readErr != nil || digest(b) == st.Hash {
			return domain.Fail("failed", "commit state uncertain; inspect config/intent before retry")
		}
		return e
	}
	if e = s.fail("readback"); e != nil {
		return domain.Fail("failed", "config committed but readback failed; ownership intent retained")
	}
	got, e := readFile(p)
	if e != nil || !bytes.Equal(got, data) {
		return domain.Fail("failed", "config committed but readback differs; ownership intent retained")
	}
	if e = s.fail("manifest"); e != nil {
		return domain.Fail("failed", "config committed; ownership intent retained for recovery")
	}
	if e = writeState(m, st); e != nil {
		return fmt.Errorf("config committed, ownership intent retained: %w", e)
	}
	if e = os.Remove(j); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}
