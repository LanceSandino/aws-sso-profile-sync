// Config storage uses a read-only snapshot and a recoverable two-file commit.
// Explicit paths, ownership metadata and typed errors define the storage boundary.
package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
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
