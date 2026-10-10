// Package auth implements explicit device login and a private, tool-owned session cache.
// Explicit paths, ownership metadata and typed errors define the storage boundary.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

// Token is deliberately stored separately from AWS CLI cache files. CLI interoperability requires manual AWS acceptance.
type Token struct {
	AccessToken           string         `json:"accessToken"`
	RefreshToken          string         `json:"refreshToken,omitempty"`
	ClientID              string         `json:"clientId"`
	ClientSecret          string         `json:"clientSecret"`
	ExpiresAt             time.Time      `json:"expiresAt"`
	RegistrationExpiresAt time.Time      `json:"registrationExpiresAt"`
	Session               domain.Session `json:"session"`
	Endpoint              string         `json:"endpoint"`
}

type Store struct {
	Root     string
	Session  domain.Session
	Endpoint string
}

func (s Store) Path() string {
	b, _ := json.Marshal(struct {
		Session  domain.Session
		Endpoint string
	}{s.Session.Normalized(), s.Endpoint})
	h := sha256.Sum256(b)
	return filepath.Join(s.Root, hex.EncodeToString(h[:])+".json")
}
func invalidCache() error {
	return domain.Fail("auth_invalid", "named-session cache is invalid or insecure; use an isolated secure token directory")
}
func required() error {
	return domain.Fail("login_required", "run explicit login for this named SSO session")
}

// securePath checks every existing component, refusing symlinks and non-directories.
func securePath(path string) error {
	if !filepath.IsAbs(path) {
		return invalidCache()
	}
	clean := filepath.Clean(path)
	for p := clean; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				// macOS exposes system temporary roots through /var and /tmp aliases.
				target, err := filepath.EvalSymlinks(p)
				if err != nil || !((p == "/var" && target == "/private/var") || (p == "/tmp" && target == "/private/tmp")) {
					return invalidCache()
				}
				info, e = os.Stat(p)
				if e != nil {
					return invalidCache()
				}
			}
			if p != clean && !info.IsDir() {
				return invalidCache()
			}
		} else if !os.IsNotExist(e) {
			return invalidCache()
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func (s Store) bound(t Token) bool {
	return t.Session.Normalized() == s.Session.Normalized() && t.Endpoint == s.Endpoint
}
func (s Store) Read() (Token, error) {
	if e := securePath(s.Root); e != nil {
		return Token{}, e
	}
	if e := securePath(s.Path()); e != nil {
		return Token{}, e
	}
	dir, e := os.Stat(s.Root)
	if os.IsNotExist(e) {
		return Token{}, required()
	}
	if e != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return Token{}, invalidCache()
	}
	file, e := os.Open(s.Path())
	if os.IsNotExist(e) {
		return Token{}, required()
	}
	if e != nil {
		return Token{}, invalidCache()
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return Token{}, invalidCache()
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var token Token
	if e = decoder.Decode(&token); e != nil {
		return Token{}, invalidCache()
	}
	var extra any
	if e = decoder.Decode(&extra); e != io.EOF {
		return Token{}, invalidCache()
	}
	if !s.bound(token) || token.AccessToken == "" || token.ExpiresAt.IsZero() {
		return Token{}, invalidCache()
	}
	return token, nil
}
func (s Store) Save(token Token) error {
	if !s.bound(token) || token.AccessToken == "" || token.ExpiresAt.IsZero() {
		return invalidCache()
	}
	if e := securePath(s.Root); e != nil {
		return e
	}
	if e := securePath(s.Path()); e != nil {
		return e
	}
	if e := os.MkdirAll(s.Root, 0700); e != nil {
		return domain.Fail("failed", "cannot create private token directory")
	}
	dir, e := os.Stat(s.Root)
	if e != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return invalidCache()
	}
	if info, e := os.Lstat(s.Path()); e == nil && !info.Mode().IsRegular() {
		return invalidCache()
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return invalidCache()
	}
	data, e := json.Marshal(token)
	if e != nil {
		return invalidCache()
	}
	tmp, e := os.CreateTemp(s.Root, ".token-*")
	if e != nil {
		return domain.Fail("failed", "cannot create secure token temporary file")
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(data); e == nil {
		e = tmp.Sync()
	}
	closeErr := tmp.Close()
	if e != nil || closeErr != nil {
		return domain.Fail("failed", "cannot persist token cache")
	}
	if e = securePath(s.Path()); e != nil {
		return e
	}
	if e = os.Rename(name, s.Path()); e != nil {
		return domain.Fail("failed", "cannot replace token cache")
	}
	dirFile, e := os.Open(s.Root)
	if e != nil {
		return domain.Fail("failed", "cannot verify token directory")
	}
	defer dirFile.Close()
	if e = dirFile.Sync(); e != nil {
		return domain.Fail("failed", "cannot sync token directory")
	}
	return nil
}
