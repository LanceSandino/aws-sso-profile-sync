// Package settings loads optional, nonsecret named CLI contexts.
// Explicit read-only files supply defaults; authentication and command actions stay elsewhere.
package settings

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

// Context contains only optional command defaults. Pointers preserve explicit false and empty prefixes.
type Context struct {
	StartURL   *string   `json:"sso_start_url,omitempty"`
	Session    *string   `json:"sso_session_name,omitempty"`
	SSORegion  *string   `json:"sso_region,omitempty"`
	Region     *string   `json:"region,omitempty"`
	Roles      *[]string `json:"roles,omitempty"`
	Prefix     *string   `json:"prefix,omitempty"`
	AutoPrefix *bool     `json:"auto_prefix,omitempty"`
	Output     *string   `json:"output,omitempty"`
	ConfigFile *string   `json:"config_file,omitempty"`
	StateDir   *string   `json:"state_dir,omitempty"`
}
type document struct {
	SchemaVersion  int                `json:"schema_version"`
	DefaultContext *string            `json:"default_context,omitempty"`
	Contexts       map[string]Context `json:"contexts"`
}

func invalid(reason string) error { return domain.Fail("config_invalid", "settings: "+reason) }

// Exact schema keys avoid encoding/json's case-insensitive field aliases.
func allowedKey(depth int, name string) bool {
	switch depth {
	case 0:
		return name == "schema_version" || name == "default_context" || name == "contexts"
	case 2:
		switch name {
		case "sso_start_url", "sso_session_name", "sso_region", "region", "roles", "prefix", "auto_prefix", "output", "config_file", "state_dir":
			return true
		default:
			return false
		}
	}
	return true
}

// unique rejects duplicate keys, nulls and excessive nesting before typed schema decoding.
func unique(d *json.Decoder, depth int) error {
	if depth > 32 {
		return invalid("invalid JSON structure")
	}
	token, err := d.Token()
	if err != nil || token == nil {
		return invalid("invalid JSON structure")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return invalid("invalid JSON structure")
			}
			name, ok := key.(string)
			if !ok || seen[name] || !allowedKey(depth, name) {
				return invalid("duplicate or invalid JSON key")
			}
			seen[name] = true
			if err := unique(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := unique(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return invalid("invalid JSON structure")
	}
	if _, err := d.Token(); err != nil {
		return invalid("invalid JSON structure")
	}
	return nil
}
func plain(value string) bool {
	return !strings.ContainsAny(value, "[]") && strings.IndexFunc(value, unicode.IsControl) < 0
}

var region = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]+$`)

func validate(c Context) bool {
	for _, value := range []*string{c.StartURL, c.Session, c.SSORegion, c.Region, c.Output} {
		if value != nil && (strings.TrimSpace(*value) == "" || !plain(*value)) {
			return false
		}
	}
	for _, value := range []*string{c.ConfigFile, c.StateDir} {
		if value != nil && (strings.TrimSpace(*value) == "" || strings.IndexFunc(*value, unicode.IsControl) >= 0) {
			return false
		}
	}
	if c.Prefix != nil && strings.IndexFunc(*c.Prefix, unicode.IsControl) >= 0 {
		return false
	}
	if c.StartURL != nil {
		u, err := url.Parse(*c.StartURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
	}
	for _, value := range []*string{c.Region, c.SSORegion} {
		if value != nil && !region.MatchString(*value) {
			return false
		}
	}
	if c.Output != nil && *c.Output != "json" && *c.Output != "text" && *c.Output != "table" && *c.Output != "yaml" && *c.Output != "yaml-stream" {
		return false
	}
	if c.Roles != nil {
		for _, role := range *c.Roles {
			if strings.TrimSpace(role) == "" || !plain(role) || strings.ContainsAny(role, ";") {
				return false
			}
		}
	}
	return true
}

// Load reads one explicit file and chooses a requested, declared-default or sole context.
// It does not discover files, create directories, persist defaults or access authentication.
func Load(path, name string) (Context, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return Context{}, invalid("explicit file path required")
	}
	data, err := read(absolute)
	if err != nil {
		return Context{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := unique(decoder, 0); err != nil {
		return Context{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Context{}, invalid("exactly one JSON document is required")
	}
	var file document
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil || file.SchemaVersion != 1 || len(file.Contexts) == 0 {
		return Context{}, invalid("schema_version 1 and named contexts are required")
	}
	for context, c := range file.Contexts {
		if strings.TrimSpace(context) == "" || !plain(context) || !validate(c) {
			return Context{}, invalid("invalid context fields")
		}
	}
	if file.DefaultContext != nil {
		if _, ok := file.Contexts[*file.DefaultContext]; !ok {
			return Context{}, invalid("default_context must name an existing context")
		}
		if name == "" {
			name = *file.DefaultContext
		}
	}
	if name == "" {
		if len(file.Contexts) != 1 {
			return Context{}, invalid("multiple contexts require --context or default_context")
		}
		for context := range file.Contexts {
			name = context
		}
	}
	result, ok := file.Contexts[name]
	if !ok {
		return Context{}, invalid("requested context does not exist")
	}
	for _, value := range []*string{result.ConfigFile, result.StateDir} {
		if value != nil && !filepath.IsAbs(*value) {
			resolved := filepath.Join(filepath.Dir(absolute), *value)
			*value = resolved
		}
	}
	return result, nil
}
