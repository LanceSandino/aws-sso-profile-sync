// Optional settings supply defaults only when requested; explicit flags always win.
// This merge does not perform authentication, network calls or filesystem writes.
package cli

import (
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/settings"
	"path/filepath"
)

func applySettings(o *Options, explicit map[string]bool, home string) error {
	if !explicit["settings-file"] && !explicit["context"] {
		return nil
	}
	if explicit["settings-file"] && o.SettingsFile == "" || explicit["context"] && o.Context == "" {
		return domain.Fail("config_invalid", "settings file and context flags require nonempty values")
	}
	path := o.SettingsFile
	if !explicit["settings-file"] {
		path = filepath.Join(home, ".aws-sso-profile-sync", "settings.json")
	}
	c, err := settings.Load(path, o.Context)
	if err != nil {
		return err
	}
	fields := []struct {
		flag   string
		target *string
		value  *string
	}{
		{"sso-start-url", &o.StartURL, c.StartURL}, {"sso-session-name", &o.Session, c.Session},
		{"sso-region", &o.SSORegion, c.SSORegion}, {"region", &o.Region, c.Region},
		{"prefix", &o.Prefix, c.Prefix}, {"output", &o.Output, c.Output},
		{"config-file", &o.Config, c.ConfigFile}, {"state-dir", &o.State, c.StateDir},
	}
	for _, field := range fields {
		if field.value != nil && !explicit[field.flag] {
			*field.target = *field.value
			if field.flag == "region" {
				o.RegionFromSettings = true
			}
		}
	}
	if c.Session != nil {
		o.SessionExplicit = true
	}
	if c.Roles != nil && !explicit["role"] {
		o.Roles = append(stringsFlag{}, (*c.Roles)...)
	}
	if c.AutoPrefix != nil && !explicit["auto-prefix"] {
		o.AutoPrefix = *c.AutoPrefix
	}
	return nil
}
