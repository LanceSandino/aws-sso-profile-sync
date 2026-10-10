// Package configstore preserves AWS shared config and commits guarded transactions.
// Read-only parsing and preview retain unrelated configuration bytes.
package configstore

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

func invalid(line int, reason string) error {
	return domain.Fail("config_invalid", fmt.Sprintf("line %d: %s", line, reason))
}

// Parse rejects ambiguous sections and keys instead of treating malformed files as empty.
// Indented AWS nested settings are accepted and retained as an opaque value.
func Parse(data []byte) (map[string]map[string]string, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, invalid(0, "NUL byte")
	}
	out := map[string]map[string]string{}
	section, last, nested := "", "", false
	for i, line := range strings.Split(string(data), "\n") {
		v := strings.TrimSpace(line)
		if v == "" || strings.HasPrefix(v, "#") || strings.HasPrefix(v, ";") {
			continue
		}
		if strings.HasPrefix(v, "[") {
			if !strings.HasSuffix(v, "]") || strings.Count(v, "[") != 1 || strings.Count(v, "]") != 1 {
				return nil, invalid(i+1, "malformed section")
			}
			section = strings.TrimSpace(v[1 : len(v)-1])
			if section == "" {
				return nil, invalid(i+1, "empty section")
			}
			if _, ok := out[section]; ok {
				return nil, invalid(i+1, "duplicate section")
			}
			out[section] = map[string]string{}
			last = ""
			nested = false
			continue
		}
		if section == "" {
			return nil, invalid(i+1, "setting outside section")
		}
		if nested && len(line) > 0 && unicode.IsSpace(rune(line[0])) {
			out[section][last] += "\n" + line
			continue
		}
		key, value, ok := strings.Cut(v, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || strings.ContainsAny(key, "[]\r\t ") {
			return nil, invalid(i+1, "malformed setting")
		}
		if _, exists := out[section][key]; exists {
			return nil, invalid(i+1, "duplicate setting")
		}
		value = strings.TrimSpace(value)
		// INI inline comments follow whitespace; embedded URL fragments remain intact.
		for j := 1; j < len(value); j++ {
			if (value[j] == '#' || value[j] == ';') && unicode.IsSpace(rune(value[j-1])) {
				value = strings.TrimSpace(value[:j])
				break
			}
		}
		out[section][key] = value
		last = key
		nested = value == ""
	}
	return out, nil
}

func safeAtom(s string) bool { return s != "" && !strings.ContainsAny(s, "\r\n\x00[]") }

// Preview returns exact proposed config bytes without filesystem access.
// Semantic no-ops retain original bytes, whitespace and line endings.
func Preview(before Snapshot, sections map[string]map[string]string) ([]byte, error) {
	data, e := render(before.Data, sections)
	if e != nil {
		return nil, e
	}
	parsed, e := Parse(data)
	if e != nil {
		return nil, e
	}
	for section, kv := range sections {
		for key, value := range kv {
			if parsed[section][key] != value {
				return nil, domain.Fail("config_invalid", "setting is interpreted differently by INI; remove inline-comment or nested-value ambiguity")
			}
		}
	}
	if reflect.DeepEqual(before.Sections, parsed) {
		return bytes.Clone(before.Data), nil
	}
	return data, nil
}

// render changes only requested keys. Every other byte (including comments) is retained.
func render(data []byte, updates map[string]map[string]string) ([]byte, error) {
	for section, kv := range updates {
		if !safeAtom(section) {
			return nil, domain.Fail("config_invalid", "invalid section name")
		}
		for k, v := range kv {
			if !safeAtom(k) || strings.ContainsAny(k, " \t=") || strings.ContainsAny(v, "\r\n\x00") {
				return nil, domain.Fail("config_invalid", "invalid setting")
			}
		}
	}
	lines := strings.SplitAfter(string(data), "\n")
	var out strings.Builder
	seen := map[string]bool{}
	written := map[string]bool{}
	section := ""
	nested := false
	newline := "\n"
	if bytes.Contains(data, []byte("\r\n")) {
		newline = "\r\n"
	}
	appendMissing := func() {
		if kv, ok := updates[section]; ok {
			keys := []string{}
			for k := range kv {
				if !written[k] {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
					out.WriteString(newline)
				}
				out.WriteString(k + " = " + kv[k] + newline)
			}
		}
	}
	for _, line := range lines {
		v := strings.TrimSpace(line)
		if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
			appendMissing()
			section = strings.TrimSpace(v[1 : len(v)-1])
			seen[section] = true
			written = map[string]bool{}
			nested = false
			out.WriteString(line)
			continue
		}
		if nested && len(line) > 0 && unicode.IsSpace(rune(line[0])) {
			out.WriteString(line)
			continue
		}
		k, prior, ok := strings.Cut(v, "=")
		k = strings.TrimSpace(k)
		if ok {
			nested = strings.TrimSpace(prior) == ""
		}
		if kv, present := updates[section]; present && ok {
			if value, target := kv[k]; target {
				written[k] = true
				out.WriteString(replaceValue(line, value))
				continue
			}
		}
		out.WriteString(line)
	}
	appendMissing()
	sections := []string{}
	for section := range updates {
		if !seen[section] {
			sections = append(sections, section)
		}
	}
	sort.Strings(sections)
	for _, section := range sections {
		if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteString(newline)
		}
		out.WriteString("[" + section + "]" + newline)
		keys := []string{}
		for k := range updates[section] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out.WriteString(k + " = " + updates[section][k] + newline)
		}
	}
	return []byte(out.String()), nil
}

func replaceValue(line, value string) string {
	pos := strings.IndexByte(line, '=') + 1
	end := len(line)
	for end > pos && (line[end-1] == '\n' || line[end-1] == '\r') {
		end--
	}
	start := pos
	for start < end && (line[start] == ' ' || line[start] == '\t') {
		start++
	}
	suffix := end
	for i := start + 1; i < end; i++ {
		if (line[i] == '#' || line[i] == ';') && unicode.IsSpace(rune(line[i-1])) {
			suffix = i
			for suffix > start && unicode.IsSpace(rune(line[suffix-1])) {
				suffix--
			}
			break
		}
	}
	return line[:start] + value + line[suffix:]
}
