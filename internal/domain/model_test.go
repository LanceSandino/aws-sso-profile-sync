package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestIdentityAndTypedErrors(t *testing.T) {
	s := Session{Name: "sample", StartURL: "https://sample.invalid/start/", Region: "us-east-1"}
	p := Profile{Session: s, Assignment: Assignment{AccountID: "111111111111", RoleName: "ReadOnly"}}
	if p.Identity() != "https://sample.invalid/start|us-east-1|111111111111|ReadOnly" {
		t.Fatal(p.Identity())
	}
	for _, c := range []struct {
		e    error
		code string
	}{{Fail("conflict", "safe"), "conflict"}, {fmt.Errorf("opaque"), "failed"}, {context.Canceled, "canceled"}, {context.DeadlineExceeded, "timed_out"}} {
		if ErrorCode(c.e) != c.code || c.e.Error() == "" {
			t.Fatal(c)
		}
	}
}

func TestWarningJSONNonsecretAdditiveContract(t *testing.T) {
	warning := Warning{Code: "duplicate_profiles", Profiles: []string{"alias", "default"}, IdentityKey: "stable-hash"}
	b, err := json.Marshal(warning)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 || decoded["code"] != warning.Code || decoded["identity_key"] != warning.IdentityKey {
		t.Fatalf("unexpected optional fields: %s", b)
	}
	setting := Warning{Code: "setting_preserved", Profiles: []string{"dev"}, Field: "region", Existing: "us-east-1", Requested: "eu-west-1"}
	b, err = json.Marshal(setting)
	if err != nil {
		t.Fatal(err)
	}
	// Unmarshal into a fresh map so absent optional fields cannot survive reuse.
	decoded = map[string]any{}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 5 || decoded["field"] != "region" || decoded["existing"] != "us-east-1" || decoded["requested"] != "eu-west-1" {
		t.Fatalf("setting warning contract: %s", b)
	}
}
