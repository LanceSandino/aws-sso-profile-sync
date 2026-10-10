package domain

import (
	"context"
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
