package configstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

func mutableEdit(t *testing.T) (Store, Snapshot, map[string]map[string]string, map[string]domain.Profile) {
	t.Helper()
	s, b, up, owned := fixture(t)
	if e := s.Apply(context.Background(), b, up, owned); e != nil {
		t.Fatal(e)
	}
	b, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	data := strings.ReplaceAll(strings.ReplaceAll(string(b.Data), "region = us-west-2", "region = eu-west-1"), "output = json", "output = text")
	if e := os.WriteFile(s.Path, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	stamp := time.Unix(1600000000, 123456789)
	if e := os.Chtimes(s.Path, stamp, stamp); e != nil {
		t.Fatal(e)
	}
	b, e = s.Read()
	if e != nil {
		t.Fatal(e)
	}
	p := owned["dev"]
	p.Region = "eu-west-1"
	p.Output = "text"
	owned["dev"] = p
	return s, b, map[string]map[string]string{"profile dev": b.Sections["profile dev"]}, owned
}

func TestMutableSettingsMetadataReconciliationPreservesConfigBytesAndMtime(t *testing.T) {
	s, b, up, owned := mutableEdit(t)
	before, e := os.Stat(s.Path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Apply(context.Background(), b, up, owned); e != nil {
		t.Fatal(e)
	}
	after, _ := os.Stat(s.Path)
	got, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got.Data, b.Data) || !before.ModTime().Equal(after.ModTime()) || !reflect.DeepEqual(got.Owned, owned) {
		t.Fatalf("metadata-only commit rewrote config or lost ownership: %+v", got)
	}
	_, manifest, intent, _, _ := s.paths()
	st, e := readState(manifest, b.Path)
	if e != nil || !reflect.DeepEqual(st.Owned, owned) {
		t.Fatalf("durable manifest stale %v %+v", e, st)
	}
	if _, e = os.Stat(intent); !os.IsNotExist(e) {
		t.Fatal("intent not cleaned", e)
	}
	if e = s.Apply(context.Background(), got, up, owned); e != nil {
		t.Fatal(e)
	}
	again, _ := os.Stat(s.Path)
	if !after.ModTime().Equal(again.ModTime()) {
		t.Fatal("repeat no-op rewrote config")
	}
}

func TestMutableSettingsMetadataReconciliationRecoveryAndConcurrentGuard(t *testing.T) {
	t.Run("manifest failure recover", func(t *testing.T) {
		s, b, up, owned := mutableEdit(t)
		info, _ := os.Stat(s.Path)
		s.Fault = func(stage string) error {
			if stage == "manifest" {
				return errors.New("synthetic manifest failure")
			}
			return nil
		}
		if e := s.Apply(context.Background(), b, up, owned); domain.ErrorCode(e) != "failed" {
			t.Fatal("false success", e)
		}
		after, _ := os.Stat(s.Path)
		if !info.ModTime().Equal(after.ModTime()) {
			t.Fatal("recovery path rewrote config")
		}
		recovered, e := s.Read()
		if e != nil || !reflect.DeepEqual(recovered.Owned, owned) {
			t.Fatal("intent recovery lost settings", e, recovered)
		}
		s.Fault = nil
		if e = s.Apply(context.Background(), recovered, up, owned); e != nil {
			t.Fatal(e)
		}
		after, _ = os.Stat(s.Path)
		if !info.ModTime().Equal(after.ModTime()) {
			t.Fatal("manifest reconciliation rewrote config")
		}
	})
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "after plan", true: "during commit"}[late], func(t *testing.T) {
			s, b, up, owned := mutableEdit(t)
			external := append(bytes.Clone(b.Data), []byte("# concurrent external edit\n")...)
			if late {
				s.Fault = func(stage string) error {
					if stage == "rename" {
						return os.WriteFile(s.Path, external, 0600)
					}
					return nil
				}
			} else {
				if e := os.WriteFile(s.Path, external, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := s.Apply(context.Background(), b, up, owned); domain.ErrorCode(e) != "conflict" {
				t.Fatal("concurrent guard missing", e)
			}
			data, e := os.ReadFile(s.Path)
			if e != nil || !bytes.Equal(data, external) {
				t.Fatal("external edit overwritten", e)
			}
		})
	}
	t.Run("cancellation at commit", func(t *testing.T) {
		s, b, up, owned := mutableEdit(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s.Fault = func(stage string) error {
			if stage == "rename" {
				cancel()
				return ctx.Err()
			}
			return nil
		}
		if e := s.Apply(ctx, b, up, owned); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
		got, e := os.ReadFile(s.Path)
		if e != nil || !bytes.Equal(got, b.Data) {
			t.Fatal("cancellation changed config", e)
		}
	})
}
