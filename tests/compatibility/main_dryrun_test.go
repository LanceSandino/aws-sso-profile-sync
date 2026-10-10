package compatibility

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/cli"
	"os"
	"path/filepath"
	"testing"
)

// The historical dry-run test now pins the intentional migration to strict no-login preview.
func TestDryRunNoToken(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "config")
	state := filepath.Join(root, "state")
	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), []string{"--dry-run", "--sso-start-url", "https://sample.invalid/start", "--config-file", config, "--state-dir", state, "--format", "json"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("missing auth succeeded")
	}
	var out cli.Envelope
	if e := json.Unmarshal(stdout.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	if out.Error == nil || out.Error.Code != "login_required" {
		t.Fatal(out)
	}
	for _, p := range []string{config, state} {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			t.Fatal("preview wrote", p, e)
		}
	}
}
