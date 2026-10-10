//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

type envelope struct {
	SchemaVersion int                 `json:"schema_version"`
	Command       string              `json:"command"`
	Results       []domain.Result     `json:"results"`
	Assignments   []domain.Assignment `json:"assignments"`
	Counts        map[string]int      `json:"counts"`
	Status        string              `json:"status"`
	Error         *domain.Error       `json:"error"`
}
type client struct{ binary, root, endpoint, session, region string }
type execution struct {
	data           envelope
	stdout, stderr []byte
	err            error
}

func buildCLI(t *testing.T) string {
	t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "aws-sso-profile-sync")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/aws-sso-profile-sync")
	cmd.Dir = repo
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GOTOOLCHAIN=local"}
	for _, k := range []string{"GOCACHE", "GOMODCACHE", "GOPATH"} {
		if v := os.Getenv(k); v != "" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build real CLI: %v: %s", err, output)
	}
	return binary
}
func newClient(t *testing.T, binary, endpoint string) client {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return client{binary: binary, root: root, endpoint: endpoint, session: "sample", region: "us-east-1"}
}
func (c client) config() string { return filepath.Join(c.root, ".aws", "config") }
func (c client) state() string  { return filepath.Join(c.root, ".aws-sso-profile-sync") }
func (c client) env() []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + c.root, "AWS_CONFIG_FILE=" + c.config(), "AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(c.root, ".aws", "credentials"), "AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test", "AWS_EC2_METADATA_DISABLED=true", "NO_COLOR=1"}
	// macOS t.TempDir follows TMPDIR. Preserve only this path hint so the
	// subprocess recognizes the same disposable system temp root.
	if value := os.Getenv("TMPDIR"); value != "" {
		env = append(env, "TMPDIR="+value)
	}
	return env
}
func (c client) args(command string, extra ...string) []string {
	args := []string{command, "--format", "json", "--sso-start-url", "https://sample.invalid/start", "--sso-session-name", c.session, "--sso-region", c.region, "--config-file", c.config(), "--state-dir", c.state(), "--test-endpoint", c.endpoint, "--test-root", c.root, "--open=false"}
	return append(args, extra...)
}
func (c client) execute(t *testing.T, command string, env []string, extra ...string) execution {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.binary, c.args(command, extra...)...)
	cmd.Env = env
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("%s subprocess deadline: %v", command, ctx.Err())
	}
	var data envelope
	expectedCommand := command
	for _, arg := range extra {
		if command == "sync" && arg == "--dry-run" {
			expectedCommand = "plan"
		}
	}
	if json.Unmarshal(out.Bytes(), &data) != nil || data.SchemaVersion != 1 || data.Command != expectedCommand {
		t.Fatalf("%s stdout is not the versioned JSON envelope", command)
	}
	return execution{data: data, stdout: out.Bytes(), stderr: stderr.Bytes(), err: err}
}
func (c client) run(t *testing.T, command string, extra ...string) execution {
	return c.execute(t, command, c.env(), extra...)
}
func mustSuccess(t *testing.T, r execution) {
	t.Helper()
	if r.err != nil || r.data.Error != nil {
		code := "unknown"
		if r.data.Error != nil {
			code = r.data.Error.Code
		}
		t.Fatalf("CLI failed: exit=%v code=%s", r.err, code)
	}
}

var deviceURL = regexp.MustCompile(`https?://[^\s]+/device\?[^\s]+`)

func (c client) login(t *testing.T) execution {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.binary, c.args("login")...)
	cmd.Env = c.env()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cancel()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	scan := bufio.NewScanner(pipe)
	verified := false
	for scan.Scan() {
		line := scan.Text()
		stderr.WriteString(line + "\n")
		if match := deviceURL.FindString(line); match != "" {
			advertised, err := url.Parse(strings.TrimRight(match, ".,)"))
			if err != nil {
				t.Fatal(err)
			}
			local, err := url.Parse(c.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			local.Path = advertised.Path
			local.RawQuery = advertised.RawQuery
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, local.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&http.Client{Timeout: 5 * time.Second, Transport: localOnlyTransport{c.endpoint}, CheckRedirect: func(*http.Request, []*http.Request) error { return os.ErrPermission }}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("local device authorization status=%d", response.StatusCode)
			}
			verified = true
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		t.Fatal("login timed out")
	}
	if scan.Err() != nil {
		t.Fatal(scan.Err())
	}
	var result envelope
	if json.Unmarshal(stdout.Bytes(), &result) != nil {
		t.Fatal("login stdout invalid JSON")
	}
	r := execution{data: result, stdout: stdout.Bytes(), stderr: stderr.Bytes(), err: err}
	mustSuccess(t, r)
	if !verified {
		t.Fatal("explicit login did not complete local /device flow")
	}
	return r
}

type snapshot map[string]fileSnapshot
type fileSnapshot struct {
	Content string
	Mode    os.FileMode
	ModTime time.Time
}

func snapshotRoot(t *testing.T, root string) snapshot {
	t.Helper()
	result := snapshot{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			relative, _ := filepath.Rel(root, path)
			result[relative] = fileSnapshot{string(content), info.Mode(), info.ModTime()}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func assertSecretFree(t *testing.T, r execution, root string) {
	t.Helper()
	outputs := string(r.stdout) + string(r.stderr)
	for _, bad := range []string{"\x1b[", "\"accessToken\"", "\"refreshToken\"", "\"clientSecret\"", "\"deviceCode\""} {
		if strings.Contains(outputs, bad) {
			t.Fatal("CLI output leaks ANSI/authentication fields")
		}
	}
	files, err := filepath.Glob(filepath.Join(root, ".aws-sso-profile-sync", "auth", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var token map[string]any
		if json.Unmarshal(b, &token) != nil {
			t.Fatal("cache invalid JSON")
		}
		for _, field := range []string{"accessToken", "refreshToken", "clientSecret"} {
			if secret, ok := token[field].(string); ok && secret != "" && strings.Contains(outputs, secret) {
				t.Fatalf("CLI output leaks %s value", field)
			}
		}
	}
}
