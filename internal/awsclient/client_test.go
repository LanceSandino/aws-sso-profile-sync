package awsclient

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func isolated(t *testing.T) string {
	t.Helper()
	r := t.TempDir()
	t.Setenv("HOME", r)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(r, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(r, "credentials"))
	for _, k := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_SSO", "AWS_ENDPOINT_URL_SSO_OIDC"} {
		t.Setenv(k, "")
	}
	return r
}
func TestD07LocalSDKBoundary(t *testing.T) {
	r := isolated(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accountList":[]}`))
	}))
	defer server.Close()
	cfg, e := New("us-east-1", server.URL, r)
	if e != nil {
		t.Fatal(e)
	}
	_, e = sso.NewFromConfig(cfg).ListAccounts(context.Background(), &sso.ListAccountsInput{AccessToken: aws.String("synthetic")})
	if e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
func TestF07RejectUnsafeBoundary(t *testing.T) {
	r := isolated(t)
	for _, endpoint := range []string{"https://sso.us-east-1.amazonaws.com", "http://evil.test", "http://127.0.0.1:123/a", "http://test@127.0.0.1:123", "http://localhost:123?x=y"} {
		if _, e := New("us-east-1", endpoint, r); e == nil {
			t.Fatal(endpoint)
		}
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "production")
	if _, e := New("us-east-1", "http://localhost:123", r); e == nil {
		t.Fatal("credentials accepted")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("HOME", filepath.Dir(r))
	if _, e := New("us-east-1", "http://localhost:123", r); e == nil {
		t.Fatal("HOME accepted")
	}
}
func TestFactoryConfiguration(t *testing.T) {
	r := isolated(t)
	if _, e := New("", "", ""); e == nil {
		t.Fatal("empty region")
	}
	cfg, e := New("us-east-1", "", "")
	if e != nil || cfg.BaseEndpoint != nil || cfg.RetryMaxAttempts != 3 {
		t.Fatalf("%v %+v", e, cfg)
	}
	if _, e = New("us-east-1", "http://localhost:123", ""); e == nil {
		t.Fatal("missing root")
	}
	if e = ValidateTestMode(r, "http://localhost:123"); e != nil {
		t.Fatal(e)
	}
	t.Setenv("AWS_CONFIG_FILE", "/etc/config")
	if e = ValidateTestMode(r, "http://localhost:123"); e == nil {
		t.Fatal("external path")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(r, "config"))
	t.Setenv("AWS_ENDPOINT_URL", "https://evil.test")
	if e = ValidateTestMode(r, "http://localhost:123"); e == nil {
		t.Fatal("endpoint env")
	}
	t.Setenv("AWS_ENDPOINT_URL", "")
	outside := t.TempDir()
	if e = os.Symlink(outside, filepath.Join(r, "link")); e != nil {
		t.Fatal(e)
	}
	if e = WithinTestRoot(r, filepath.Join(r, "link", "file")); e == nil {
		t.Fatal("symlink escape")
	}
	if e = WithinTestRoot(r, filepath.Join(r, "safe", "file")); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(GuardError().Error(), "unsupported_endpoint") {
		t.Fatal("guard code")
	}
}

func TestD07GuardTransportAndRedirect(t *testing.T) {
	r := isolated(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path == "/redirect" {
			http.Redirect(w, q, "http://nonlocal.invalid/secret", 302)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()
	endpoint := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	cfg, e := New("us-east-1", endpoint, r)
	if e != nil {
		t.Fatal(e)
	}
	req, _ := http.NewRequest("GET", endpoint, nil)
	response, e := cfg.HTTPClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	req, _ = http.NewRequest("GET", endpoint+"/redirect", nil)
	if _, e = cfg.HTTPClient.Do(req); e == nil {
		t.Fatal("redirect accepted")
	}
	req, _ = http.NewRequest("GET", "http://nonlocal.invalid/secret", nil)
	if _, e = cfg.HTTPClient.Do(req); e == nil {
		t.Fatal("external transport")
	}
	credentials, e := cfg.Credentials.Retrieve(context.Background())
	if e != nil || credentials.AccessKeyID != "test" {
		t.Fatal(e)
	}
	if e = WithinTestRoot("relative", r); e == nil {
		t.Fatal("relative root")
	}
	if e = WithinTestRoot(r, "relative"); e == nil {
		t.Fatal("relative path")
	}
	if e = WithinTestRoot(filepath.Join(r, "absent"), filepath.Join(r, "file")); e == nil {
		t.Fatal("absent root")
	}
	if e = WithinTestRoot(r, filepath.Dir(r)); e == nil {
		t.Fatal("outside")
	}
	t.Setenv("AWS_SESSION_TOKEN", "secret")
	if e = ValidateTestMode(r, endpoint); e == nil {
		t.Fatal("session credential")
	}
	t.Setenv("AWS_SESSION_TOKEN", "")
	if e = ValidateTestMode("/", endpoint); e == nil {
		t.Fatal("non-disposable root")
	}
	if _, e = New("us-east-1", "", r); e == nil {
		t.Fatal("root without endpoint")
	}
}

func TestD06SDKRetryBudget(t *testing.T) {
	r := isolated(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-amzn-ErrorType", "TooManyRequestsException")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"message":"synthetic server detail"}`))
	}))
	defer server.Close()
	cfg, e := New("us-east-1", server.URL, r)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, e = sso.NewFromConfig(cfg).ListAccounts(ctx, &sso.ListAccountsInput{AccessToken: aws.String("synthetic")})
	if e == nil || calls.Load() != 3 {
		t.Fatalf("calls=%d err=%v", calls.Load(), e)
	}
}
