// Package awsclient builds explicit SDK configurations without personal config loading.
// Explicit endpoints and synthetic test boundaries prevent credential or endpoint fallback.
package awsclient

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// GuardError deliberately contains no inherited values or endpoint secrets.
func GuardError() error {
	return domain.Fail("unsupported_endpoint", "local test mode requires a loopback endpoint and isolated synthetic environment")
}

func localURL(endpoint string) (*url.URL, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, GuardError()
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, GuardError()
	}
	if u.Port() == "" {
		return nil, GuardError()
	}
	return u, nil
}

// WithinTestRoot refuses traversal or symlink escape even for a not-yet-created path.
func WithinTestRoot(root, path string) error {
	if root == "" || path == "" || !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return GuardError()
	}
	r, e := filepath.EvalSymlinks(root)
	if e != nil {
		return GuardError()
	}
	p := filepath.Clean(path)
	tail := []string{}
	for {
		resolved, err := filepath.EvalSymlinks(p)
		if err == nil {
			p = resolved
			break
		}
		if !os.IsNotExist(err) {
			return GuardError()
		}
		parent := filepath.Dir(p)
		if parent == p {
			return GuardError()
		}
		tail = append(tail, filepath.Base(p))
		p = parent
	}
	for n := len(tail) - 1; n >= 0; n-- {
		p = filepath.Join(p, tail[n])
	}
	rel, e := filepath.Rel(r, p)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return GuardError()
	}
	return nil
}

// ValidateTestMode is exported so CLI and seeders can enforce the same boundary.
func ValidateTestMode(root, endpoint string) error {
	if _, e := localURL(endpoint); e != nil {
		return e
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return GuardError()
	}
	realRoot, e := filepath.EvalSymlinks(root)
	if e != nil {
		return GuardError()
	}
	temp, e := filepath.EvalSymlinks(os.TempDir())
	if e != nil {
		return GuardError()
	}
	rel, e := filepath.Rel(temp, realRoot)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return GuardError()
	}
	home, e := filepath.EvalSymlinks(os.Getenv("HOME"))
	if e != nil || home != realRoot {
		return GuardError()
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") != "test" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "test" {
		return GuardError()
	}
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"} {
		if os.Getenv(key) != "" {
			return GuardError()
		}
	}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "AWS_ENDPOINT_URL") && value != "" {
			return GuardError()
		}
	}
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		if e := WithinTestRoot(root, os.Getenv(key)); e != nil {
			return e
		}
	}
	return nil
}

// New never invokes LoadDefaultConfig, profiles, IMDS, environment endpoints or credentials.
// HTTP deadlines and bounded retries protect callers that omit an operation deadline.
func New(region, endpoint, testRoot string) (aws.Config, error) {
	if region == "" {
		return aws.Config{}, domain.Fail("config_invalid", "SSO region is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	cfg := aws.Config{Region: region, Credentials: aws.AnonymousCredentials{}, RetryMaxAttempts: 3, Retryer: func() aws.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 3; o.MaxBackoff = 2 * time.Second })
	}}
	if endpoint != "" {
		if e := ValidateTestMode(testRoot, endpoint); e != nil {
			return aws.Config{}, e
		}
		u, _ := localURL(endpoint)
		allowed := u.Host
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, e := net.SplitHostPort(address)
			if e != nil || address != allowed {
				return nil, GuardError()
			}
			if host == "localhost" {
				address = net.JoinHostPort("127.0.0.1", u.Port())
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		}
		cfg.BaseEndpoint = aws.String(strings.TrimRight(endpoint, "/"))
		cfg.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
	} else if testRoot != "" {
		return aws.Config{}, GuardError()
	}
	cfg.HTTPClient = &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return GuardError() }}
	return cfg, nil
}
