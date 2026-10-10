//go:build integration

// Readiness probes the local emulator's API before fixture creation or restart use.
package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

type ssoReadinessAPI interface {
	ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
}

func waitForSSOReady(ctx context.Context, client ssoReadinessAPI) (*ssoadmin.ListInstancesOutput, error) {
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("Floci API readiness: %w; last probe: %v", err, last)
		}
		probe, cancel := context.WithTimeout(ctx, time.Second)
		output, err := client.ListInstances(probe, &ssoadmin.ListInstancesInput{}, func(options *ssoadmin.Options) { options.RetryMaxAttempts = 1 })
		cancel()
		if err == nil {
			return output, nil
		}
		last = err
		delay := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			delay.Stop()
			return nil, fmt.Errorf("Floci API readiness: %w; last probe: %v", ctx.Err(), last)
		case <-delay.C:
		}
	}
}

func TestFlociHTTPReadiness(t *testing.T) {
	t.Run("OpenListenerReset503ThenHealthy", func(t *testing.T) {
		t.Setenv("AWS_ENDPOINT_URL", "http://outside.invalid")
		t.Setenv("AWS_PROFILE", "unused-synthetic-profile")
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || !strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".ListInstances") || !strings.Contains(r.Header.Get("Authorization"), "Credential=test/") {
				t.Error("probe did not use the real SSO Admin protocol with explicit synthetic credentials")
			}
			switch attempts.Add(1) {
			case 1:
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
			case 2:
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"message":"synthetic startup"}`))
			default:
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				_, _ = w.Write([]byte(`{"Instances":[{"InstanceArn":"arn:aws:sso:::instance/ssoins-1111111111111111","IdentityStoreId":"d-1111111111"}]}`))
			}
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		started := time.Now()
		output, err := waitForSSOReady(ctx, ssoadmin.NewFromConfig(localConfig(server.URL)))
		if err != nil || output == nil || len(output.Instances) != 1 {
			t.Fatalf("API did not become ready: %v", err)
		}
		if attempts.Load() != 3 || time.Since(started) < 450*time.Millisecond {
			t.Fatalf("expected three single SDK attempts with bounded probe delays, got %d", attempts.Load())
		}
	})
	t.Run("NeverReadyDeadline", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		started := time.Now()
		output, err := waitForSSOReady(ctx, ssoadmin.NewFromConfig(localConfig(server.URL)))
		if output != nil || !errors.Is(err, context.DeadlineExceeded) || attempts.Load() != 1 || time.Since(started) > time.Second {
			t.Fatalf("never-ready probe was not bounded: output=%v error=%v attempts=%d", output, err, attempts.Load())
		}
	})
	t.Run("CancellationDuringBackoff", func(t *testing.T) {
		called := make(chan struct{}, 1)
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			called <- struct{}{}
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { <-called; time.Sleep(20 * time.Millisecond); cancel() }()
		started := time.Now()
		_, err := waitForSSOReady(ctx, ssoadmin.NewFromConfig(localConfig(server.URL)))
		if !errors.Is(err, context.Canceled) || attempts.Load() != 1 || time.Since(started) > time.Second {
			t.Fatalf("cancellation did not stop backoff: %v attempts=%d", err, attempts.Load())
		}
	})
	t.Run("EndpointFallbackRejected", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { attempts.Add(1); w.WriteHeader(http.StatusOK) }))
		defer server.Close()
		client := ssoadmin.NewFromConfig(localConfig(server.URL), func(options *ssoadmin.Options) { options.BaseEndpoint = aws.String("http://outside.invalid") })
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		output, err := waitForSSOReady(ctx, client)
		if output != nil || err == nil || !strings.Contains(err.Error(), "fixture endpoint fallback forbidden") || attempts.Load() != 0 {
			t.Fatalf("endpoint guard was bypassed: %v attempts=%d", err, attempts.Load())
		}
	})
}
