// Device polling and refresh write only the explicitly bound private session store.
// Authentication effects require an explicit, caller-bound manager invocation.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
)

type OIDC interface {
	RegisterClient(context.Context, *ssooidc.RegisterClientInput, ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(context.Context, *ssooidc.StartDeviceAuthorizationInput, ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(context.Context, *ssooidc.CreateTokenInput, ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}
type Manager struct {
	Client   OIDC
	Store    Store
	Notify   func(string) error
	Validate func(context.Context, string) error
	Now      func() time.Time
	Sleep    func(context.Context, time.Duration) error
}

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}
func (m Manager) sleep(ctx context.Context, d time.Duration) error {
	if m.Sleep != nil {
		return m.Sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func contextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return domain.Fail("timed_out", "authentication deadline exceeded")
	}
	return domain.Fail("canceled", "authentication canceled")
}
func safeAuth(err error, ctx context.Context) error {
	if ctx.Err() != nil {
		return contextError(ctx)
	}
	return domain.Fail("auth_invalid", "SSO authorization failed; run explicit login")
}

// Access(false) is strictly read-only. Refresh is permitted only to explicit login callers.
func (m Manager) Access(ctx context.Context, refresh bool) (string, error) {
	if ctx.Err() != nil {
		return "", contextError(ctx)
	}
	token, e := m.Store.Read()
	if e != nil {
		return "", e
	}
	if token.ExpiresAt.After(m.now().Add(time.Minute)) {
		if refresh && m.Validate != nil {
			if err := m.Validate(ctx, token.AccessToken); err != nil {
				return "", safeAuth(err, ctx)
			}
		}
		return token.AccessToken, nil
	}
	if !refresh || m.Client == nil || token.RefreshToken == "" || token.ClientID == "" || token.ClientSecret == "" || !token.RegistrationExpiresAt.After(m.now().Add(time.Minute)) {
		return "", required()
	}
	result, e := m.Client.CreateToken(ctx, &ssooidc.CreateTokenInput{GrantType: aws.String("refresh_token"), RefreshToken: aws.String(token.RefreshToken), ClientId: aws.String(token.ClientID), ClientSecret: aws.String(token.ClientSecret)})
	if e != nil {
		return "", safeAuth(e, ctx)
	}
	if result == nil || aws.ToString(result.AccessToken) == "" || result.ExpiresIn <= 60 {
		return "", safeAuth(nil, ctx)
	}
	if m.Validate != nil {
		if err := m.Validate(ctx, aws.ToString(result.AccessToken)); err != nil {
			return "", safeAuth(err, ctx)
		}
	}
	token.AccessToken = aws.ToString(result.AccessToken)
	if aws.ToString(result.RefreshToken) != "" {
		token.RefreshToken = aws.ToString(result.RefreshToken)
	}
	token.ExpiresAt = m.now().Add(time.Duration(result.ExpiresIn) * time.Second)
	if e = m.Store.Save(token); e != nil {
		return "", e
	}
	return token.AccessToken, nil
}

func (m Manager) Login(ctx context.Context) error {
	if ctx.Err() != nil {
		return contextError(ctx)
	}
	// The full registration/device flow, including retries, has a finite wall-clock bound.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, e := m.Access(ctx, true); e == nil {
		return nil
	} else if domain.ErrorCode(e) == "auth_invalid" {
		// Explicit login may recover a revoked bearer or invalid refresh grant.
		// It must not disguise malformed, mismatched, or insecure cache state.
		if _, cacheError := m.Store.Read(); cacheError != nil {
			return cacheError
		}
	} else if domain.ErrorCode(e) != "login_required" {
		return e
	}
	if m.Client == nil {
		return domain.Fail("auth_invalid", "OIDC client is required for login")
	}
	registration, e := m.Client.RegisterClient(ctx, &ssooidc.RegisterClientInput{ClientName: aws.String("aws-sso-profile-sync"), ClientType: aws.String("public"), Scopes: []string{"sso:account:access"}})
	if e != nil {
		return safeAuth(e, ctx)
	}
	if registration == nil || aws.ToString(registration.ClientId) == "" || aws.ToString(registration.ClientSecret) == "" || registration.ClientSecretExpiresAt <= m.now().Unix() {
		return safeAuth(nil, ctx)
	}
	device, e := m.Client.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{ClientId: registration.ClientId, ClientSecret: registration.ClientSecret, StartUrl: aws.String(m.Store.Session.StartURL)})
	if e != nil {
		return safeAuth(e, ctx)
	}
	if device == nil || aws.ToString(device.DeviceCode) == "" || aws.ToString(device.VerificationUriComplete) == "" || device.ExpiresIn <= 0 {
		return safeAuth(nil, ctx)
	}
	if m.Notify != nil {
		if e = m.Notify(aws.ToString(device.VerificationUriComplete)); e != nil {
			return domain.Fail("failed", "cannot present device authorization URL")
		}
	}
	duration := time.Duration(device.ExpiresIn) * time.Second
	ctx, stop := context.WithTimeout(ctx, duration)
	defer stop()
	expires := m.now().Add(duration)
	interval := time.Duration(device.Interval) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	// Independent attempt budget also bounds custom clocks/sleepers and repeated pending replies.
	for attempts := 0; attempts < 120; attempts++ {
		if ctx.Err() != nil {
			return contextError(ctx)
		}
		if !m.now().Before(expires) {
			return domain.Fail("timed_out", "device authorization expired")
		}
		if e = m.sleep(ctx, interval); e != nil {
			if ctx.Err() != nil {
				return contextError(ctx)
			}
			return domain.Fail("canceled", "device polling interrupted")
		}
		result, e := m.Client.CreateToken(ctx, &ssooidc.CreateTokenInput{ClientId: registration.ClientId, ClientSecret: registration.ClientSecret, DeviceCode: device.DeviceCode, GrantType: aws.String("urn:ietf:params:oauth:grant-type:device_code")})
		if e != nil {
			var pending *types.AuthorizationPendingException
			var slowdown *types.SlowDownException
			if errors.As(e, &pending) {
				continue
			}
			if errors.As(e, &slowdown) {
				interval += 5 * time.Second
				continue
			}
			return safeAuth(e, ctx)
		}
		if result == nil || aws.ToString(result.AccessToken) == "" || result.ExpiresIn <= 60 {
			return safeAuth(nil, ctx)
		}
		if m.Validate != nil {
			if err := m.Validate(ctx, aws.ToString(result.AccessToken)); err != nil {
				return safeAuth(err, ctx)
			}
		}
		return m.Store.Save(Token{AccessToken: aws.ToString(result.AccessToken), RefreshToken: aws.ToString(result.RefreshToken), ClientID: aws.ToString(registration.ClientId), ClientSecret: aws.ToString(registration.ClientSecret), ExpiresAt: m.now().Add(time.Duration(result.ExpiresIn) * time.Second), RegistrationExpiresAt: time.Unix(registration.ClientSecretExpiresAt, 0), Session: m.Store.Session, Endpoint: m.Store.Endpoint})
	}
	return domain.Fail("timed_out", "device authorization polling limit reached")
}
