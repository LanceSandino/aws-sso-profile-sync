package auth

import (
	"context"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeOIDC struct {
	register int
	start    int
	create   int
	errs     []error
	response *ssooidc.CreateTokenOutput
}

func (f *fakeOIDC) RegisterClient(c context.Context, i *ssooidc.RegisterClientInput, o ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	f.register++
	if len(i.Scopes) != 1 || i.Scopes[0] != "sso:account:access" {
		panic("scope")
	}
	return &ssooidc.RegisterClientOutput{ClientId: aws.String("client"), ClientSecret: aws.String("secret"), ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix()}, nil
}
func (f *fakeOIDC) StartDeviceAuthorization(c context.Context, i *ssooidc.StartDeviceAuthorizationInput, o ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	f.start++
	return &ssooidc.StartDeviceAuthorizationOutput{DeviceCode: aws.String("device-secret"), VerificationUriComplete: aws.String("http://localhost/device?user_code=public"), ExpiresIn: 600, Interval: 1}, nil
}
func (f *fakeOIDC) CreateToken(c context.Context, i *ssooidc.CreateTokenInput, o ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	f.create++
	if len(f.errs) > 0 {
		e := f.errs[0]
		f.errs = f.errs[1:]
		return nil, e
	}
	if f.response != nil {
		return f.response, nil
	}
	return &ssooidc.CreateTokenOutput{AccessToken: aws.String("access"), RefreshToken: aws.String("refresh"), ExpiresIn: 3600}, nil
}
func store(t *testing.T) Store {
	return Store{Root: filepath.Join(t.TempDir(), "tokens"), Session: domain.Session{Name: "test", StartURL: "https://synthetic.example/start", Region: "us-east-1"}, Endpoint: "http://localhost:123"}
}
func valid(s Store) Token {
	return Token{AccessToken: "access", RefreshToken: "refresh", ClientID: "client", ClientSecret: "secret", ExpiresAt: time.Now().Add(time.Hour), RegistrationExpiresAt: time.Now().Add(time.Hour), Session: s.Session, Endpoint: s.Endpoint}
}
func TestA01DeviceLoginA02CacheReuse(t *testing.T) {
	s := store(t)
	f := &fakeOIDC{}
	urls := 0
	m := Manager{Client: f, Store: s, Notify: func(u string) error { urls++; return nil }}
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.register != 1 || f.start != 1 || urls != 1 {
		t.Fatalf("%+v %d", f, urls)
	}
	token, e := m.Access(context.Background(), false)
	if e != nil || token != "access" {
		t.Fatalf("%s %v", token, e)
	}
}
func TestA03InvalidA04IsolationA09Secure(t *testing.T) {
	s := store(t)
	if _, e := s.Read(); domain.ErrorCode(e) != "login_required" {
		t.Fatal(e)
	}
	tok := valid(s)
	if e := s.Save(tok); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(s.Path())
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("%v %v", info, e)
	}
	wrong := s
	wrong.Session.Region = "eu-west-1"
	if _, e = wrong.Read(); domain.ErrorCode(e) != "login_required" {
		t.Fatal(e)
	}
	tok.Session.Name = "other"
	if e = s.Save(tok); e == nil {
		t.Fatal("wrong binding")
	}
	tok = valid(s)
	tok.ExpiresAt = time.Now().Add(-time.Hour)
	if e = s.Save(tok); e != nil {
		t.Fatal(e)
	}
	m := Manager{Store: s}
	if _, e = m.Access(context.Background(), false); domain.ErrorCode(e) != "login_required" {
		t.Fatal(e)
	}
	os.WriteFile(s.Path(), []byte("bad json"), 0600)
	if _, e = s.Read(); domain.ErrorCode(e) != "auth_invalid" {
		t.Fatal(e)
	}
	os.Remove(s.Path())
	os.Symlink("elsewhere", s.Path())
	if _, e = s.Read(); e == nil {
		t.Fatal("symlink read")
	}
	if e = s.Save(valid(s)); e == nil {
		t.Fatal("symlink write")
	}
}
func TestA05TypedPollingA06Cancel(t *testing.T) {
	s := store(t)
	f := &fakeOIDC{errs: []error{&types.AuthorizationPendingException{}, &types.SlowDownException{}}}
	var waits []time.Duration
	m := Manager{Client: f, Store: s, Sleep: func(c context.Context, d time.Duration) error { waits = append(waits, d); return nil }}
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(waits) != 3 || waits[2] <= waits[1] {
		t.Fatal(waits)
	}
	for _, e := range []error{&types.AccessDeniedException{}, &types.ExpiredTokenException{}, &types.InvalidGrantException{}} {
		s = store(t)
		m = Manager{Client: &fakeOIDC{errs: []error{e}}, Store: s, Sleep: func(context.Context, time.Duration) error { return nil }}
		if e = m.Login(context.Background()); domain.ErrorCode(e) != "auth_invalid" {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m = Manager{Client: &fakeOIDC{}, Store: store(t)}
	if e := m.Login(ctx); domain.ErrorCode(e) != "canceled" {
		t.Fatal(e)
	}
}
func TestA10ExplicitRefreshOnly(t *testing.T) {
	s := store(t)
	tok := valid(s)
	tok.ExpiresAt = time.Now().Add(-time.Hour)
	s.Save(tok)
	f := &fakeOIDC{}
	m := Manager{Client: f, Store: s}
	if _, e := m.Access(context.Background(), false); e == nil || f.create != 0 {
		t.Fatal("hidden refresh")
	}
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.create != 1 || f.register != 0 {
		t.Fatal(f)
	}
	tok.ExpiresAt = time.Now().Add(-time.Hour)
	s.Save(tok)
	m.Client = &fakeOIDC{response: &ssooidc.CreateTokenOutput{ExpiresIn: 0}}
	if _, e := m.Access(context.Background(), true); domain.ErrorCode(e) != "auth_invalid" {
		t.Fatal(e)
	}
}

type scriptedOIDC struct {
	fakeOIDC
	registerErr    error
	deviceErr      error
	badRegister    bool
	badDevice      bool
	deviceInterval int32
}

func (f *scriptedOIDC) RegisterClient(c context.Context, i *ssooidc.RegisterClientInput, o ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	if f.registerErr != nil {
		return nil, f.registerErr
	}
	if f.badRegister {
		return &ssooidc.RegisterClientOutput{}, nil
	}
	return f.fakeOIDC.RegisterClient(c, i, o...)
}
func (f *scriptedOIDC) StartDeviceAuthorization(c context.Context, i *ssooidc.StartDeviceAuthorizationInput, o ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	if f.deviceErr != nil {
		return nil, f.deviceErr
	}
	if f.badDevice {
		return &ssooidc.StartDeviceAuthorizationOutput{}, nil
	}
	out, e := f.fakeOIDC.StartDeviceAuthorization(c, i, o...)
	if e == nil && f.deviceInterval > 0 {
		out.Interval = f.deviceInterval
	}
	return out, e
}
func TestA03LoginFailuresNeverCacheSecrets(t *testing.T) {
	for _, f := range []OIDC{&scriptedOIDC{registerErr: &types.InvalidClientException{}}, &scriptedOIDC{deviceErr: &types.InvalidClientException{}}, &scriptedOIDC{badRegister: true}, &scriptedOIDC{badDevice: true}, &fakeOIDC{response: &ssooidc.CreateTokenOutput{}}, nil} {
		s := store(t)
		m := Manager{Client: f, Store: s, Sleep: func(context.Context, time.Duration) error { return nil }}
		if e := m.Login(context.Background()); domain.ErrorCode(e) != "auth_invalid" {
			t.Fatal(e)
		}
		if _, e := os.Stat(s.Root); !os.IsNotExist(e) {
			t.Fatal("failure wrote cache")
		}
	}
	s := store(t)
	m := Manager{Client: &fakeOIDC{}, Store: s, Notify: func(string) error { return os.ErrPermission }}
	if e := m.Login(context.Background()); domain.ErrorCode(e) != "failed" {
		t.Fatal(e)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if e := m.Login(ctx); domain.ErrorCode(e) != "timed_out" {
		t.Fatal(e)
	}
}
func TestA05FinitePollBudget(t *testing.T) {
	f := &fakeOIDC{}
	for i := 0; i < 130; i++ {
		f.errs = append(f.errs, &types.AuthorizationPendingException{})
	}
	m := Manager{Client: f, Store: store(t), Sleep: func(context.Context, time.Duration) error { return nil }}
	if e := m.Login(context.Background()); domain.ErrorCode(e) != "timed_out" || f.create != 120 {
		t.Fatalf("%v %d", e, f.create)
	}
	m = Manager{Client: &fakeOIDC{}, Store: store(t), Sleep: func(context.Context, time.Duration) error { return os.ErrClosed }}
	if e := m.Login(context.Background()); domain.ErrorCode(e) != "canceled" {
		t.Fatal(e)
	}
	m = Manager{Client: &fakeOIDC{}, Store: store(t)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if e := m.Login(ctx); domain.ErrorCode(e) != "timed_out" {
		t.Fatal(e)
	}
}
func TestA09RejectInsecureAndMalformedCache(t *testing.T) {
	s := store(t)
	tok := valid(s)
	if e := s.Save(tok); e != nil {
		t.Fatal(e)
	}
	for _, contents := range []string{`{"unknown":"value"}`, `{} {}`, `{"accessToken":"access"}`} {
		if e := os.WriteFile(s.Path(), []byte(contents), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := s.Read(); e == nil {
			t.Fatal("invalid accepted")
		}
	}
	os.Remove(s.Path())
	if e := s.Save(tok); e != nil {
		t.Fatal(e)
	}
	os.Chmod(s.Path(), 0644)
	if _, e := s.Read(); e == nil {
		t.Fatal("insecure file")
	}
	os.Chmod(s.Path(), 0600)
	os.Chmod(s.Root, 0755)
	if _, e := s.Read(); e == nil {
		t.Fatal("insecure dir")
	}
	if e := s.Save(tok); e == nil {
		t.Fatal("insecure dir save")
	}
	os.Chmod(s.Root, 0700)
	os.Remove(s.Path())
	os.Mkdir(s.Path(), 0700)
	if e := s.Save(tok); e == nil {
		t.Fatal("directory target")
	}
	relative := s
	relative.Root = "relative"
	if _, e := relative.Read(); e == nil {
		t.Fatal("relative read")
	}
	if e := relative.Save(tok); e == nil {
		t.Fatal("relative save")
	}
	root := filepath.Join(t.TempDir(), "root")
	if e := os.Symlink(s.Root, root); e != nil {
		t.Fatal(e)
	}
	s.Root = root
	if _, e := s.Read(); e == nil {
		t.Fatal("symlink root")
	}
}
func TestA10RefreshFailureAndRotation(t *testing.T) {
	s := store(t)
	tok := valid(s)
	tok.ExpiresAt = time.Now().Add(-time.Hour)
	if e := s.Save(tok); e != nil {
		t.Fatal(e)
	}
	f := &fakeOIDC{errs: []error{&types.InvalidGrantException{}}}
	m := Manager{Store: s, Client: f}
	if _, e := m.Access(context.Background(), true); domain.ErrorCode(e) != "auth_invalid" {
		t.Fatal(e)
	}
	f = &fakeOIDC{response: &ssooidc.CreateTokenOutput{AccessToken: aws.String("rotated"), ExpiresIn: 3600}}
	m.Client = f
	if _, e := m.Access(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	got, e := s.Read()
	if e != nil || got.RefreshToken != "refresh" || got.AccessToken != "rotated" {
		t.Fatalf("%+v %v", got, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = m.Access(ctx, false); domain.ErrorCode(e) != "canceled" {
		t.Fatal(e)
	}
	m.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, e = m.Access(context.Background(), true); domain.ErrorCode(e) != "login_required" {
		t.Fatal(e)
	}
}

func TestA09FilesystemFailuresKeepOriginal(t *testing.T) {
	s := store(t)
	if e := s.Save(valid(s)); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(s.Path())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(s.Root, 0500); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(s.Root, 0700)
	if e = s.Save(valid(s)); domain.ErrorCode(e) != "failed" {
		t.Fatal(e)
	}
	after, e := os.ReadFile(s.Path())
	if e != nil || string(after) != string(original) {
		t.Fatal("original changed")
	}
	s2 := store(t)
	if e = os.WriteFile(s2.Root, []byte("regular"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = s2.Save(valid(s2)); e == nil {
		t.Fatal("regular root")
	}
	if _, e = s2.Read(); e == nil {
		t.Fatal("regular root read")
	}
	s3 := store(t)
	if e = os.MkdirAll(s3.Root, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(s3.Path(), make([]byte, (1<<20)+1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s3.Read(); e == nil {
		t.Fatal("unbounded cache read")
	}
}

func TestA05DeviceExpiryWithInjectedClock(t *testing.T) {
	now := time.Now()
	calls := 0
	m := Manager{Client: &fakeOIDC{}, Store: store(t), Now: func() time.Time {
		calls++
		if calls > 2 {
			return now.Add(11 * time.Minute)
		}
		return now
	}, Sleep: func(context.Context, time.Duration) error { return nil }}
	if e := m.Login(context.Background()); domain.ErrorCode(e) != "timed_out" {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m = Manager{Client: &fakeOIDC{}, Store: store(t), Notify: func(string) error { cancel(); return nil }}
	if e := m.Login(ctx); domain.ErrorCode(e) != "canceled" {
		t.Fatal(e)
	}
}

func TestA03ValidateCachedIssuedRefreshedBeforeSuccess(t *testing.T) {
	for _, kind := range []string{"cached", "issued", "refreshed"} {
		t.Run(kind, func(t *testing.T) {
			s := store(t)
			var original []byte
			if kind != "issued" {
				token := valid(s)
				if kind == "refreshed" {
					token.ExpiresAt = time.Now().Add(-time.Hour)
				}
				if e := s.Save(token); e != nil {
					t.Fatal(e)
				}
				original, _ = os.ReadFile(s.Path())
			}
			calls := 0
			m := Manager{Client: &fakeOIDC{}, Store: s, Sleep: func(context.Context, time.Duration) error { return nil }, Validate: func(context.Context, string) error { calls++; return os.ErrPermission }}
			if e := m.Login(context.Background()); domain.ErrorCode(e) != "auth_invalid" {
				t.Fatal(e)
			}
			expectedCalls := 1
			if kind != "issued" {
				expectedCalls = 2
			}
			if calls != expectedCalls {
				t.Fatal(calls)
			}
			if kind == "issued" {
				if _, e := os.Stat(s.Root); !os.IsNotExist(e) {
					t.Fatal("invalid token was saved")
				}
			} else {
				after, e := os.ReadFile(s.Path())
				if e != nil || string(after) != string(original) {
					t.Fatal("invalid login changed cache")
				}
			}
		})
	}
	s := store(t)
	m := Manager{Store: s, Client: &fakeOIDC{}, Sleep: func(context.Context, time.Duration) error { return nil }, Validate: func(context.Context, string) error { return nil }}
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
	token, _ := s.Read()
	token.ExpiresAt = time.Now().Add(-time.Hour)
	s.Save(token)
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestA10ExplicitReloginRecoversRevokedAndInvalidRefresh(t *testing.T) {
	for _, kind := range []string{"revoked", "refresh"} {
		t.Run(kind, func(t *testing.T) {
			s := store(t)
			cached := valid(s)
			cached.AccessToken = "old-revoked"
			if kind == "refresh" {
				cached.ExpiresAt = time.Now().Add(-time.Hour)
			}
			if e := s.Save(cached); e != nil {
				t.Fatal(e)
			}
			original, _ := os.ReadFile(s.Path())
			f := &fakeOIDC{}
			if kind == "refresh" {
				f.errs = []error{&types.InvalidGrantException{}}
			}
			m := Manager{Store: s, Client: f, Sleep: func(context.Context, time.Duration) error { return nil }, Validate: func(c context.Context, token string) error {
				if token == "old-revoked" {
					return &types.InvalidGrantException{}
				}
				data, e := os.ReadFile(s.Path())
				if e != nil || string(data) != string(original) {
					t.Fatal("old cache changed before successful validation")
				}
				return nil
			}}
			if e := m.Login(context.Background()); e != nil {
				t.Fatal(e)
			}
			got, e := s.Read()
			if e != nil || got.AccessToken != "access" || f.register != 1 || f.start != 1 {
				t.Fatalf("%+v %v %+v", got, e, f)
			}
		})
	}
	s := store(t)
	if e := s.Save(valid(s)); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(s.Path(), []byte("malformed"), 0600)
	f := &fakeOIDC{}
	m := Manager{Store: s, Client: f}
	if e := m.Login(context.Background()); domain.ErrorCode(e) != "auth_invalid" || f.register != 0 {
		t.Fatalf("%v %+v", e, f)
	}
}

func TestA05HonorsServerIntervalAndSlowDown(t *testing.T) {
	f := &scriptedOIDC{deviceInterval: 40, fakeOIDC: fakeOIDC{errs: []error{&types.SlowDownException{}, &types.SlowDownException{}}}}
	var waits []time.Duration
	m := Manager{Store: store(t), Client: f, Sleep: func(c context.Context, d time.Duration) error { waits = append(waits, d); return nil }}
	if e := m.Login(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(waits) != 3 || waits[0] != 40*time.Second || waits[1] != 45*time.Second || waits[2] != 50*time.Second {
		t.Fatal(waits)
	}
}
