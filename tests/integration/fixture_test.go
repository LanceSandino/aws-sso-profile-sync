//go:build integration

// Package integration_test drives the real CLI against a disposable local Floci.
package integration_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	itypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	atypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	docker "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	dockerclient "github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Release 2.2.0, source revision 17c99047b92b5729b356f3584513cd6ed598b8a9.
const flociImage = "floci/floci:2.2.0@sha256:e97cd0c1dc2aa14e7697fb5ef5018404c4d6345169dbd276315f0bed2c7b0520"
const fixtureRevision = "sso-direct-group-v1"
const readRole = "Team=ReadOnly"
const powerRole = "AWSPowerUserAccess"

type fixture struct{ endpoint, principal string }

// No LoadDefaultConfig: the seeder cannot load personal files or credentials.
func localConfig(endpoint string) aws.Config {
	return aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), BaseEndpoint: aws.String(endpoint), HTTPClient: &http.Client{Timeout: 10 * time.Second, Transport: localOnlyTransport{endpoint}, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("fixture redirect forbidden") }}, RetryMaxAttempts: 2}
}

type localOnlyTransport struct{ endpoint string }

func (s localOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	endpoint, err := url.Parse(s.endpoint)
	if err != nil || request.URL.Scheme != "http" || request.URL.Host != endpoint.Host || request.URL.Hostname() != "127.0.0.1" {
		return nil, fmt.Errorf("fixture endpoint fallback forbidden")
	}
	return http.DefaultTransport.RoundTrip(request)
}

type ownedContainer struct {
	testcontainers.Container
	terminated bool
}

func (c *ownedContainer) Terminate(ctx context.Context) error {
	if c.terminated {
		return nil
	}
	err := c.Container.Terminate(ctx)
	if err == nil {
		c.terminated = true
	}
	return err
}

func startFloci(t *testing.T, data, principal string) (*ownedContainer, string) {
	t.Helper()
	// Testcontainers tries other Docker hosts after an explicit DOCKER_HOST
	// fails. An explicit selection is authoritative for this isolated suite;
	// reject an unavailable host before the library can silently fall back.
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		probe, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		client, err := dockerclient.New(dockerclient.WithHost(host))
		if err == nil {
			_, err = client.Ping(probe, dockerclient.PingOptions{})
			_ = client.Close()
		}
		cancel()
		if err != nil {
			t.Fatal("F10 FAIL: explicitly selected Docker host unavailable; no fallback or skip")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	raw, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{Started: true, ContainerRequest: testcontainers.ContainerRequest{
		Image: flociImage, ExposedPorts: []string{"4566/tcp"},
		Env: map[string]string{"FLOCI_STORAGE_MODE": "persistent", "FLOCI_STORAGE_PERSISTENT_PATH": "/fixture", "FLOCI_SERVICES_SSOOIDC_LOCAL_PRINCIPAL_ID": principal},
		HostConfigModifier: func(h *docker.HostConfig) {
			h.Binds = []string{data + ":/fixture"}
			port := network.MustParsePort("4566/tcp")
			h.PortBindings = network.PortMap{port: []network.PortBinding{{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "0"}}}
		},
		WaitingFor: wait.ForListeningPort("4566/tcp").WithStartupTimeout(75 * time.Second),
	}})
	if err != nil {
		t.Fatalf("F10 FAIL: Docker/Floci startup required; no skip: %v", err)
	}
	c := &ownedContainer{Container: raw}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := c.Terminate(cleanup); err != nil {
			t.Errorf("suite-owned container cleanup: %v", err)
		}
	})
	port, err := c.MappedPort(ctx, "4566/tcp")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + net.JoinHostPort("127.0.0.1", port.Port())
	// A listening TCP port does not prove the Java service can answer HTTP.
	// Probe the guarded local API within this same startup budget, including
	// the persisted fixture restart, before issuing fixture mutations.
	if _, err := waitForSSOReady(ctx, ssoadmin.NewFromConfig(localConfig(endpoint))); err != nil {
		t.Fatalf("F01 Floci API readiness failed: %v", err)
	}
	return c, endpoint
}

func seedFixture(t *testing.T) fixture {
	t.Helper()
	data := filepath.Join(t.TempDir(), "floci-data")
	if err := os.Mkdir(data, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(data, 0777); err != nil {
		t.Fatal(err)
	}
	bootstrap, endpoint := startFloci(t, data, "11111111-2222-3333-4444-555555555555")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cfg := localConfig(endpoint)
	admin := ssoadmin.NewFromConfig(cfg)
	ids := identitystore.NewFromConfig(cfg)
	instances, err := admin.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		t.Fatalf("F01 fixture ListInstances: %v", err)
	}
	if len(instances.Instances) != 1 {
		t.Fatalf("F01 expected one local instance, got %d", len(instances.Instances))
	}
	instance := instances.Instances[0]
	user, err := ids.CreateUser(ctx, &identitystore.CreateUserInput{IdentityStoreId: instance.IdentityStoreId, UserName: aws.String("sample-user"), DisplayName: aws.String("Synthetic Sample User")})
	if err != nil {
		t.Fatalf("F01 CreateUser: %v", err)
	}
	other, err := ids.CreateUser(ctx, &identitystore.CreateUserInput{IdentityStoreId: instance.IdentityStoreId, UserName: aws.String("unassigned-user")})
	if err != nil {
		t.Fatal(err)
	}
	group, err := ids.CreateGroup(ctx, &identitystore.CreateGroupInput{IdentityStoreId: instance.IdentityStoreId, DisplayName: aws.String("Synthetic ReadOnly Group")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ids.CreateGroupMembership(ctx, &identitystore.CreateGroupMembershipInput{IdentityStoreId: instance.IdentityStoreId, GroupId: group.GroupId, MemberId: &itypes.MemberIdMemberUserId{Value: aws.ToString(user.UserId)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{readRole, powerRole, "UnassignedRole"} {
		ps, err := admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: aws.String(role), SessionDuration: aws.String("PT1H")})
		if err != nil {
			t.Fatal(err)
		}
		if role != "UnassignedRole" {
			policy := role
			if role == readRole {
				policy = "AWSReadOnlyAccess"
			}
			_, err = admin.AttachManagedPolicyToPermissionSet(ctx, &ssoadmin.AttachManagedPolicyToPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: ps.PermissionSet.PermissionSetArn, ManagedPolicyArn: aws.String("arn:aws:iam::aws:policy/" + policy)})
			if err != nil {
				t.Fatal(err)
			}
		}
		// A third principal/account proves unrelated assignments cannot leak through.
		accounts := []string{"111111111111", "222222222222"}
		principal := user.UserId
		kind := atypes.PrincipalTypeUser
		if role == readRole {
			principal = group.GroupId
			kind = atypes.PrincipalTypeGroup
		}
		if role == "UnassignedRole" {
			accounts = []string{"333333333333"}
			principal = other.UserId
		}
		for _, account := range accounts {
			result, err := admin.CreateAccountAssignment(ctx, &ssoadmin.CreateAccountAssignmentInput{InstanceArn: instance.InstanceArn, PermissionSetArn: ps.PermissionSet.PermissionSetArn, PrincipalId: principal, PrincipalType: kind, TargetType: atypes.TargetTypeAwsAccount, TargetId: aws.String(account)})
			if err != nil {
				t.Fatal(err)
			}
			if result.AccountAssignmentCreationStatus == nil || result.AccountAssignmentCreationStatus.Status != atypes.StatusValuesSucceeded {
				t.Fatalf("assignment not successful: %v", result.AccountAssignmentCreationStatus)
			}
		}
	}
	// CreateUser assigns its own ID. Reboot persisted SDK-created resources with
	// that ID as the immutable configured local OIDC principal.
	if err := bootstrap.Terminate(ctx); err != nil {
		t.Fatal(err)
	}
	_, endpoint = startFloci(t, data, aws.ToString(user.UserId))
	verifyCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	_, err = identitystore.NewFromConfig(localConfig(endpoint)).DescribeUser(verifyCtx, &identitystore.DescribeUserInput{IdentityStoreId: instance.IdentityStoreId, UserId: user.UserId})
	if err != nil {
		t.Fatalf("SDK fixture did not persist across principal binding restart: %v", err)
	}
	t.Logf("F01 fixture=%s image=%s; synthetic SDK user/group, 2 assigned accounts, direct/group roles, 1 unassigned account/role", fixtureRevision, flociImage)
	return fixture{endpoint: endpoint, principal: aws.ToString(user.UserId)}
}

func fixtureWantPairs() map[string]bool {
	return map[string]bool{fmt.Sprintf("111111111111/%s", readRole): true, fmt.Sprintf("111111111111/%s", powerRole): true, fmt.Sprintf("222222222222/%s", readRole): true, fmt.Sprintf("222222222222/%s", powerRole): true}
}
