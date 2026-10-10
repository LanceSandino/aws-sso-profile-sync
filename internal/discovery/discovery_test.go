package discovery

import (
	"context"
	"errors"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	"sync"
	"testing"
)

type mock struct {
	mu        sync.Mutex
	fail      bool
	cycle     bool
	roleCycle bool
	calls     int
}

func (m *mock) ListAccounts(c context.Context, i *sso.ListAccountsInput, o ...func(*sso.Options)) (*sso.ListAccountsOutput, error) {
	if e := c.Err(); e != nil {
		return nil, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if i.NextToken == nil {
		return &sso.ListAccountsOutput{AccountList: []types.AccountInfo{{AccountId: aws.String("222222222222"), AccountName: aws.String("B")}}, NextToken: aws.String("page2")}, nil
	}
	next := (*string)(nil)
	if m.cycle {
		next = aws.String("page2")
	}
	return &sso.ListAccountsOutput{AccountList: []types.AccountInfo{{AccountId: aws.String("111111111111"), AccountName: aws.String("A")}, {AccountId: aws.String("222222222222"), AccountName: aws.String("B")}}, NextToken: next}, nil
}
func (m *mock) ListAccountRoles(c context.Context, i *sso.ListAccountRolesInput, o ...func(*sso.Options)) (*sso.ListAccountRolesOutput, error) {
	if e := c.Err(); e != nil {
		return nil, e
	}
	if m.fail {
		return nil, errors.New("secret body")
	}
	if i.NextToken == nil {
		return &sso.ListAccountRolesOutput{RoleList: []types.RoleInfo{{RoleName: aws.String("Read")}}, NextToken: aws.String("page2")}, nil
	}
	next := (*string)(nil)
	if m.roleCycle {
		next = aws.String("page2")
	}
	return &sso.ListAccountRolesOutput{RoleList: []types.RoleInfo{{RoleName: aws.String("Admin")}, {RoleName: aws.String("Read")}}, NextToken: next}, nil
}
func TestD01PaginationDeterministic(t *testing.T) {
	m := &mock{}
	s := Service{Client: m, Workers: 2}
	got, e := s.Discover(context.Background(), "access")
	if e != nil || len(got) != 4 {
		t.Fatalf("%+v %v", got, e)
	}
	if got[0].AccountID != "111111111111" || got[0].RoleName != "Admin" {
		t.Fatal(got)
	}
	if m.calls != 2 {
		t.Fatal(m.calls)
	}
}
func TestD04IncompleteD05CanceledD06Bounded(t *testing.T) {
	s := Service{Client: &mock{fail: true}}
	got, e := s.Discover(context.Background(), "access")
	if e == nil || got != nil || domain.ErrorCode(e) != "discovery_incomplete" {
		t.Fatalf("%+v %v", got, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.Discover(ctx, "access"); domain.ErrorCode(e) != "canceled" {
		t.Fatal(e)
	}
	for _, m := range []*mock{{cycle: true}, {roleCycle: true}} {
		s.Client = m
		if _, e = s.Discover(context.Background(), "access"); domain.ErrorCode(e) != "discovery_incomplete" {
			t.Fatal(e)
		}
	}
	if _, e = s.Discover(context.Background(), ""); domain.ErrorCode(e) != "login_required" {
		t.Fatal(e)
	}
}
