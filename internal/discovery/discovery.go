// Package discovery returns complete, sorted account-role assignments or no results.
// Explicit SDK clients and caller contexts yield complete sorted assignments.
package discovery

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/domain"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
)

type API interface {
	ListAccounts(context.Context, *sso.ListAccountsInput, ...func(*sso.Options)) (*sso.ListAccountsOutput, error)
	ListAccountRoles(context.Context, *sso.ListAccountRolesInput, ...func(*sso.Options)) (*sso.ListAccountRolesOutput, error)
}
type Service struct {
	Client  API
	Workers int
}

func failure(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return domain.Fail("timed_out", "discovery deadline exceeded")
	}
	if ctx.Err() != nil {
		return domain.Fail("canceled", "discovery canceled")
	}
	return domain.Fail("discovery_incomplete", "account-role discovery failed; no partial results can be applied")
}
func (s Service) accounts(ctx context.Context, token string) ([]types.AccountInfo, error) {
	paginator := sso.NewListAccountsPaginator(s.Client, &sso.ListAccountsInput{AccessToken: aws.String(token)}, func(o *sso.ListAccountsPaginatorOptions) { o.StopOnDuplicateToken = true })
	seenPages := map[string]bool{}
	seen := map[string]bool{}
	var accounts []types.AccountInfo
	for pages := 0; pages < 1000 && paginator.HasMorePages(); pages++ {
		out, e := paginator.NextPage(ctx)
		if e != nil {
			var unauthorized *types.UnauthorizedException
			if errors.As(e, &unauthorized) {
				return nil, domain.Fail("auth_invalid", "cached bearer was rejected; run explicit login")
			}
			return nil, failure(ctx)
		}
		if out == nil {
			return nil, failure(ctx)
		}
		for _, a := range out.AccountList {
			id := aws.ToString(a.AccountId)
			if id == "" {
				return nil, failure(ctx)
			}
			if !seen[id] {
				seen[id] = true
				accounts = append(accounts, a)
			}
		}
		next := out.NextToken
		if aws.ToString(next) == "" {
			return accounts, nil
		}
		if seenPages[*next] {
			return nil, failure(ctx)
		}
		seenPages[*next] = true
	}
	return nil, failure(ctx)
}
func (s Service) roles(ctx context.Context, token string, a types.AccountInfo) ([]domain.Assignment, error) {
	paginator := sso.NewListAccountRolesPaginator(s.Client, &sso.ListAccountRolesInput{AccessToken: aws.String(token), AccountId: a.AccountId}, func(o *sso.ListAccountRolesPaginatorOptions) { o.StopOnDuplicateToken = true })
	seenPages := map[string]bool{}
	seen := map[string]bool{}
	var roles []domain.Assignment
	for pages := 0; pages < 1000 && paginator.HasMorePages(); pages++ {
		out, e := paginator.NextPage(ctx)
		if e != nil {
			var unauthorized *types.UnauthorizedException
			if errors.As(e, &unauthorized) {
				return nil, domain.Fail("auth_invalid", "cached bearer was rejected; run explicit login")
			}
			return nil, failure(ctx)
		}
		if out == nil {
			return nil, failure(ctx)
		}
		for _, r := range out.RoleList {
			name := aws.ToString(r.RoleName)
			if name == "" {
				return nil, failure(ctx)
			}
			if !seen[name] {
				seen[name] = true
				roles = append(roles, domain.Assignment{AccountID: aws.ToString(a.AccountId), AccountName: aws.ToString(a.AccountName), RoleName: name})
			}
		}
		next := out.NextToken
		if aws.ToString(next) == "" {
			return roles, nil
		}
		if seenPages[*next] {
			return nil, failure(ctx)
		}
		seenPages[*next] = true
	}
	return nil, failure(ctx)
}
func (s Service) Discover(ctx context.Context, token string) ([]domain.Assignment, error) {
	if ctx.Err() != nil {
		return nil, failure(ctx)
	}
	if token == "" {
		return nil, domain.Fail("login_required", "run explicit login before discovery")
	}
	if s.Client == nil {
		return nil, failure(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	accounts, e := s.accounts(ctx, token)
	if e != nil {
		return nil, e
	}
	workers := s.Workers
	if workers < 1 {
		workers = 4
	}
	if workers > 16 {
		workers = 16
	}
	if workers > len(accounts) {
		workers = len(accounts)
	}
	jobs := make(chan types.AccountInfo)
	var wg sync.WaitGroup
	var mu sync.Mutex
	assignments := []domain.Assignment{}
	var first error
	for n := 0; n < workers; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				roles, e := s.roles(ctx, token, a)
				mu.Lock()
				if e != nil {
					if first == nil {
						first = e
						cancel()
					}
				} else {
					assignments = append(assignments, roles...)
				}
				mu.Unlock()
			}
		}()
	}
send:
	for _, a := range accounts {
		select {
		case jobs <- a:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return nil, first
	}
	if ctx.Err() != nil {
		return nil, failure(ctx)
	}
	sort.Slice(assignments, func(i, j int) bool {
		if assignments[i].AccountID != assignments[j].AccountID {
			return assignments[i].AccountID < assignments[j].AccountID
		}
		return assignments[i].RoleName < assignments[j].RoleName
	})
	return assignments, nil
}
