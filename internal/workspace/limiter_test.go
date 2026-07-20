package workspace

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisWorkspaceLimiterKeepsActionsAndWindowsIndependent(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	clearWorkspaceLimitKeys(t, ctx, client)
	defer clearWorkspaceLimitKeys(t, context.Background(), client)

	policies := LimitPolicies{
		WorkspaceCreate:  LimitPolicy{Limit: 1, Window: 10 * time.Second},
		InvitationCreate: LimitPolicy{Limit: 2, Window: 20 * time.Second},
		InvitationAccept: LimitPolicy{Limit: 3, Window: 30 * time.Second},
	}
	limiter, err := NewRedisWorkspaceLimiter(client, policies)
	if err != nil {
		t.Fatalf("NewRedisWorkspaceLimiter() error = %v", err)
	}
	actor := Actor{
		UserID:   uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		DeviceID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
	}
	workspaceID := uuid.MustParse("33333333-3333-4333-8333-333333333333")

	if retryAfter, err := limiter.Allow(ctx, LimitWorkspaceCreate, actor, nil); err != nil || retryAfter != 0 {
		t.Fatalf("first workspace Allow() = %v, %v", retryAfter, err)
	}
	retryAfter, err := limiter.Allow(ctx, LimitWorkspaceCreate, actor, nil)
	if !errors.Is(err, ErrRateLimited) || retryAfter <= 0 || retryAfter > policies.WorkspaceCreate.Window {
		t.Fatalf("second workspace Allow() = %v, %v", retryAfter, err)
	}
	if retryAfter, err := limiter.Allow(ctx, LimitInvitationCreate, actor, &workspaceID); err != nil || retryAfter != 0 {
		t.Fatalf("first invitation creation Allow() = %v, %v", retryAfter, err)
	}
	if retryAfter, err := limiter.Allow(ctx, LimitInvitationAccept, actor, nil); err != nil || retryAfter != 0 {
		t.Fatalf("first invitation acceptance Allow() = %v, %v", retryAfter, err)
	}

	tests := []struct {
		action      LimitAction
		workspaceID *uuid.UUID
		wantCount   string
		window      time.Duration
	}{
		{action: LimitWorkspaceCreate, wantCount: "2", window: policies.WorkspaceCreate.Window},
		{action: LimitInvitationCreate, workspaceID: &workspaceID, wantCount: "1", window: policies.InvitationCreate.Window},
		{action: LimitInvitationAccept, wantCount: "1", window: policies.InvitationAccept.Window},
	}
	for _, test := range tests {
		key, err := limiter.redisKey(test.action, actor, test.workspaceID)
		if err != nil {
			t.Fatalf("redisKey(%s) error = %v", test.action, err)
		}
		count, err := client.Get(ctx, key).Result()
		if err != nil || count != test.wantCount {
			t.Fatalf("counter %s = %q, %v; want %q", test.action, count, err, test.wantCount)
		}
		ttl, err := client.PTTL(ctx, key).Result()
		if err != nil || ttl <= 0 || ttl > test.window {
			t.Fatalf("TTL %s = %v, %v; want within %v", test.action, ttl, err, test.window)
		}
	}
}

func TestRedisWorkspaceLimiterKeysContainOnlyHashedScope(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	clearWorkspaceLimitKeys(t, ctx, client)
	defer clearWorkspaceLimitKeys(t, context.Background(), client)

	limiter, err := NewRedisWorkspaceLimiter(client, LimitPolicies{
		WorkspaceCreate:  LimitPolicy{Limit: 5, Window: time.Minute},
		InvitationCreate: LimitPolicy{Limit: 5, Window: time.Minute},
		InvitationAccept: LimitPolicy{Limit: 5, Window: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewRedisWorkspaceLimiter() error = %v", err)
	}
	actor := Actor{
		UserID:   uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		DeviceID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
	}
	workspaceID := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	for _, request := range []struct {
		action      LimitAction
		workspaceID *uuid.UUID
	}{
		{action: LimitWorkspaceCreate},
		{action: LimitInvitationCreate, workspaceID: &workspaceID},
		{action: LimitInvitationAccept},
	} {
		if _, err := limiter.Allow(ctx, request.action, actor, request.workspaceID); err != nil {
			t.Fatalf("Allow(%s) error = %v", request.action, err)
		}
	}

	keys, err := client.Keys(ctx, redisWorkspaceLimitPrefix+"*").Result()
	if err != nil || len(keys) != 3 {
		t.Fatalf("workspace limit keys = %v, error = %v", keys, err)
	}
	sort.Strings(keys)
	keyPattern := regexp.MustCompile("^" + regexp.QuoteMeta(redisWorkspaceLimitPrefix) + `[0-9a-f]{64}$`)
	for _, key := range keys {
		if !keyPattern.MatchString(key) {
			t.Fatalf("Redis key is not prefix plus lowercase SHA-256: %q", key)
		}
		for _, forbidden := range []string{
			actor.UserID.String(), actor.DeviceID.String(), workspaceID.String(), "203.0.113.10", "raw-invitation-token",
		} {
			if strings.Contains(key, forbidden) {
				t.Fatalf("Redis key %q exposes raw scope %q", key, forbidden)
			}
		}
	}
}

func TestRedisWorkspaceLimiterFailsClosedForEveryAction(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1", DialTimeout: 25 * time.Millisecond, ReadTimeout: 25 * time.Millisecond,
		WriteTimeout: 25 * time.Millisecond, MaxRetries: 0,
	})
	defer func() { _ = client.Close() }()
	limiter, err := NewRedisWorkspaceLimiter(client, LimitPolicies{
		WorkspaceCreate:  LimitPolicy{Limit: 1, Window: time.Minute},
		InvitationCreate: LimitPolicy{Limit: 1, Window: time.Minute},
		InvitationAccept: LimitPolicy{Limit: 1, Window: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewRedisWorkspaceLimiter() error = %v", err)
	}
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	workspaceID := uuid.New()
	for _, request := range []struct {
		action      LimitAction
		workspaceID *uuid.UUID
	}{
		{action: LimitWorkspaceCreate},
		{action: LimitInvitationCreate, workspaceID: &workspaceID},
		{action: LimitInvitationAccept},
	} {
		retryAfter, err := limiter.Allow(context.Background(), request.action, actor, request.workspaceID)
		if !errors.Is(err, ErrServiceUnavailable) || retryAfter != 0 {
			t.Fatalf("Allow(%s) = %v, %v; want fail-closed ErrServiceUnavailable", request.action, retryAfter, err)
		}
	}
}

func TestRedisWorkspaceLimiterRejectsInvalidConfigurationAndScope(t *testing.T) {
	validPolicies := LimitPolicies{
		WorkspaceCreate:  LimitPolicy{Limit: 1, Window: time.Minute},
		InvitationCreate: LimitPolicy{Limit: 1, Window: time.Minute},
		InvitationAccept: LimitPolicy{Limit: 1, Window: time.Minute},
	}
	if _, err := NewRedisWorkspaceLimiter(nil, validPolicies); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil client error = %v, want ErrInvalidRequest", err)
	}
	invalidPolicies := validPolicies
	invalidPolicies.InvitationAccept.Limit = 0
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = client.Close() }()
	if _, err := NewRedisWorkspaceLimiter(client, invalidPolicies); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid policies error = %v, want ErrInvalidRequest", err)
	}

	limiter, err := NewRedisWorkspaceLimiter(client, validPolicies)
	if err != nil {
		t.Fatalf("NewRedisWorkspaceLimiter() error = %v", err)
	}
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	workspaceID := uuid.New()
	for _, request := range []struct {
		action      LimitAction
		actor       Actor
		workspaceID *uuid.UUID
	}{
		{action: "unknown", actor: actor},
		{action: LimitWorkspaceCreate, actor: Actor{}},
		{action: LimitWorkspaceCreate, actor: actor, workspaceID: &workspaceID},
		{action: LimitInvitationCreate, actor: actor},
		{action: LimitInvitationAccept, actor: actor, workspaceID: &workspaceID},
	} {
		if _, err := limiter.Allow(context.Background(), request.action, request.actor, request.workspaceID); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Allow(%s) invalid scope error = %v, want ErrInvalidRequest", request.action, err)
		}
	}
}

func clearWorkspaceLimitKeys(t *testing.T, ctx context.Context, client redis.UniversalClient) {
	t.Helper()
	keys, err := client.Keys(ctx, redisWorkspaceLimitPrefix+"*").Result()
	if err != nil {
		t.Fatalf("list workspace limit keys: %v", err)
	}
	if len(keys) > 0 {
		if err := client.Del(ctx, keys...).Err(); err != nil {
			t.Fatalf("delete workspace limit keys: %v", err)
		}
	}
}
