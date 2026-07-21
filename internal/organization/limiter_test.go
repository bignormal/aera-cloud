package organization

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisOrganizationLimiterKeepsFiveActionsAndWindowsIndependent(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	clearOrganizationLimitKeys(t, ctx, client)
	defer clearOrganizationLimitKeys(t, context.Background(), client)

	policies := LimitPolicies{
		OrganizationCreate: LimitPolicy{Limit: 1, Window: 10 * time.Second},
		InvitationCreate:   LimitPolicy{Limit: 2, Window: 20 * time.Second},
		InvitationAccept:   LimitPolicy{Limit: 3, Window: 30 * time.Second},
		Mutation:           LimitPolicy{Limit: 4, Window: 40 * time.Second},
		HighRisk:           LimitPolicy{Limit: 5, Window: 50 * time.Second},
	}
	limiter, err := NewRedisOrganizationLimiter(client, policies)
	if err != nil {
		t.Fatalf("NewRedisOrganizationLimiter() error = %v", err)
	}
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	organizationID := uuid.New()
	requests := []struct {
		action         LimitAction
		organizationID *uuid.UUID
		window         time.Duration
	}{
		{action: LimitOrganizationCreate, window: policies.OrganizationCreate.Window},
		{action: LimitInvitationCreate, organizationID: &organizationID, window: policies.InvitationCreate.Window},
		{action: LimitInvitationAccept, window: policies.InvitationAccept.Window},
		{action: LimitMutation, organizationID: &organizationID, window: policies.Mutation.Window},
		{action: LimitHighRisk, organizationID: &organizationID, window: policies.HighRisk.Window},
	}
	for _, request := range requests {
		if retryAfter, err := limiter.Allow(ctx, request.action, actor, request.organizationID); err != nil || retryAfter != 0 {
			t.Fatalf("first Allow(%s) = %v, %v", request.action, retryAfter, err)
		}
		key, err := limiter.redisKey(request.action, actor, request.organizationID)
		if err != nil {
			t.Fatalf("redisKey(%s) error = %v", request.action, err)
		}
		if count, err := client.Get(ctx, key).Result(); err != nil || count != "1" {
			t.Fatalf("counter %s = %q, %v", request.action, count, err)
		}
		if ttl, err := client.PTTL(ctx, key).Result(); err != nil || ttl <= 0 || ttl > request.window {
			t.Fatalf("TTL %s = %v, %v", request.action, ttl, err)
		}
	}
	retryAfter, err := limiter.Allow(ctx, LimitOrganizationCreate, actor, nil)
	if !errors.Is(err, ErrRateLimited) || retryAfter <= 0 || retryAfter > policies.OrganizationCreate.Window {
		t.Fatalf("second create Allow() = %v, %v", retryAfter, err)
	}
}

func TestOrganizationLimiterKeysContainOnlyHashedScope(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = client.Close() }()
	limiter, err := NewRedisOrganizationLimiter(client, validLimitPolicies())
	if err != nil {
		t.Fatalf("NewRedisOrganizationLimiter() error = %v", err)
	}
	actor := Actor{
		UserID:   uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		DeviceID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
	}
	organizationID := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	requests := []struct {
		action         LimitAction
		organizationID *uuid.UUID
	}{
		{action: LimitOrganizationCreate},
		{action: LimitInvitationCreate, organizationID: &organizationID},
		{action: LimitInvitationAccept},
		{action: LimitMutation, organizationID: &organizationID},
		{action: LimitHighRisk, organizationID: &organizationID},
	}
	pattern := regexp.MustCompile("^" + regexp.QuoteMeta(redisOrganizationLimitPrefix) + `[0-9a-f]{64}$`)
	seen := map[string]struct{}{}
	for _, request := range requests {
		key, err := limiter.redisKey(request.action, actor, request.organizationID)
		if err != nil {
			t.Fatalf("redisKey(%s) error = %v", request.action, err)
		}
		if !pattern.MatchString(key) {
			t.Fatalf("Redis key is not prefix plus lowercase SHA-256: %q", key)
		}
		for _, forbidden := range []string{actor.UserID.String(), actor.DeviceID.String(), organizationID.String(), "raw-invitation-token"} {
			if strings.Contains(key, forbidden) {
				t.Fatalf("Redis key %q exposes raw scope %q", key, forbidden)
			}
		}
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("independent action reused Redis key %q", key)
		}
		seen[key] = struct{}{}
	}
}

func TestOrganizationLimiterRejectsInvalidConfigurationAndScope(t *testing.T) {
	policies := validLimitPolicies()
	if _, err := NewRedisOrganizationLimiter(nil, policies); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil client error = %v", err)
	}
	invalid := policies
	invalid.HighRisk.Limit = 0
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = client.Close() }()
	if _, err := NewRedisOrganizationLimiter(client, invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid policy error = %v", err)
	}
	limiter, err := NewRedisOrganizationLimiter(client, policies)
	if err != nil {
		t.Fatalf("NewRedisOrganizationLimiter() error = %v", err)
	}
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	organizationID := uuid.New()
	for _, request := range []struct {
		action         LimitAction
		actor          Actor
		organizationID *uuid.UUID
	}{
		{action: "unknown", actor: actor},
		{action: LimitOrganizationCreate, actor: Actor{}},
		{action: LimitOrganizationCreate, actor: actor, organizationID: &organizationID},
		{action: LimitInvitationCreate, actor: actor},
		{action: LimitInvitationAccept, actor: actor, organizationID: &organizationID},
		{action: LimitMutation, actor: actor},
		{action: LimitHighRisk, actor: actor},
	} {
		if _, err := limiter.Allow(context.Background(), request.action, request.actor, request.organizationID); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Allow(%s) error = %v, want ErrInvalidRequest", request.action, err)
		}
	}
}

func TestOrganizationLimiterFailsClosedForEveryAction(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1", DialTimeout: 25 * time.Millisecond, ReadTimeout: 25 * time.Millisecond,
		WriteTimeout: 25 * time.Millisecond, MaxRetries: 0,
	})
	defer func() { _ = client.Close() }()
	limiter, err := NewRedisOrganizationLimiter(client, validLimitPolicies())
	if err != nil {
		t.Fatalf("NewRedisOrganizationLimiter() error = %v", err)
	}
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	organizationID := uuid.New()
	for _, request := range []struct {
		action         LimitAction
		organizationID *uuid.UUID
	}{
		{action: LimitOrganizationCreate},
		{action: LimitInvitationCreate, organizationID: &organizationID},
		{action: LimitInvitationAccept},
		{action: LimitMutation, organizationID: &organizationID},
		{action: LimitHighRisk, organizationID: &organizationID},
	} {
		retryAfter, err := limiter.Allow(context.Background(), request.action, actor, request.organizationID)
		if !errors.Is(err, ErrServiceUnavailable) || retryAfter != 0 {
			t.Fatalf("Allow(%s) = %v, %v", request.action, retryAfter, err)
		}
	}
}

func validLimitPolicies() LimitPolicies {
	return LimitPolicies{
		OrganizationCreate: LimitPolicy{Limit: 1, Window: time.Minute},
		InvitationCreate:   LimitPolicy{Limit: 2, Window: time.Minute},
		InvitationAccept:   LimitPolicy{Limit: 3, Window: time.Minute},
		Mutation:           LimitPolicy{Limit: 4, Window: time.Minute},
		HighRisk:           LimitPolicy{Limit: 5, Window: time.Minute},
	}
}

func clearOrganizationLimitKeys(t *testing.T, ctx context.Context, client redis.UniversalClient) {
	t.Helper()
	keys, err := client.Keys(ctx, redisOrganizationLimitPrefix+"*").Result()
	if err != nil {
		t.Fatalf("list Organization limit keys: %v", err)
	}
	if len(keys) > 0 {
		if err := client.Del(ctx, keys...).Err(); err != nil {
			t.Fatalf("delete Organization limit keys: %v", err)
		}
	}
}
