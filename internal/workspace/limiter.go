package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const redisWorkspaceLimitPrefix = "aera-cloud:workspace-limit:"

var incrementWorkspaceLimitScript = redis.NewScript(`
	local count = redis.call('INCR', KEYS[1])
	if count == 1 then
		redis.call('PEXPIRE', KEYS[1], ARGV[1])
	end
	local ttl = redis.call('PTTL', KEYS[1])
	return {count, ttl}
`)

type LimitPolicy struct {
	Limit  int64
	Window time.Duration
}

func (p LimitPolicy) valid() bool {
	return p.Limit > 0 && p.Window >= time.Millisecond
}

type LimitPolicies struct {
	WorkspaceCreate  LimitPolicy
	InvitationCreate LimitPolicy
	InvitationAccept LimitPolicy
}

func (p LimitPolicies) valid() bool {
	return p.WorkspaceCreate.valid() && p.InvitationCreate.valid() && p.InvitationAccept.valid()
}

type RedisWorkspaceLimiter struct {
	client   redis.UniversalClient
	policies LimitPolicies
}

func NewRedisWorkspaceLimiter(client redis.UniversalClient, policies LimitPolicies) (*RedisWorkspaceLimiter, error) {
	if client == nil || !policies.valid() {
		return nil, fmt.Errorf("%w: workspace rate limit configuration is invalid", ErrInvalidRequest)
	}
	return &RedisWorkspaceLimiter{client: client, policies: policies}, nil
}

func (l *RedisWorkspaceLimiter) Allow(
	ctx context.Context,
	action LimitAction,
	actor Actor,
	workspaceID *uuid.UUID,
) (time.Duration, error) {
	if l == nil || l.client == nil {
		return 0, ErrServiceUnavailable
	}
	policy, err := l.policy(action)
	if err != nil {
		return 0, err
	}
	key, err := l.redisKey(action, actor, workspaceID)
	if err != nil {
		return 0, err
	}
	result, err := incrementWorkspaceLimitScript.Run(
		ctx,
		l.client,
		[]string{key},
		policy.Window.Milliseconds(),
	).Int64Slice()
	if err != nil || len(result) != 2 {
		return 0, ErrServiceUnavailable
	}
	if result[0] <= policy.Limit {
		return 0, nil
	}
	retryAfter := time.Duration(result[1]) * time.Millisecond
	if retryAfter <= 0 || retryAfter > policy.Window {
		retryAfter = policy.Window
	}
	return retryAfter, ErrRateLimited
}

func (l *RedisWorkspaceLimiter) policy(action LimitAction) (LimitPolicy, error) {
	switch action {
	case LimitWorkspaceCreate:
		return l.policies.WorkspaceCreate, nil
	case LimitInvitationCreate:
		return l.policies.InvitationCreate, nil
	case LimitInvitationAccept:
		return l.policies.InvitationAccept, nil
	default:
		return LimitPolicy{}, fmt.Errorf("%w: workspace rate limit action is invalid", ErrInvalidRequest)
	}
}

func (l *RedisWorkspaceLimiter) redisKey(
	action LimitAction,
	actor Actor,
	workspaceID *uuid.UUID,
) (string, error) {
	if err := actor.Validate(); err != nil {
		return "", err
	}
	switch action {
	case LimitWorkspaceCreate, LimitInvitationAccept:
		if workspaceID != nil {
			return "", fmt.Errorf("%w: workspace scope is not allowed for this action", ErrInvalidRequest)
		}
	case LimitInvitationCreate:
		if workspaceID == nil || *workspaceID == uuid.Nil {
			return "", fmt.Errorf("%w: workspace scope is required for invitation creation", ErrInvalidRequest)
		}
	default:
		return "", fmt.Errorf("%w: workspace rate limit action is invalid", ErrInvalidRequest)
	}

	digest := sha256.New()
	_, _ = digest.Write([]byte("agentera.workspace-rate-limit.v1\x00"))
	_, _ = digest.Write([]byte(action))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(actor.UserID[:])
	_, _ = digest.Write(actor.DeviceID[:])
	if workspaceID == nil {
		_, _ = digest.Write([]byte{0})
	} else {
		_, _ = digest.Write([]byte{1})
		_, _ = digest.Write(workspaceID[:])
	}
	return redisWorkspaceLimitPrefix + hex.EncodeToString(digest.Sum(nil)), nil
}
