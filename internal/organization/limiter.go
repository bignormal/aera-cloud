package organization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const redisOrganizationLimitPrefix = "aera-cloud:organization-limit:"

var incrementOrganizationLimitScript = redis.NewScript(`
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
	OrganizationCreate LimitPolicy
	InvitationCreate   LimitPolicy
	InvitationAccept   LimitPolicy
	Mutation           LimitPolicy
	HighRisk           LimitPolicy
}

func (p LimitPolicies) valid() bool {
	return p.OrganizationCreate.valid() && p.InvitationCreate.valid() && p.InvitationAccept.valid() &&
		p.Mutation.valid() && p.HighRisk.valid()
}

type RedisOrganizationLimiter struct {
	client   redis.UniversalClient
	policies LimitPolicies
}

func NewRedisOrganizationLimiter(client redis.UniversalClient, policies LimitPolicies) (*RedisOrganizationLimiter, error) {
	if client == nil || !policies.valid() {
		return nil, fmt.Errorf("%w: organization rate limit configuration is invalid", ErrInvalidRequest)
	}
	return &RedisOrganizationLimiter{client: client, policies: policies}, nil
}

func (l *RedisOrganizationLimiter) Allow(
	ctx context.Context,
	action LimitAction,
	actor Actor,
	organizationID *uuid.UUID,
) (time.Duration, error) {
	if l == nil || l.client == nil {
		return 0, ErrServiceUnavailable
	}
	policy, err := l.policy(action)
	if err != nil {
		return 0, err
	}
	key, err := l.redisKey(action, actor, organizationID)
	if err != nil {
		return 0, err
	}
	result, err := incrementOrganizationLimitScript.Run(
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

func (l *RedisOrganizationLimiter) policy(action LimitAction) (LimitPolicy, error) {
	switch action {
	case LimitOrganizationCreate:
		return l.policies.OrganizationCreate, nil
	case LimitInvitationCreate:
		return l.policies.InvitationCreate, nil
	case LimitInvitationAccept:
		return l.policies.InvitationAccept, nil
	case LimitMutation:
		return l.policies.Mutation, nil
	case LimitHighRisk:
		return l.policies.HighRisk, nil
	default:
		return LimitPolicy{}, fmt.Errorf("%w: organization rate limit action is invalid", ErrInvalidRequest)
	}
}

func (l *RedisOrganizationLimiter) redisKey(
	action LimitAction,
	actor Actor,
	organizationID *uuid.UUID,
) (string, error) {
	if err := actor.Validate(); err != nil {
		return "", err
	}
	switch action {
	case LimitOrganizationCreate, LimitInvitationAccept:
		if organizationID != nil {
			return "", fmt.Errorf("%w: organization scope is not allowed for this action", ErrInvalidRequest)
		}
	case LimitInvitationCreate, LimitMutation, LimitHighRisk:
		if organizationID == nil || *organizationID == uuid.Nil {
			return "", fmt.Errorf("%w: organization scope is required for this action", ErrInvalidRequest)
		}
	default:
		return "", fmt.Errorf("%w: organization rate limit action is invalid", ErrInvalidRequest)
	}

	digest := sha256.New()
	_, _ = digest.Write([]byte("agentera.organization-rate-limit.v1\x00"))
	_, _ = digest.Write([]byte(action))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(actor.UserID[:])
	_, _ = digest.Write(actor.DeviceID[:])
	if organizationID == nil {
		_, _ = digest.Write([]byte{0})
	} else {
		_, _ = digest.Write([]byte{1})
		_, _ = digest.Write(organizationID[:])
	}
	return redisOrganizationLimitPrefix + hex.EncodeToString(digest.Sum(nil)), nil
}
