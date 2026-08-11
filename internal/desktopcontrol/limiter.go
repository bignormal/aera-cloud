package desktopcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisDesktopControlLimitPrefix = "aera-cloud:desktop-control-limit:"

var incrementDesktopControlLimitScript = redis.NewScript(`
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

func (policy LimitPolicy) valid() bool {
	return policy.Limit > 0 && policy.Window >= time.Second
}

type LimitPolicies struct {
	Heartbeat     LimitPolicy
	CommandResult LimitPolicy
}

func (policies LimitPolicies) valid() bool {
	return policies.Heartbeat.valid() && policies.CommandResult.valid()
}

func DefaultLimitPolicies() LimitPolicies {
	return LimitPolicies{
		Heartbeat:     LimitPolicy{Limit: 120, Window: 10 * time.Minute},
		CommandResult: LimitPolicy{Limit: 120, Window: 10 * time.Minute},
	}
}

type RedisLimiter struct {
	client   redis.UniversalClient
	policies LimitPolicies
}

func NewRedisLimiter(client redis.UniversalClient, policies LimitPolicies) (*RedisLimiter, error) {
	if client == nil || !policies.valid() {
		return nil, errors.New("desktop control rate limit configuration is invalid")
	}
	return &RedisLimiter{client: client, policies: policies}, nil
}

func (limiter *RedisLimiter) Allow(ctx context.Context, action LimitAction, principal DevicePrincipal) (time.Duration, error) {
	if limiter == nil || limiter.client == nil {
		return 0, ErrUnavailable
	}
	if err := validatePrincipal(principal); err != nil {
		return 0, err
	}
	policy, err := limiter.policy(action)
	if err != nil {
		return 0, err
	}
	result, err := incrementDesktopControlLimitScript.Run(
		ctx, limiter.client, []string{desktopControlLimitKey(action, principal)}, policy.Window.Milliseconds(),
	).Int64Slice()
	if err != nil || len(result) != 2 {
		return 0, ErrUnavailable
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

func (limiter *RedisLimiter) policy(action LimitAction) (LimitPolicy, error) {
	switch action {
	case LimitHeartbeat:
		return limiter.policies.Heartbeat, nil
	case LimitCommandResult:
		return limiter.policies.CommandResult, nil
	default:
		return LimitPolicy{}, ErrInvalidInput
	}
}

func desktopControlLimitKey(action LimitAction, principal DevicePrincipal) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("aera.desktop-control-rate-limit.v1\x00"))
	_, _ = digest.Write([]byte(action))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(principal.UserID[:])
	_, _ = digest.Write(principal.DeviceID[:])
	return redisDesktopControlLimitPrefix + hex.EncodeToString(digest.Sum(nil))
}
