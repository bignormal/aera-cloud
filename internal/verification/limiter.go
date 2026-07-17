package verification

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisLimitPrefix = "aera-cloud:verification:limit:"
	redisLeasePrefix = "aera-cloud:verification:delivery:"
)

var (
	incrementWindowScript = redis.NewScript(`
		local count = redis.call('INCR', KEYS[1])
		if count == 1 then
			redis.call('PEXPIRE', KEYS[1], ARGV[1])
		end
		local ttl = redis.call('PTTL', KEYS[1])
		return {count, ttl}
	`)
	releaseLeaseScript = redis.NewScript(`
		if redis.call('GET', KEYS[1]) == ARGV[1] then
			return redis.call('DEL', KEYS[1])
		end
		return 0
	`)
)

type Policy struct {
	Limit        int64
	CaptchaAfter int64
	Window       time.Duration
}

type Decision struct {
	Allowed         bool
	CaptchaRequired bool
	RetryAfter      time.Duration
}

type ScopePolicies struct {
	Identity Policy
	IP       Policy
	Device   Policy
}

func DefaultScopePolicies() ScopePolicies {
	return ScopePolicies{
		Identity: Policy{Limit: 5, CaptchaAfter: 3, Window: 10 * time.Minute},
		IP:       Policy{Limit: 20, CaptchaAfter: 10, Window: time.Hour},
		Device:   Policy{Limit: 10, CaptchaAfter: 5, Window: 10 * time.Minute},
	}
}

func (p ScopePolicies) valid() bool {
	return validPolicy(p.Identity) && validPolicy(p.IP) && validPolicy(p.Device)
}

func validPolicy(policy Policy) bool {
	return policy.Limit > 0 && policy.CaptchaAfter > 0 && policy.CaptchaAfter <= policy.Limit && policy.Window > 0
}

type RedisLimiter struct {
	client redis.UniversalClient
}

func NewRedisLimiter(client redis.UniversalClient) *RedisLimiter {
	return &RedisLimiter{client: client}
}

func (l *RedisLimiter) Allow(ctx context.Context, key string, policy Policy) (Decision, error) {
	if l == nil || l.client == nil || strings.TrimSpace(key) == "" || !validPolicy(policy) {
		return Decision{}, errors.New("verification limit request is invalid")
	}
	result, err := incrementWindowScript.Run(
		ctx,
		l.client,
		[]string{redisLimitPrefix + key},
		policy.Window.Milliseconds(),
	).Int64Slice()
	if err != nil || len(result) != 2 {
		return Decision{}, errors.New("verification limit store is unavailable")
	}
	retryAfter := time.Duration(result[1]) * time.Millisecond
	if retryAfter < 0 {
		retryAfter = policy.Window
	}
	if retryAfter > policy.Window {
		retryAfter = policy.Window
	}
	return Decision{
		Allowed:         result[0] <= policy.Limit,
		CaptchaRequired: result[0] > policy.CaptchaAfter,
		RetryAfter:      retryAfter,
	}, nil
}

type RedisDeliveryGuard struct {
	client redis.UniversalClient
}

func NewRedisDeliveryGuard(client redis.UniversalClient) *RedisDeliveryGuard {
	return &RedisDeliveryGuard{client: client}
}

func (g *RedisDeliveryGuard) Acquire(ctx context.Context, key, owner string, ttl time.Duration) (bool, error) {
	if g == nil || g.client == nil || strings.TrimSpace(key) == "" || strings.TrimSpace(owner) == "" || ttl <= 0 {
		return false, errors.New("verification delivery lease request is invalid")
	}
	acquired, err := g.client.SetNX(ctx, redisLeasePrefix+key, owner, ttl).Result()
	if err != nil {
		return false, errors.New("verification delivery lease store is unavailable")
	}
	return acquired, nil
}

func (g *RedisDeliveryGuard) Release(ctx context.Context, key, owner string) error {
	if g == nil || g.client == nil || strings.TrimSpace(key) == "" || strings.TrimSpace(owner) == "" {
		return errors.New("verification delivery lease release is invalid")
	}
	if _, err := releaseLeaseScript.Run(ctx, g.client, []string{redisLeasePrefix + key}, owner).Int64(); err != nil {
		return errors.New("verification delivery lease store is unavailable")
	}
	return nil
}
