package account

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisLoginLimitPrefix = "aera-cloud:login-limit:"

var incrementLoginLimitsScript = redis.NewScript(`
	local identity_count = redis.call('INCR', KEYS[1])
	if identity_count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
	local ip_count = redis.call('INCR', KEYS[2])
	if ip_count == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[1]) end
	return {identity_count, ip_count}
`)

type LoginRatePolicy struct {
	IdentityLimit int64
	IPLimit       int64
	Window        time.Duration
}

type RedisLoginLimiter struct {
	redis   redis.UniversalClient
	hmacKey []byte
	policy  LoginRatePolicy
}

func NewRedisLoginLimiter(
	client redis.UniversalClient,
	hmacKey []byte,
	policy LoginRatePolicy,
) (*RedisLoginLimiter, error) {
	if client == nil || len(hmacKey) < 32 || policy.IdentityLimit <= 0 || policy.IPLimit <= 0 ||
		policy.IdentityLimit > policy.IPLimit || policy.Window < time.Minute || policy.Window > 24*time.Hour {
		return nil, errors.New("password login rate limit configuration is invalid")
	}
	return &RedisLoginLimiter{
		redis: client, hmacKey: append([]byte(nil), hmacKey...), policy: policy,
	}, nil
}

func (l *RedisLoginLimiter) Allow(ctx context.Context, identityHMAC []byte, rawIPAddress string) (bool, error) {
	if l == nil || l.redis == nil || len(l.hmacKey) < 32 || len(identityHMAC) != sha256.Size {
		return false, errors.New("password login rate limit request is invalid")
	}
	ipAddress := net.ParseIP(rawIPAddress)
	if ipAddress == nil {
		return false, errors.New("password login IP address is invalid")
	}
	identityKey := redisLoginLimitPrefix + "identity:" + base64.RawURLEncoding.EncodeToString(identityHMAC)
	ipKey := redisLoginLimitPrefix + "ip:" + base64.RawURLEncoding.EncodeToString(l.ipHMAC(ipAddress.String()))
	counts, err := incrementLoginLimitsScript.Run(
		ctx, l.redis, []string{identityKey, ipKey}, l.policy.Window.Milliseconds(),
	).Int64Slice()
	if err != nil || len(counts) != 2 {
		return false, errors.New("password login rate limit store is unavailable")
	}
	return counts[0] <= l.policy.IdentityLimit && counts[1] <= l.policy.IPLimit, nil
}

func (l *RedisLoginLimiter) ipHMAC(ipAddress string) []byte {
	mac := hmac.New(sha256.New, l.hmacKey)
	_, _ = mac.Write([]byte("agentera.login-ip.v1\x00"))
	_, _ = mac.Write([]byte(ipAddress))
	return mac.Sum(nil)
}
