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

const redisDirectRegistrationLimitPrefix = "aera-cloud:direct-registration-limit:"

var incrementDirectRegistrationLimitScript = redis.NewScript(`
	local count = redis.call('INCR', KEYS[1])
	if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
	return count
`)

type DirectRegistrationRatePolicy struct {
	IPLimit int64
	Window  time.Duration
}

type RedisDirectRegistrationLimiter struct {
	redis   redis.UniversalClient
	hmacKey []byte
	policy  DirectRegistrationRatePolicy
}

func NewRedisDirectRegistrationLimiter(
	client redis.UniversalClient,
	hmacKey []byte,
	policy DirectRegistrationRatePolicy,
) (*RedisDirectRegistrationLimiter, error) {
	if client == nil || len(hmacKey) < 32 || policy.IPLimit <= 0 ||
		policy.Window < time.Second || policy.Window > 24*time.Hour {
		return nil, errors.New("direct registration rate limit configuration is invalid")
	}
	return &RedisDirectRegistrationLimiter{
		redis: client, hmacKey: append([]byte(nil), hmacKey...), policy: policy,
	}, nil
}

func (l *RedisDirectRegistrationLimiter) Allow(
	ctx context.Context,
	rawIPAddress string,
) (bool, error) {
	if l == nil || l.redis == nil || len(l.hmacKey) < 32 {
		return false, errors.New("direct registration rate limit request is invalid")
	}
	ipAddress := net.ParseIP(rawIPAddress)
	if ipAddress == nil {
		return false, errors.New("direct registration IP address is invalid")
	}
	key := redisDirectRegistrationLimitPrefix +
		base64.RawURLEncoding.EncodeToString(l.ipHMAC(ipAddress.String()))
	count, err := incrementDirectRegistrationLimitScript.Run(
		ctx,
		l.redis,
		[]string{key},
		l.policy.Window.Milliseconds(),
	).Int64()
	if err != nil {
		return false, errors.New("direct registration rate limit store is unavailable")
	}
	return count <= l.policy.IPLimit, nil
}

func (l *RedisDirectRegistrationLimiter) ipHMAC(ipAddress string) []byte {
	mac := hmac.New(sha256.New, l.hmacKey)
	_, _ = mac.Write([]byte("agentera.direct-registration-ip.v1\x00"))
	_, _ = mac.Write([]byte(ipAddress))
	return mac.Sum(nil)
}
