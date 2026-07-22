package officialquality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisOfficialQualityLimitPrefix = "aera-cloud:official-quality-limit:"

var incrementOfficialQualityLimitsScript = redis.NewScript(`
	local request_count = redis.call('INCR', KEYS[1])
	if request_count == 1 then
		redis.call('PEXPIRE', KEYS[1], ARGV[1])
	end
	local subject_count = redis.call('INCR', KEYS[2])
	if subject_count == 1 then
		redis.call('PEXPIRE', KEYS[2], ARGV[2])
	end
	return {request_count, subject_count}
`)

type QualityLimitPolicy struct {
	Limit  int64
	Window time.Duration
}

func (p QualityLimitPolicy) valid() bool {
	return p.Limit > 0 && p.Window >= time.Millisecond
}

type QualityLimitPolicies struct {
	Request QualityLimitPolicy
	Subject QualityLimitPolicy
}

func (p QualityLimitPolicies) valid() bool {
	return p.Request.valid() && p.Subject.valid()
}

func DefaultQualityLimitPolicies() QualityLimitPolicies {
	return QualityLimitPolicies{
		Request: QualityLimitPolicy{Limit: 120, Window: time.Hour},
		Subject: QualityLimitPolicy{Limit: 40, Window: 24 * time.Hour},
	}
}

type RedisQualityLimiter struct {
	client   redis.UniversalClient
	policies QualityLimitPolicies
}

func NewRedisQualityLimiter(
	client redis.UniversalClient,
	policies QualityLimitPolicies,
) (*RedisQualityLimiter, error) {
	if client == nil || !policies.valid() {
		return nil, errors.New("official quality rate limit configuration is invalid")
	}
	return &RedisQualityLimiter{client: client, policies: policies}, nil
}

func (l *RedisQualityLimiter) Allow(
	ctx context.Context,
	principal Principal,
	purpose string,
	subjectPseudonym []byte,
) error {
	if l == nil || l.client == nil {
		return ErrServiceUnavailable
	}
	if !principal.valid() || !validPurpose(purpose) || len(subjectPseudonym) != sha256.Size || !l.policies.valid() {
		return ErrInvalidRequest
	}
	requestKey := qualityLimitKey("request", purpose, principal.UserID[:], principal.DeviceID[:])
	subjectKey := qualityLimitKey("subject", purpose, subjectPseudonym)
	result, err := incrementOfficialQualityLimitsScript.Run(
		ctx,
		l.client,
		[]string{requestKey, subjectKey},
		l.policies.Request.Window.Milliseconds(),
		l.policies.Subject.Window.Milliseconds(),
	).Int64Slice()
	if err != nil || len(result) != 2 {
		return ErrServiceUnavailable
	}
	if result[0] > l.policies.Request.Limit || result[1] > l.policies.Subject.Limit {
		return ErrRateLimited
	}
	return nil
}

func qualityLimitKey(scope, purpose string, parts ...[]byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("agentera.official-quality-rate-limit.v1\x00" + scope + "\x00" + purpose))
	for _, part := range parts {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(part)
	}
	return redisOfficialQualityLimitPrefix + scope + ":" + hex.EncodeToString(digest.Sum(nil))
}
