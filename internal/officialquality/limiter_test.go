package officialquality

import (
	"bytes"
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

func TestRedisQualityLimiterEnforcesRequestAndSubjectWindowsWithoutRawIdentity(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername,
		Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	clearQualityLimitKeys(t, ctx, client)
	defer clearQualityLimitKeys(t, context.Background(), client)

	limiter, err := NewRedisQualityLimiter(client, QualityLimitPolicies{
		Request: QualityLimitPolicy{Limit: 2, Window: time.Minute},
		Subject: QualityLimitPolicy{Limit: 3, Window: time.Hour},
	})
	if err != nil {
		t.Fatalf("NewRedisQualityLimiter() error = %v", err)
	}
	principal := validQualityPrincipal()
	subject := bytes.Repeat([]byte{0x91}, 32)
	if err := limiter.Allow(ctx, principal, PurposeMetrics, subject); err != nil {
		t.Fatalf("first Allow() error = %v", err)
	}
	if err := limiter.Allow(ctx, principal, PurposeMetrics, subject); err != nil {
		t.Fatalf("second Allow() error = %v", err)
	}
	if err := limiter.Allow(ctx, principal, PurposeMetrics, subject); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third Allow() error = %v, want ErrRateLimited", err)
	}

	keys, err := client.Keys(ctx, redisOfficialQualityLimitPrefix+"*").Result()
	if err != nil || len(keys) != 2 {
		t.Fatalf("quality limit keys = %v, error = %v", keys, err)
	}
	pattern := regexp.MustCompile("^" + regexp.QuoteMeta(redisOfficialQualityLimitPrefix) + `(request|subject):[0-9a-f]{64}$`)
	for _, key := range keys {
		if !pattern.MatchString(key) {
			t.Fatalf("quality limiter key is not bounded and hashed: %q", key)
		}
		for _, forbidden := range []string{principal.UserID.String(), principal.DeviceID.String(), PurposeMetrics} {
			if strings.Contains(key, forbidden) {
				t.Fatalf("quality limiter key %q contains %q", key, forbidden)
			}
		}
	}
}

func TestRedisQualityLimiterRejectsInvalidInputsAndFailsClosed(t *testing.T) {
	if _, err := NewRedisQualityLimiter(nil, QualityLimitPolicies{}); err == nil {
		t.Fatal("NewRedisQualityLimiter() accepted invalid configuration")
	}
	limiter := &RedisQualityLimiter{}
	if err := limiter.Allow(context.Background(), Principal{UserID: uuid.New()}, PurposeMetrics, []byte{1}); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("Allow() error = %v, want ErrServiceUnavailable", err)
	}
}

func clearQualityLimitKeys(t *testing.T, ctx context.Context, client redis.UniversalClient) {
	t.Helper()
	keys, err := client.Keys(ctx, redisOfficialQualityLimitPrefix+"*").Result()
	if err != nil {
		t.Fatalf("list quality limiter keys: %v", err)
	}
	if len(keys) > 0 {
		if err := client.Del(ctx, keys...).Err(); err != nil {
			t.Fatalf("clear quality limiter keys: %v", err)
		}
	}
}
