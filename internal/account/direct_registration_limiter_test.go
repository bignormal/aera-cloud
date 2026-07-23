package account

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/redis/go-redis/v9"
)

func TestRedisDirectRegistrationLimiterAppliesIPLimitWithoutRawIPKeys(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername,
		Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("FlushDB() error = %v", err)
	}
	limiter, err := NewRedisDirectRegistrationLimiter(
		client,
		bytes.Repeat([]byte{8}, 32),
		DirectRegistrationRatePolicy{IPLimit: 2, Window: time.Minute},
	)
	if err != nil {
		t.Fatalf("NewRedisDirectRegistrationLimiter() error = %v", err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		allowed, err := limiter.Allow(ctx, "203.0.113.10")
		if err != nil {
			t.Fatalf("Allow() attempt %d error = %v", attempt, err)
		}
		if allowed != (attempt <= 2) {
			t.Fatalf("Allow() attempt %d = %v", attempt, allowed)
		}
	}
	keys, err := client.Keys(ctx, redisDirectRegistrationLimitPrefix+"*").Result()
	if err != nil || len(keys) != 1 {
		t.Fatalf("direct registration limit keys = %+v, error:%v", keys, err)
	}
	if strings.Contains(keys[0], "203.0.113.10") {
		t.Fatalf("Redis key exposes raw IP: %q", keys[0])
	}
}

func TestRedisDirectRegistrationLimiterFailsClosedForInvalidInputs(t *testing.T) {
	if _, err := NewRedisDirectRegistrationLimiter(nil, nil, DirectRegistrationRatePolicy{}); err == nil {
		t.Fatal("NewRedisDirectRegistrationLimiter() accepted invalid configuration")
	}
	limiter := &RedisDirectRegistrationLimiter{}
	if _, err := limiter.Allow(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("Allow() accepted invalid inputs")
	}
}
