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

func TestRedisLoginLimiterAppliesIdentityAndIPLimitsWithoutRawIPKeys(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("FlushDB() error = %v", err)
	}
	limiter, err := NewRedisLoginLimiter(client, bytes.Repeat([]byte{8}, 32), LoginRatePolicy{
		IdentityLimit: 2, IPLimit: 3, Window: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewRedisLoginLimiter() error = %v", err)
	}
	identity := bytes.Repeat([]byte{1}, 32)
	for attempt := 1; attempt <= 3; attempt++ {
		allowed, err := limiter.Allow(ctx, identity, "203.0.113.10")
		if err != nil {
			t.Fatalf("Allow() attempt %d error = %v", attempt, err)
		}
		if allowed != (attempt <= 2) {
			t.Fatalf("Allow() attempt %d = %v", attempt, allowed)
		}
	}
	keys, err := client.Keys(ctx, redisLoginLimitPrefix+"*").Result()
	if err != nil || len(keys) != 2 {
		t.Fatalf("login limit keys = %+v, error:%v", keys, err)
	}
	for _, key := range keys {
		if strings.Contains(key, "203.0.113.10") {
			t.Fatalf("Redis key exposes raw IP: %q", key)
		}
	}
}

func TestRedisLoginLimiterFailsClosedForInvalidInputs(t *testing.T) {
	if _, err := NewRedisLoginLimiter(nil, nil, LoginRatePolicy{}); err == nil {
		t.Fatal("NewRedisLoginLimiter() accepted invalid configuration")
	}
	limiter := &RedisLoginLimiter{}
	if _, err := limiter.Allow(context.Background(), []byte{1}, "not-an-ip"); err == nil {
		t.Fatal("Allow() accepted invalid inputs")
	}
}
