package verification

import (
	"context"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/redis/go-redis/v9"
)

func TestRedisLimiterCountsAtomicallyAndEscalatesBeforeDenial(t *testing.T) {
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
	limiter := NewRedisLimiter(client)
	policy := Policy{Limit: 3, CaptchaAfter: 2, Window: time.Minute}

	first, err := limiter.Allow(ctx, "identity:test", policy)
	if err != nil {
		t.Fatalf("first Allow() error = %v", err)
	}
	if !first.Allowed || first.CaptchaRequired {
		t.Fatalf("first decision = %+v", first)
	}
	second, err := limiter.Allow(ctx, "identity:test", policy)
	if err != nil {
		t.Fatalf("second Allow() error = %v", err)
	}
	if !second.Allowed || second.CaptchaRequired {
		t.Fatalf("second decision = %+v", second)
	}
	third, err := limiter.Allow(ctx, "identity:test", policy)
	if err != nil {
		t.Fatalf("third Allow() error = %v", err)
	}
	if !third.Allowed || !third.CaptchaRequired {
		t.Fatalf("third decision = %+v, want CAPTCHA escalation", third)
	}
	fourth, err := limiter.Allow(ctx, "identity:test", policy)
	if err != nil {
		t.Fatalf("fourth Allow() error = %v", err)
	}
	if fourth.Allowed || !fourth.CaptchaRequired || fourth.RetryAfter <= 0 || fourth.RetryAfter > time.Minute {
		t.Fatalf("fourth decision = %+v, want denial with bounded retry", fourth)
	}
}

func TestRedisDeliveryGuardUsesOwnerCheckedRelease(t *testing.T) {
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
	guard := NewRedisDeliveryGuard(client)

	acquired, err := guard.Acquire(ctx, "request:test", "owner-a", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("first Acquire() = %v, %v", acquired, err)
	}
	acquired, err = guard.Acquire(ctx, "request:test", "owner-b", time.Minute)
	if err != nil || acquired {
		t.Fatalf("second Acquire() = %v, %v", acquired, err)
	}
	if err := guard.Release(ctx, "request:test", "owner-b"); err != nil {
		t.Fatalf("wrong-owner Release() error = %v", err)
	}
	acquired, err = guard.Acquire(ctx, "request:test", "owner-b", time.Minute)
	if err != nil || acquired {
		t.Fatalf("Acquire() after wrong-owner release = %v, %v", acquired, err)
	}
	if err := guard.Release(ctx, "request:test", "owner-a"); err != nil {
		t.Fatalf("owner Release() error = %v", err)
	}
	acquired, err = guard.Acquire(ctx, "request:test", "owner-b", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("Acquire() after owner release = %v, %v", acquired, err)
	}
}

func TestRedisControlsRejectInvalidInputsWithoutCallingRedis(t *testing.T) {
	limiter := NewRedisLimiter(nil)
	if _, err := limiter.Allow(context.Background(), "", Policy{}); err == nil {
		t.Fatal("Allow() accepted invalid key and policy")
	}
	guard := NewRedisDeliveryGuard(nil)
	if _, err := guard.Acquire(context.Background(), "", "", 0); err == nil {
		t.Fatal("Acquire() accepted invalid inputs")
	}
	if err := guard.Release(context.Background(), "", ""); err == nil {
		t.Fatal("Release() accepted invalid inputs")
	}
}
