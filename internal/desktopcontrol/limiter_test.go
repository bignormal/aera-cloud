package desktopcontrol

import (
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

func TestRedisLimiterSeparatesActionsAndHashesDeviceIdentity(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername,
		Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	clearDesktopControlLimitKeys(t, ctx, client)
	defer clearDesktopControlLimitKeys(t, context.Background(), client)

	limiter, err := NewRedisLimiter(client, LimitPolicies{
		Heartbeat:     LimitPolicy{Limit: 2, Window: time.Minute},
		CommandResult: LimitPolicy{Limit: 1, Window: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewRedisLimiter() error = %v", err)
	}
	principal := DevicePrincipal{UserID: uuid.New(), DeviceID: uuid.New()}
	for attempt := 0; attempt < 2; attempt++ {
		if retry, err := limiter.Allow(ctx, LimitHeartbeat, principal); err != nil || retry != 0 {
			t.Fatalf("heartbeat Allow(%d) = %s/%v", attempt, retry, err)
		}
	}
	if retry, err := limiter.Allow(ctx, LimitHeartbeat, principal); !errors.Is(err, ErrRateLimited) || retry <= 0 {
		t.Fatalf("limited heartbeat = %s/%v", retry, err)
	}
	if retry, err := limiter.Allow(ctx, LimitCommandResult, principal); err != nil || retry != 0 {
		t.Fatalf("independent result limit = %s/%v", retry, err)
	}

	keys, err := client.Keys(ctx, redisDesktopControlLimitPrefix+"*").Result()
	if err != nil || len(keys) != 2 {
		t.Fatalf("desktop control limit keys = %v error=%v", keys, err)
	}
	pattern := regexp.MustCompile("^" + regexp.QuoteMeta(redisDesktopControlLimitPrefix) + `[0-9a-f]{64}$`)
	for _, key := range keys {
		if !pattern.MatchString(key) || strings.Contains(key, principal.UserID.String()) || strings.Contains(key, principal.DeviceID.String()) {
			t.Fatalf("desktop control limiter key is not bounded and hashed: %q", key)
		}
	}
}

func TestRedisLimiterRejectsInvalidConfigurationAndFailsClosed(t *testing.T) {
	if _, err := NewRedisLimiter(nil, LimitPolicies{}); err == nil {
		t.Fatal("NewRedisLimiter() accepted invalid configuration")
	}
	limiter := &RedisLimiter{}
	if _, err := limiter.Allow(context.Background(), LimitHeartbeat, DevicePrincipal{UserID: uuid.New(), DeviceID: uuid.New()}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Allow() error = %v, want ErrUnavailable", err)
	}
}

func clearDesktopControlLimitKeys(t *testing.T, ctx context.Context, client redis.UniversalClient) {
	t.Helper()
	keys, err := client.Keys(ctx, redisDesktopControlLimitPrefix+"*").Result()
	if err != nil {
		t.Fatalf("list Desktop control limiter keys: %v", err)
	}
	if len(keys) > 0 {
		if err := client.Del(ctx, keys...).Err(); err != nil {
			t.Fatalf("clear Desktop control limiter keys: %v", err)
		}
	}
}
