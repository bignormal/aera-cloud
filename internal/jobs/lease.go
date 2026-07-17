package jobs

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisMaintenanceLeasePrefix = "aera-cloud:maintenance:lease:"

var releaseMaintenanceLeaseScript = redis.NewScript(`
	if redis.call('GET', KEYS[1]) == ARGV[1] then
		return redis.call('DEL', KEYS[1])
	end
	return 0
`)

type RedisLease struct {
	client redis.UniversalClient
}

func NewRedisLease(client redis.UniversalClient) *RedisLease {
	return &RedisLease{client: client}
}

func (l *RedisLease) Acquire(ctx context.Context, key, owner string, ttl time.Duration) (bool, error) {
	if l == nil || l.client == nil || strings.TrimSpace(key) == "" || strings.TrimSpace(owner) == "" || ttl <= 0 {
		return false, ErrLeaseUnavailable
	}
	acquired, err := l.client.SetNX(ctx, redisMaintenanceLeasePrefix+key, owner, ttl).Result()
	if err != nil {
		return false, ErrLeaseUnavailable
	}
	return acquired, nil
}

func (l *RedisLease) Release(ctx context.Context, key, owner string) error {
	if l == nil || l.client == nil || strings.TrimSpace(key) == "" || strings.TrimSpace(owner) == "" {
		return ErrLeaseUnavailable
	}
	if _, err := releaseMaintenanceLeaseScript.Run(
		ctx, l.client, []string{redisMaintenanceLeasePrefix + key}, owner,
	).Int64(); err != nil {
		return errors.Join(ErrLeaseUnavailable, err)
	}
	return nil
}
