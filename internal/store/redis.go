package store

import (
	"context"
	"errors"
	"strings"

	"github.com/redis/go-redis/v9"
)

type RedisOptions struct {
	Addr     string
	Username string
	Password string
	DB       int
}

type RedisStore struct {
	client *redis.Client
}

func OpenRedis(ctx context.Context, options RedisOptions) (*RedisStore, error) {
	if strings.TrimSpace(options.Addr) == "" || strings.TrimSpace(options.Username) == "" || options.Password == "" {
		return nil, errors.New("Redis configuration is incomplete")
	}
	client := redis.NewClient(&redis.Options{
		Addr:     options.Addr,
		Username: options.Username,
		Password: options.Password,
		DB:       options.DB,
	})
	store := &RedisStore{client: client}
	if err := store.Ping(ctx); err != nil {
		_ = client.Close()
		return nil, errors.New("Redis is unavailable")
	}
	return store, nil
}

func (s *RedisStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func (s *RedisStore) Close() error {
	return s.client.Close()
}
