package store

import (
	"context"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
)

func TestOpenPostgresAndRedis(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := postgres.Ping(ctx); err != nil {
		t.Fatalf("PostgreSQL Ping() error = %v", err)
	}

	redisStore, err := OpenRedis(ctx, RedisOptions{
		Addr:     services.RedisAddr,
		Username: services.RedisUsername,
		Password: services.RedisPassword,
		DB:       services.RedisDB,
	})
	if err != nil {
		t.Fatalf("OpenRedis() error = %v", err)
	}
	defer func() {
		if err := redisStore.Close(); err != nil {
			t.Errorf("Redis Close() error = %v", err)
		}
	}()
	if err := redisStore.Ping(ctx); err != nil {
		t.Fatalf("Redis Ping() error = %v", err)
	}
}
