package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func OpenPostgres(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("PostgreSQL configuration is invalid")
	}
	poolConfig.MaxConns = 8
	poolConfig.MinConns = 0
	poolConfig.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("PostgreSQL pool could not be created")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("PostgreSQL is unavailable")
	}
	return pool, nil
}
