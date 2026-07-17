package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const redisAccessStatusPrefix = "aera-cloud:session-status:"

type AccessStatus string

const (
	AccessStatusUnknown AccessStatus = ""
	AccessStatusActive  AccessStatus = "active"
	AccessStatusRevoked AccessStatus = "revoked"
)

type AccessTokenVerifier interface {
	Verify(string) (AccessClaims, error)
}

type AccessStatusRepository interface {
	AccessActive(context.Context, AccessBinding, time.Time) (bool, error)
}

type AccessStatusCache interface {
	Read(context.Context, uuid.UUID) (AccessStatus, error)
	Write(context.Context, uuid.UUID, AccessStatus, time.Duration) error
}

type AccessAuthenticatorConfig struct {
	Tokens     AccessTokenVerifier
	Repository AccessStatusRepository
	Cache      AccessStatusCache
	Clock      func() time.Time
}

type AccessAuthenticator struct {
	tokens     AccessTokenVerifier
	repository AccessStatusRepository
	cache      AccessStatusCache
	clock      func() time.Time
}

func NewAccessAuthenticator(config AccessAuthenticatorConfig) (*AccessAuthenticator, error) {
	if config.Tokens == nil || config.Repository == nil || config.Cache == nil {
		return nil, errors.New("access authenticator configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &AccessAuthenticator{
		tokens: config.Tokens, repository: config.Repository, cache: config.Cache, clock: clock,
	}, nil
}

func (a *AccessAuthenticator) Authenticate(ctx context.Context, serialized string) (AccessClaims, error) {
	if a == nil {
		return AccessClaims{}, ErrUnavailable
	}
	claims, err := a.tokens.Verify(serialized)
	if err != nil {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	now := a.clock().UTC()
	if !now.Before(claims.ExpiresAt) {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	status, err := a.cache.Read(ctx, claims.SessionID)
	if err != nil {
		return AccessClaims{}, ErrUnavailable
	}
	if status == AccessStatusRevoked {
		return AccessClaims{}, ErrSessionRevoked
	}
	if status != AccessStatusUnknown && status != AccessStatusActive {
		return AccessClaims{}, ErrUnavailable
	}

	// An active cache entry is deliberately not sufficient for authorization.
	// PostgreSQL remains authoritative so revocation takes effect immediately;
	// Redis provides a fail-closed terminal-revocation view and shared status.
	active, err := a.repository.AccessActive(ctx, claims.AccessBinding, now)
	if err != nil {
		return AccessClaims{}, ErrUnavailable
	}
	status = AccessStatusRevoked
	if active {
		status = AccessStatusActive
	}
	if err := a.cache.Write(ctx, claims.SessionID, status, claims.ExpiresAt.Sub(now)); err != nil {
		return AccessClaims{}, ErrUnavailable
	}
	if !active {
		return AccessClaims{}, ErrSessionRevoked
	}
	return claims, nil
}

type RedisAccessStatusCache struct {
	client redis.UniversalClient
}

func NewRedisAccessStatusCache(client redis.UniversalClient) *RedisAccessStatusCache {
	return &RedisAccessStatusCache{client: client}
}

func (c *RedisAccessStatusCache) Read(ctx context.Context, sessionID uuid.UUID) (AccessStatus, error) {
	if c == nil || c.client == nil || sessionID == uuid.Nil {
		return AccessStatusUnknown, errors.New("access status cache is unavailable")
	}
	value, err := c.client.Get(ctx, redisAccessStatusPrefix+sessionID.String()).Result()
	if errors.Is(err, redis.Nil) {
		return AccessStatusUnknown, nil
	}
	if err != nil {
		return AccessStatusUnknown, errors.New("access status cache is unavailable")
	}
	status := AccessStatus(value)
	if status != AccessStatusActive && status != AccessStatusRevoked {
		return AccessStatusUnknown, errors.New("access status cache contains invalid state")
	}
	return status, nil
}

func (c *RedisAccessStatusCache) Write(
	ctx context.Context,
	sessionID uuid.UUID,
	status AccessStatus,
	ttl time.Duration,
) error {
	if c == nil || c.client == nil || sessionID == uuid.Nil || ttl <= 0 ||
		(status != AccessStatusActive && status != AccessStatusRevoked) {
		return errors.New("access status cache write is invalid")
	}
	if err := c.client.Set(ctx, redisAccessStatusPrefix+sessionID.String(), string(status), ttl).Err(); err != nil {
		return errors.New("access status cache is unavailable")
	}
	return nil
}
