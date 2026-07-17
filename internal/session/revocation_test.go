package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
)

func TestAccessAuthenticationVerifiesTokenBeforeRevocationState(t *testing.T) {
	verifier := &stubAccessVerifier{err: ErrInvalidAccessToken}
	repository := &stubAccessStatusRepository{active: true}
	cache := &stubAccessStatusCache{status: AccessStatusActive}
	authenticator, err := NewAccessAuthenticator(AccessAuthenticatorConfig{
		Tokens: verifier, Repository: repository, Cache: cache,
	})
	if err != nil {
		t.Fatalf("NewAccessAuthenticator() error = %v", err)
	}

	if _, err := authenticator.Authenticate(context.Background(), "altered"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if cache.readCalls != 0 || repository.calls != 0 {
		t.Fatalf("revocation state consulted before signature verification: cache=%d repository=%d", cache.readCalls, repository.calls)
	}
}

func TestAccessAuthenticationFailsClosedWhenRedisIsUnavailable(t *testing.T) {
	claims := validAccessClaims()
	authenticator, err := NewAccessAuthenticator(AccessAuthenticatorConfig{
		Tokens: &stubAccessVerifier{claims: claims}, Repository: &stubAccessStatusRepository{active: true},
		Cache: &stubAccessStatusCache{readErr: errors.New("redis unavailable")},
	})
	if err != nil {
		t.Fatalf("NewAccessAuthenticator() error = %v", err)
	}

	if _, err := authenticator.Authenticate(context.Background(), "signed"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Authenticate() error = %v", err)
	}
}

func TestAccessAuthenticationRejectsCachedRevocationWithoutDatabaseRead(t *testing.T) {
	claims := validAccessClaims()
	repository := &stubAccessStatusRepository{active: true}
	authenticator, err := NewAccessAuthenticator(AccessAuthenticatorConfig{
		Tokens: &stubAccessVerifier{claims: claims}, Repository: repository,
		Cache: &stubAccessStatusCache{status: AccessStatusRevoked},
	})
	if err != nil {
		t.Fatalf("NewAccessAuthenticator() error = %v", err)
	}

	if _, err := authenticator.Authenticate(context.Background(), "signed"); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want 0 for a cached terminal revocation", repository.calls)
	}
}

func TestPostgresRemainsAuthoritativeOverCachedActiveState(t *testing.T) {
	claims := validAccessClaims()
	cache := &stubAccessStatusCache{status: AccessStatusActive}
	repository := &stubAccessStatusRepository{active: false}
	authenticator, err := NewAccessAuthenticator(AccessAuthenticatorConfig{
		Tokens: &stubAccessVerifier{claims: claims}, Repository: repository, Cache: cache,
	})
	if err != nil {
		t.Fatalf("NewAccessAuthenticator() error = %v", err)
	}

	if _, err := authenticator.Authenticate(context.Background(), "signed"); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if repository.calls != 1 || cache.written != AccessStatusRevoked {
		t.Fatalf("authority/cache calls=%d written=%q", repository.calls, cache.written)
	}
}

func TestAccessAuthenticationCachesAuthoritativeActiveState(t *testing.T) {
	claims := validAccessClaims()
	cache := &stubAccessStatusCache{status: AccessStatusUnknown}
	authenticator, err := NewAccessAuthenticator(AccessAuthenticatorConfig{
		Tokens: &stubAccessVerifier{claims: claims}, Repository: &stubAccessStatusRepository{active: true}, Cache: cache,
		Clock: func() time.Time { return claims.IssuedAt.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("NewAccessAuthenticator() error = %v", err)
	}

	got, err := authenticator.Authenticate(context.Background(), "signed")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got != claims || cache.written != AccessStatusActive || cache.ttl != 14*time.Minute {
		t.Fatalf("claims/cache = %+v status=%q ttl=%s", got, cache.written, cache.ttl)
	}
}

func TestPostgresAccessStatusReflectsImmediateRevocation(t *testing.T) {
	fixture := newSessionFixture(t)
	binding := fixture.binding(t)
	tokens, err := fixture.service.Start(fixture.ctx, binding)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	repository := NewPostgresRepository(fixture.postgres)
	accessBinding := AccessBinding{
		UserID: binding.UserID, SessionID: tokens.SessionID,
		DeviceID: binding.DeviceID, PersonalSpaceID: binding.PersonalSpaceID,
	}
	active, err := repository.AccessActive(fixture.ctx, accessBinding, fixture.now)
	if err != nil || !active {
		t.Fatalf("AccessActive(before revoke) = %v, %v", active, err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE sessions SET revoked_at = $2, revoked_reason = 'test' WHERE id = $1
	`, tokens.SessionID, fixture.now.Add(time.Second)); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	active, err = repository.AccessActive(fixture.ctx, accessBinding, fixture.now.Add(2*time.Second))
	if err != nil || active {
		t.Fatalf("AccessActive(after revoke) = %v, %v", active, err)
	}
}

func TestRedisAccessStatusCacheRoundTripAndCorruptionFailure(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	redisStore, err := store.OpenRedis(ctx, store.RedisOptions{
		Addr: services.RedisAddr, Username: services.RedisUsername,
		Password: services.RedisPassword, DB: services.RedisDB,
	})
	if err != nil {
		t.Fatalf("OpenRedis() error = %v", err)
	}
	t.Cleanup(func() { _ = redisStore.Close() })

	cache := NewRedisAccessStatusCache(redisStore.Client())
	sessionID := uuid.New()
	key := redisAccessStatusPrefix + sessionID.String()
	t.Cleanup(func() { _ = redisStore.Client().Del(context.Background(), key).Err() })
	status, err := cache.Read(ctx, sessionID)
	if err != nil || status != AccessStatusUnknown {
		t.Fatalf("Read(missing) = %q, %v", status, err)
	}
	if err := cache.Write(ctx, sessionID, AccessStatusActive, time.Minute); err != nil {
		t.Fatalf("Write(active) error = %v", err)
	}
	status, err = cache.Read(ctx, sessionID)
	if err != nil || status != AccessStatusActive {
		t.Fatalf("Read(active) = %q, %v", status, err)
	}
	if err := redisStore.Client().Set(ctx, key, "corrupt", time.Minute).Err(); err != nil {
		t.Fatalf("seed corrupt cache: %v", err)
	}
	if _, err := cache.Read(ctx, sessionID); err == nil {
		t.Fatal("Read(corrupt) error = nil")
	}
}

func validAccessClaims() AccessClaims {
	issuedAt := time.Date(2026, 7, 18, 4, 0, 0, 0, time.UTC)
	return AccessClaims{
		AccessBinding: AccessBinding{
			UserID: uuid.New(), SessionID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New(),
		},
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(15 * time.Minute),
	}
}

type stubAccessVerifier struct {
	claims AccessClaims
	err    error
}

func (s *stubAccessVerifier) Verify(string) (AccessClaims, error) {
	return s.claims, s.err
}

type stubAccessStatusRepository struct {
	active bool
	err    error
	calls  int
}

func (s *stubAccessStatusRepository) AccessActive(context.Context, AccessBinding, time.Time) (bool, error) {
	s.calls++
	return s.active, s.err
}

type stubAccessStatusCache struct {
	status    AccessStatus
	readErr   error
	writeErr  error
	readCalls int
	written   AccessStatus
	ttl       time.Duration
}

func (s *stubAccessStatusCache) Read(context.Context, uuid.UUID) (AccessStatus, error) {
	s.readCalls++
	return s.status, s.readErr
}

func (s *stubAccessStatusCache) Write(_ context.Context, _ uuid.UUID, status AccessStatus, ttl time.Duration) error {
	s.written = status
	s.ttl = ttl
	return s.writeErr
}
