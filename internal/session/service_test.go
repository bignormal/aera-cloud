package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/entitlement"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRefreshRotationExtendsThirtyDaysAndStoresOnlyHash(t *testing.T) {
	fixture := newSessionFixture(t)
	binding := fixture.binding(t)
	initial, err := fixture.service.Start(fixture.ctx, binding)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if initial.RefreshExpiresAt != fixture.now.Add(30*24*time.Hour) || initial.AccessToken == "" || initial.OfflineEntitlement == "" {
		t.Fatalf("initial tokens = %+v", initial)
	}
	var storedHash []byte
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT refresh_token_hash FROM sessions WHERE id = $1`, initial.SessionID).Scan(&storedHash); err != nil {
		t.Fatalf("read refresh hash: %v", err)
	}
	if len(storedHash) != 32 || bytes.Contains(storedHash, []byte(initial.RefreshToken)) {
		t.Fatalf("stored refresh hash length=%d contains token=%v", len(storedHash), bytes.Contains(storedHash, []byte(initial.RefreshToken)))
	}

	fixture.now = fixture.now.Add(24 * time.Hour)
	rotated, err := fixture.service.Refresh(fixture.ctx, initial.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if rotated.RefreshToken == initial.RefreshToken || rotated.RefreshExpiresAt != fixture.now.Add(30*24*time.Hour) || rotated.SessionID == initial.SessionID {
		t.Fatalf("rotated tokens = %+v", rotated)
	}
	var replacedAt pgtype.Timestamptz
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT replaced_at FROM sessions WHERE id = $1`, initial.SessionID).Scan(&replacedAt); err != nil {
		t.Fatalf("read replacement state: %v", err)
	}
	if !replacedAt.Valid || !replacedAt.Time.Equal(fixture.now) {
		t.Fatalf("replaced_at = %+v", replacedAt)
	}
}

func TestRefreshRejectsNonCanonicalTokenAlias(t *testing.T) {
	fixture := newSessionFixture(t)
	initial, err := fixture.service.Start(fixture.ctx, fixture.binding(t))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	alias := testkit.NonCanonicalBase64URLAlias(t, initial.RefreshToken)
	if _, err := fixture.service.Refresh(fixture.ctx, alias); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Refresh(noncanonical alias) error = %v", err)
	}
}

func TestRefreshReportsUnavailableAccountStateBeforeGenericRevocation(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   error
	}{
		{name: "pending deletion", status: "pending_deletion", want: ErrAccountPendingDeletion},
		{name: "disabled", status: "disabled", want: ErrAccountDisabled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSessionFixture(t)
			binding := fixture.binding(t)
			initial, err := fixture.service.Start(fixture.ctx, binding)
			if err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			if _, err := fixture.postgres.Exec(fixture.ctx, `
				UPDATE users
				SET status = $2::text,
					deletion_requested_at = CASE WHEN $2::text = 'pending_deletion' THEN $3::timestamptz ELSE NULL::timestamptz END,
					updated_at = $3
				WHERE id = $1
			`, binding.UserID, test.status, fixture.now); err != nil {
				t.Fatalf("set account state: %v", err)
			}
			if _, err := fixture.postgres.Exec(fixture.ctx, `
				UPDATE devices SET status = 'revoked', revoked_at = $2, updated_at = $2 WHERE id = $1
			`, binding.DeviceID, fixture.now); err != nil {
				t.Fatalf("revoke account device: %v", err)
			}
			if _, err := fixture.postgres.Exec(fixture.ctx, `
				UPDATE sessions SET revoked_at = $2, revoked_reason = 'account_state' WHERE id = $1
			`, initial.SessionID, fixture.now); err != nil {
				t.Fatalf("revoke account session: %v", err)
			}
			if _, err := fixture.service.Refresh(fixture.ctx, initial.RefreshToken); !errors.Is(err, test.want) {
				t.Fatalf("Refresh(%s) error = %v", test.status, err)
			}
		})
	}
}

func TestRefreshReuseRevokesWholeFamily(t *testing.T) {
	fixture := newSessionFixture(t)
	initial, err := fixture.service.Start(fixture.ctx, fixture.binding(t))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	fixture.now = fixture.now.Add(time.Hour)
	if _, err := fixture.service.Refresh(fixture.ctx, initial.RefreshToken); err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}
	fixture.now = fixture.now.Add(time.Minute)
	if _, err := fixture.service.Refresh(fixture.ctx, initial.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("replayed Refresh() error = %v", err)
	}
	var total int64
	var revoked int64
	var replayed int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*), count(*) FILTER (WHERE revoked_at IS NOT NULL),
			count(*) FILTER (WHERE replay_detected_at IS NOT NULL)
		FROM sessions WHERE family_id = (SELECT family_id FROM sessions WHERE id = $1)
	`, initial.SessionID).Scan(&total, &revoked, &replayed); err != nil {
		t.Fatalf("read family state: %v", err)
	}
	if total != 2 || revoked != 2 || replayed != 1 {
		t.Fatalf("family total=%d revoked=%d replayed=%d", total, revoked, replayed)
	}
}

func TestConcurrentRefreshHasOneWinner(t *testing.T) {
	fixture := newSessionFixture(t)
	initial, err := fixture.service.Start(fixture.ctx, fixture.binding(t))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	fixture.now = fixture.now.Add(time.Hour)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := fixture.service.Refresh(fixture.ctx, initial.RefreshToken)
			results <- err
		}()
	}
	close(start)
	successes := 0
	revoked := 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrSessionRevoked):
			revoked++
		default:
			t.Fatalf("concurrent Refresh() error = %v", err)
		}
	}
	if successes != 1 || revoked != 1 {
		t.Fatalf("concurrent results successes=%d revoked=%d", successes, revoked)
	}
	var sessions int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 2 {
		t.Fatalf("sessions = %d, want one original and one successor", sessions)
	}
}

type sessionFixture struct {
	ctx         context.Context
	postgres    *pgxpool.Pool
	service     *Service
	access      *fakeAccessIssuer
	entitlement *fakeEntitlementIssuer
	now         time.Time
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	t.Cleanup(postgres.Close)
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE offline_entitlement_issuances, sessions, devices, personal_spaces, users CASCADE`); err != nil {
		t.Fatalf("truncate session tables: %v", err)
	}
	fixture := &sessionFixture{
		ctx: ctx, postgres: postgres, access: &fakeAccessIssuer{}, entitlement: &fakeEntitlementIssuer{},
		now: time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC),
	}
	service, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), AccessTokens: fixture.access, OfflineEntitlements: fixture.entitlement,
		RefreshHMACKey: bytes.Repeat([]byte{4}, 32), Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

func (f *sessionFixture) binding(t *testing.T) Binding {
	t.Helper()
	binding := Binding{
		UserID: uuid.New(), DeviceID: uuid.New(), InstallationID: uuid.New(), PersonalSpaceID: uuid.New(),
	}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)
	`, binding.UserID, f.now); err != nil {
		t.Fatalf("insert session user: %v", err)
	}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, binding.PersonalSpaceID, binding.UserID, f.now); err != nil {
		t.Fatalf("insert session personal space: %v", err)
	}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Test Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, binding.DeviceID, binding.UserID, binding.InstallationID, bytes.Repeat([]byte{9}, 32), f.now); err != nil {
		t.Fatalf("insert session device: %v", err)
	}
	return binding
}

type fakeAccessIssuer struct{}

func (*fakeAccessIssuer) Issue(binding AccessBinding) (IssuedAccessToken, error) {
	return IssuedAccessToken{Serialized: "access-" + binding.SessionID.String(), ExpiresAt: time.Now().Add(15 * time.Minute)}, nil
}

type fakeEntitlementIssuer struct{}

func (*fakeEntitlementIssuer) Issue(_ context.Context, binding entitlement.Binding) (entitlement.Issued, error) {
	return entitlement.Issued{Serialized: "offline-" + binding.DeviceID.String(), ExpiresAt: time.Now().Add(7 * 24 * time.Hour)}, nil
}

func (f *fakeEntitlementIssuer) IssueInTx(_ context.Context, _ pgx.Tx, binding entitlement.Binding) (entitlement.Issued, error) {
	return f.Issue(context.Background(), binding)
}
