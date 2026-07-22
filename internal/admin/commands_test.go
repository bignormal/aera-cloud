package admin

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestRestrictedCommandsRequireExplicitOperatorAndAuditEveryMutation(t *testing.T) {
	now := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	repository := &fakeRepository{}
	commands, err := NewCommands(repository, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewCommands() error = %v", err)
	}
	userID := uuid.New()
	sessionID := uuid.New()

	if err := commands.DisableAccount(context.Background(), "", userID); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("DisableAccount(empty operator) error = %v", err)
	}
	if err := commands.DisableAccount(context.Background(), "operator-01", userID); err != nil {
		t.Fatalf("DisableAccount() error = %v", err)
	}
	if err := commands.EnableAccount(context.Background(), "operator-01", userID); err != nil {
		t.Fatalf("EnableAccount() error = %v", err)
	}
	if err := commands.RevokeSession(context.Background(), "operator-01", sessionID); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if len(repository.mutations) != 3 {
		t.Fatalf("mutations = %+v", repository.mutations)
	}
	for _, mutation := range repository.mutations {
		if mutation.Operator != "operator-01" || mutation.AuditEventID == uuid.Nil || !mutation.OccurredAt.Equal(now) {
			t.Fatalf("unaudited mutation = %+v", mutation)
		}
	}
}

func TestAuditLookupReturnsOnlyRedactedFields(t *testing.T) {
	userID := uuid.New()
	repository := &fakeRepository{events: []RedactedAuditEvent{{
		ID: uuid.New(), EventType: "account_disabled", Outcome: "success", ObjectType: "user",
		OccurredAt: time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC),
	}}}
	commands, err := NewCommands(repository, time.Now)
	if err != nil {
		t.Fatalf("NewCommands() error = %v", err)
	}

	events, err := commands.Audit(context.Background(), "operator-01", userID, 50)

	if err != nil || len(events) != 1 || events[0].EventType != "account_disabled" {
		t.Fatalf("Audit() = %+v, %v", events, err)
	}
	if repository.auditQuery.Operator != "operator-01" || repository.auditQuery.AuditEventID == uuid.Nil {
		t.Fatalf("audit lookup record = %+v", repository.auditQuery)
	}
}

func TestPostgresRestrictedCommandsDisableEnableRevokeAndAudit(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		TRUNCATE audit_events, offline_entitlement_issuances, sessions, devices, personal_spaces, users CASCADE
	`); err != nil {
		t.Fatalf("truncate admin tables: %v", err)
	}
	now := time.Date(2026, 7, 18, 10, 30, 0, 0, time.UTC)
	userID, spaceID, deviceID, sessionID, familyID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := postgres.Exec(ctx, `INSERT INTO users (id, nickname, status, created_at, updated_at) VALUES ($1, 'Alice', 'active', $2, $2)`, userID, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at) VALUES ($1, $2, 'active', $3, $3)`, spaceID, userID, now); err != nil {
		t.Fatalf("seed space: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO devices (id, user_id, installation_id, public_key, display_name, platform, app_version, status, last_seen_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'Admin Test Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, deviceID, userID, uuid.New(), bytes.Repeat([]byte{70}, 32), now); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO sessions (id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, sessionID, userID, deviceID, familyID, bytes.Repeat([]byte{71}, 32), now, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO offline_entitlement_issuances (
			jti, user_id, device_id, personal_space_id, installation_id, signing_key_id, policy_version, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'offline-v1', 1, $6, $7)
	`, uuid.New(), userID, deviceID, spaceID, uuid.New(), now, now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("seed entitlement: %v", err)
	}
	commands, err := NewCommands(NewPostgresRepository(postgres), func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatalf("NewCommands() error = %v", err)
	}
	lifecycleLock, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lifecycle lock transaction: %v", err)
	}
	lockID := int64(binary.BigEndian.Uint64(userID[:8]))
	if _, err := lifecycleLock.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		t.Fatalf("hold lifecycle lock: %v", err)
	}
	disableResult := make(chan error, 1)
	go func() { disableResult <- commands.DisableAccount(ctx, "operator-01", userID) }()
	select {
	case err := <-disableResult:
		_ = lifecycleLock.Rollback(ctx)
		t.Fatalf("DisableAccount() ignored the shared lifecycle lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := lifecycleLock.Rollback(ctx); err != nil {
		t.Fatalf("release lifecycle lock: %v", err)
	}
	if err := <-disableResult; err != nil {
		t.Fatalf("DisableAccount() error = %v", err)
	}
	var status, spaceStatus, deviceStatus string
	var administrativeRevision int64
	var administrativelyDisabled bool
	var sessionRevoked, entitlementRevoked pgtype.Timestamptz
	if err := postgres.QueryRow(ctx, `SELECT status, administratively_disabled, administrative_revision FROM users WHERE id = $1`, userID).Scan(&status, &administrativelyDisabled, &administrativeRevision); err != nil {
		t.Fatalf("read disabled user: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT status FROM personal_spaces WHERE id = $1`, spaceID).Scan(&spaceStatus); err != nil {
		t.Fatalf("read disabled space: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT status FROM devices WHERE id = $1`, deviceID).Scan(&deviceStatus); err != nil {
		t.Fatalf("read disabled device: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, sessionID).Scan(&sessionRevoked); err != nil {
		t.Fatalf("read disabled session: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT revoked_at FROM offline_entitlement_issuances WHERE device_id = $1`, deviceID).Scan(&entitlementRevoked); err != nil {
		t.Fatalf("read disabled entitlement: %v", err)
	}
	if status != "disabled" || !administrativelyDisabled || administrativeRevision != 2 || spaceStatus != "disabled" || deviceStatus != "revoked" || !sessionRevoked.Valid || !entitlementRevoked.Valid {
		t.Fatalf("disabled state user=%s/%v/%d space=%s device=%s session=%v entitlement=%v", status, administrativelyDisabled, administrativeRevision, spaceStatus, deviceStatus, sessionRevoked.Valid, entitlementRevoked.Valid)
	}
	if err := commands.EnableAccount(ctx, "operator-01", userID); err != nil {
		t.Fatalf("EnableAccount() error = %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT status, administratively_disabled, administrative_revision FROM users WHERE id = $1`, userID).Scan(&status, &administrativelyDisabled, &administrativeRevision); err != nil {
		t.Fatalf("read enabled user: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT status FROM personal_spaces WHERE id = $1`, spaceID).Scan(&spaceStatus); err != nil {
		t.Fatalf("read enabled space: %v", err)
	}
	if status != "active" || administrativelyDisabled || administrativeRevision != 3 || spaceStatus != "active" {
		t.Fatalf("enabled state user=%s/%v/%d space=%s", status, administrativelyDisabled, administrativeRevision, spaceStatus)
	}

	secondDeviceID, secondSessionID := uuid.New(), uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO devices (id, user_id, installation_id, public_key, display_name, platform, app_version, status, last_seen_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'Second Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, secondDeviceID, userID, uuid.New(), bytes.Repeat([]byte{72}, 32), now); err != nil {
		t.Fatalf("seed second device: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO sessions (id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, secondSessionID, userID, secondDeviceID, uuid.New(), bytes.Repeat([]byte{73}, 32), now, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("seed second session: %v", err)
	}
	if err := commands.RevokeSession(ctx, "operator-01", secondSessionID); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, secondSessionID).Scan(&sessionRevoked); err != nil || !sessionRevoked.Valid {
		t.Fatalf("revoked admin session = %v, %v", sessionRevoked.Valid, err)
	}
	if err := postgres.QueryRow(ctx, `SELECT administrative_revision FROM users WHERE id = $1`, userID).Scan(&administrativeRevision); err != nil || administrativeRevision != 4 {
		t.Fatalf("session revoke revision = %d, %v; want 4", administrativeRevision, err)
	}
	events, err := commands.Audit(ctx, "operator-01", userID, 50)
	if err != nil || len(events) < 3 {
		t.Fatalf("Audit() = %d events, %v", len(events), err)
	}
	var operatorAudits int64
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE event_type IN ('account_disabled', 'account_enabled', 'session_admin_revoked', 'admin_audit_lookup')
		  AND operator_identity = 'operator-01'
	`).Scan(&operatorAudits); err != nil {
		t.Fatalf("count operator audits: %v", err)
	}
	if operatorAudits != 4 {
		t.Fatalf("operator audit rows = %d, want 4", operatorAudits)
	}
}

type fakeRepository struct {
	mutations  []Mutation
	auditQuery AuditQuery
	events     []RedactedAuditEvent
	err        error
}

func (f *fakeRepository) DisableAccount(_ context.Context, mutation Mutation) error {
	f.mutations = append(f.mutations, mutation)
	return f.err
}

func (f *fakeRepository) EnableAccount(_ context.Context, mutation Mutation) error {
	f.mutations = append(f.mutations, mutation)
	return f.err
}

func (f *fakeRepository) RevokeSession(_ context.Context, mutation Mutation) error {
	f.mutations = append(f.mutations, mutation)
	return f.err
}

func (f *fakeRepository) Audit(_ context.Context, query AuditQuery) ([]RedactedAuditEvent, error) {
	f.auditQuery = query
	return f.events, f.err
}
