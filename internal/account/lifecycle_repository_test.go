package account

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPostgresLifecycleRemovesOnlySecondaryIdentityAndPreservesCurrentSessionOnPasswordChange(t *testing.T) {
	fixture := newRepositoryFixture(t)
	emailClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 31)
	registration := fixture.registrationRecord(t, emailClaims, "Alice")
	if _, err := fixture.repository.Register(fixture.ctx, registration); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	phoneClaims := fixture.verifiedReceipt(t, secure.IdentityPhone, "+8613800138000", verification.PurposeBindIdentity, 32)
	sealedPhone, err := fixture.identity.Seal(phoneClaims.Kind, phoneClaims.NormalizedIdentity)
	if err != nil {
		t.Fatalf("Seal(phone) error = %v", err)
	}
	if err := fixture.repository.BindIdentity(fixture.ctx, IdentityBindingRecord{
		ReceiptClaims: phoneClaims, UserID: registration.UserID, IdentityID: uuid.New(), AuditEventID: uuid.New(),
		SealedIdentity: sealedPhone, CreatedAt: fixture.now,
	}); err != nil {
		t.Fatalf("BindIdentity() error = %v", err)
	}
	profile, found, err := fixture.repository.Profile(fixture.ctx, registration.UserID)
	if err != nil || !found || profile.UserID != registration.UserID || len(profile.IdentityKinds) != 2 ||
		profile.IdentityKinds[0] != secure.IdentityEmail || profile.IdentityKinds[1] != secure.IdentityPhone {
		t.Fatalf("Profile() = %+v, found=%v, error=%v", profile, found, err)
	}
	if err := fixture.repository.RemoveIdentity(fixture.ctx, IdentityRemovalRecord{
		UserID: registration.UserID, Kind: secure.IdentityPhone, AuditEventID: uuid.New(), RemovedAt: fixture.now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("RemoveIdentity(phone) error = %v", err)
	}
	if err := fixture.repository.RemoveIdentity(fixture.ctx, IdentityRemovalRecord{
		UserID: registration.UserID, Kind: secure.IdentityEmail, AuditEventID: uuid.New(), RemovedAt: fixture.now.Add(2 * time.Minute),
	}); !errors.Is(err, ErrLastIdentity) {
		t.Fatalf("RemoveIdentity(last) error = %v", err)
	}

	currentSessionID := seedLifecycleSession(t, fixture, registration.UserID, 41)
	otherSessionID := seedLifecycleSession(t, fixture, registration.UserID, 42)
	if err := fixture.repository.ChangePassword(fixture.ctx, PasswordChangeRecord{
		UserID: registration.UserID, CurrentSessionID: currentSessionID,
		PasswordHash: "new-password-hash", PasswordParamsVersion: 2,
		AuditEventID: uuid.New(), ChangedAt: fixture.now.Add(3 * time.Minute),
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}
	var currentRevoked pgtype.Timestamptz
	var otherRevoked pgtype.Timestamptz
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, currentSessionID).Scan(&currentRevoked); err != nil {
		t.Fatalf("read current session: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, otherSessionID).Scan(&otherRevoked); err != nil {
		t.Fatalf("read other session: %v", err)
	}
	if currentRevoked.Valid || !otherRevoked.Valid {
		t.Fatalf("session revocation current=%v other=%v", currentRevoked.Valid, otherRevoked.Valid)
	}
	credential, found, err := fixture.repository.FindCredentialByUserID(fixture.ctx, registration.UserID)
	if err != nil || !found || credential.PasswordHash != "new-password-hash" || credential.ParamsVersion != 2 {
		t.Fatalf("FindCredentialByUserID() = %+v, %v, %v", credential, found, err)
	}
}

func TestPostgresLifecycleRefusesIdentityAlreadyOwnedByAnotherAccount(t *testing.T) {
	fixture := newRepositoryFixture(t)
	firstClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "owner@example.com", verification.PurposeRegistration, 81)
	first := fixture.registrationRecord(t, firstClaims, "Owner")
	if _, err := fixture.repository.Register(fixture.ctx, first); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}
	secondClaims := fixture.verifiedReceipt(t, secure.IdentityPhone, "+8613900139000", verification.PurposeRegistration, 82)
	second := fixture.registrationRecord(t, secondClaims, "Second")
	if _, err := fixture.repository.Register(fixture.ctx, second); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}
	bindClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "owner@example.com", verification.PurposeBindIdentity, 83)
	sealed, err := fixture.identity.Seal(bindClaims.Kind, bindClaims.NormalizedIdentity)
	if err != nil {
		t.Fatalf("Seal(bind identity) error = %v", err)
	}
	err = fixture.repository.BindIdentity(fixture.ctx, IdentityBindingRecord{
		ReceiptClaims: bindClaims, UserID: second.UserID, IdentityID: uuid.New(), AuditEventID: uuid.New(),
		SealedIdentity: sealed, CreatedAt: fixture.now,
	})
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BindIdentity(owned identity) error = %v", err)
	}
}

func TestPostgresLifecycleDeletionRevokesCloudAccessAndRecoversWithinSevenDays(t *testing.T) {
	fixture := newRepositoryFixture(t)
	registrationClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 51)
	registration := fixture.registrationRecord(t, registrationClaims, "Alice")
	if _, err := fixture.repository.Register(fixture.ctx, registration); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	sessionID := seedLifecycleSession(t, fixture, registration.UserID, 52)
	var deviceID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT device_id FROM sessions WHERE id = $1`, sessionID).Scan(&deviceID); err != nil {
		t.Fatalf("read session device: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO offline_entitlement_issuances (
			jti, user_id, device_id, personal_space_id, installation_id,
			signing_key_id, policy_version, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'offline-v1', 1, $6, $7)
	`, uuid.New(), registration.UserID, deviceID, registration.PersonalSpaceID, uuid.New(), fixture.now, fixture.now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert offline entitlement: %v", err)
	}
	deletionClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeAccountDeletion, 53)
	requestedAt := fixture.now.Add(time.Hour)
	if err := fixture.repository.RequestDeletion(fixture.ctx, DeletionRequestRecord{
		ReceiptClaims: deletionClaims, UserID: registration.UserID,
		AuditEventID: uuid.New(), RequestedAt: requestedAt,
	}); err != nil {
		t.Fatalf("RequestDeletion() error = %v", err)
	}
	var userStatus, spaceStatus, deviceStatus string
	var sessionRevoked, entitlementRevoked pgtype.Timestamptz
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM users WHERE id = $1`, registration.UserID).Scan(&userStatus); err != nil {
		t.Fatalf("read user status: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM personal_spaces WHERE id = $1`, registration.PersonalSpaceID).Scan(&spaceStatus); err != nil {
		t.Fatalf("read space status: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM devices WHERE id = $1`, deviceID).Scan(&deviceStatus); err != nil {
		t.Fatalf("read device status: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, sessionID).Scan(&sessionRevoked); err != nil {
		t.Fatalf("read session revocation: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT revoked_at FROM offline_entitlement_issuances WHERE device_id = $1`, deviceID).Scan(&entitlementRevoked); err != nil {
		t.Fatalf("read entitlement revocation: %v", err)
	}
	if userStatus != "pending_deletion" || spaceStatus != "disabled" || deviceStatus != "revoked" ||
		!sessionRevoked.Valid || !entitlementRevoked.Valid {
		t.Fatalf("deletion state user=%s space=%s device=%s session=%v entitlement=%v", userStatus, spaceStatus, deviceStatus, sessionRevoked.Valid, entitlementRevoked.Valid)
	}

	recoveryClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeDeletionRecovery, 54)
	if err := fixture.repository.RecoverDeletion(fixture.ctx, DeletionRecoveryRecord{
		ReceiptClaims: recoveryClaims, UserID: registration.UserID,
		AuditEventID: uuid.New(), RecoveredAt: requestedAt.Add(6 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("RecoverDeletion() error = %v", err)
	}
	var deletionRequested pgtype.Timestamptz
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status, deletion_requested_at FROM users WHERE id = $1`, registration.UserID).Scan(&userStatus, &deletionRequested); err != nil {
		t.Fatalf("read recovered user: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM personal_spaces WHERE id = $1`, registration.PersonalSpaceID).Scan(&spaceStatus); err != nil {
		t.Fatalf("read recovered space: %v", err)
	}
	if userStatus != "active" || deletionRequested.Valid || spaceStatus != "active" {
		t.Fatalf("recovered state user=%s requested=%v space=%s", userStatus, deletionRequested.Valid, spaceStatus)
	}
}

func TestPostgresLifecycleFinalizationReleasesIdentityAndAnonymizesAudit(t *testing.T) {
	fixture := newRepositoryFixture(t)
	registrationClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 61)
	registration := fixture.registrationRecord(t, registrationClaims, "Alice")
	if _, err := fixture.repository.Register(fixture.ctx, registration); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	seedLifecycleSession(t, fixture, registration.UserID, 62)
	deletionClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeAccountDeletion, 63)
	requestedAt := fixture.now.Add(time.Hour)
	if err := fixture.repository.RequestDeletion(fixture.ctx, DeletionRequestRecord{
		ReceiptClaims: deletionClaims, UserID: registration.UserID,
		AuditEventID: uuid.New(), RequestedAt: requestedAt,
	}); err != nil {
		t.Fatalf("RequestDeletion() error = %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO audit_events (
			id, event_type, operator_identity, subject_user_id, object_type, object_id, outcome, metadata, created_at
		) VALUES ($1, 'session_admin_revoked', 'operator-01', $2, 'session', $3, 'success', '{}'::jsonb, $4)
	`, uuid.New(), registration.UserID, uuid.New(), requestedAt.Add(time.Minute)); err != nil {
		t.Fatalf("insert subject-scoped admin audit: %v", err)
	}
	unrelatedActorID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at)
		VALUES ($1, 'Security Reviewer', 'active', $2, $2)
	`, unrelatedActorID, requestedAt); err != nil {
		t.Fatalf("insert unrelated audit actor: %v", err)
	}
	crossActorAuditID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, subject_user_id, object_type, object_id, outcome, metadata, created_at
		) VALUES ($1, 'security_review', $2, $3, 'user', $3, 'success', '{}'::jsonb, $4)
	`, crossActorAuditID, unrelatedActorID, registration.UserID, requestedAt.Add(2*time.Minute)); err != nil {
		t.Fatalf("insert cross-actor audit: %v", err)
	}
	if err := fixture.repository.FinalizeDeletion(
		fixture.ctx, registration.UserID, uuid.New(), requestedAt.Add(7*24*time.Hour),
	); err != nil {
		t.Fatalf("FinalizeDeletion() error = %v", err)
	}
	var status string
	var nickname *string
	var finalizedAt pgtype.Timestamptz
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT status, nickname, deletion_finalized_at FROM users WHERE id = $1
	`, registration.UserID).Scan(&status, &nickname, &finalizedAt); err != nil {
		t.Fatalf("read finalized user: %v", err)
	}
	if status != "disabled" || nickname != nil || !finalizedAt.Valid {
		t.Fatalf("finalized user status=%s nickname=%v finalized=%v", status, nickname, finalizedAt.Valid)
	}
	for _, table := range []string{"identities", "password_credentials", "personal_spaces", "devices", "sessions", "legal_acceptances"} {
		var count int64
		if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM `+table+` WHERE `+lifecycleOwnerColumn(table)+` = $1`, registration.UserID).Scan(&count); err != nil {
			t.Fatalf("count finalized %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("finalized %s rows = %d", table, count)
		}
	}
	var identifyingAudit int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM audit_events
		WHERE actor_user_id = $1 OR subject_user_id = $1 OR device_id IS NOT NULL OR object_id IS NOT NULL
	`, registration.UserID).Scan(&identifyingAudit); err != nil {
		t.Fatalf("count identifying audit: %v", err)
	}
	if identifyingAudit != 0 {
		t.Fatalf("identifying audit rows = %d", identifyingAudit)
	}
	var retainedActor uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT actor_user_id FROM audit_events WHERE id = $1
	`, crossActorAuditID).Scan(&retainedActor); err != nil {
		t.Fatalf("read retained unrelated actor: %v", err)
	}
	if retainedActor != unrelatedActorID {
		t.Fatalf("retained actor = %s, want %s", retainedActor, unrelatedActorID)
	}

	newClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 64)
	if _, err := fixture.repository.Register(fixture.ctx, fixture.registrationRecord(t, newClaims, "New Alice")); err != nil {
		t.Fatalf("Register(released identity) error = %v", err)
	}
}

func TestPostgresDeletionRecoveryAtSevenDayBoundaryIsRejectedWithoutConsumingReceipt(t *testing.T) {
	fixture := newRepositoryFixture(t)
	registrationClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "boundary@example.com", verification.PurposeRegistration, 71)
	registration := fixture.registrationRecord(t, registrationClaims, "Boundary")
	if _, err := fixture.repository.Register(fixture.ctx, registration); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	deletionClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "boundary@example.com", verification.PurposeAccountDeletion, 72)
	requestedAt := fixture.now.Add(time.Hour)
	if err := fixture.repository.RequestDeletion(fixture.ctx, DeletionRequestRecord{
		ReceiptClaims: deletionClaims, UserID: registration.UserID,
		AuditEventID: uuid.New(), RequestedAt: requestedAt,
	}); err != nil {
		t.Fatalf("RequestDeletion() error = %v", err)
	}
	recoveryClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "boundary@example.com", verification.PurposeDeletionRecovery, 73)
	err := fixture.repository.RecoverDeletion(fixture.ctx, DeletionRecoveryRecord{
		ReceiptClaims: recoveryClaims, UserID: registration.UserID,
		AuditEventID: uuid.New(), RecoveredAt: requestedAt.Add(7 * 24 * time.Hour),
	})
	if !errors.Is(err, ErrDeletionWindowExpired) {
		t.Fatalf("RecoverDeletion(exact boundary) error = %v", err)
	}
	var status string
	var receiptConsumed pgtype.Timestamptz
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM users WHERE id = $1`, registration.UserID).Scan(&status); err != nil {
		t.Fatalf("read pending user: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT receipt_consumed_at FROM verification_challenges WHERE id = $1
	`, recoveryClaims.ChallengeID).Scan(&receiptConsumed); err != nil {
		t.Fatalf("read recovery receipt state: %v", err)
	}
	if status != "pending_deletion" || receiptConsumed.Valid {
		t.Fatalf("boundary state status=%s receipt_consumed=%v", status, receiptConsumed.Valid)
	}
}

func seedLifecycleSession(t *testing.T, fixture *repositoryFixture, userID uuid.UUID, discriminator byte) uuid.UUID {
	t.Helper()
	deviceID := uuid.New()
	sessionID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Lifecycle Device', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, deviceID, userID, uuid.New(), bytes.Repeat([]byte{discriminator}, 32), fixture.now); err != nil {
		t.Fatalf("insert lifecycle device: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO sessions (
			id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, sessionID, userID, deviceID, uuid.New(), bytes.Repeat([]byte{discriminator + 80}, 32), fixture.now, fixture.now.Add(30*24*time.Hour)); err != nil {
		t.Fatalf("insert lifecycle session: %v", err)
	}
	return sessionID
}

func lifecycleOwnerColumn(table string) string {
	switch table {
	case "identities", "password_credentials", "devices", "sessions", "legal_acceptances":
		return "user_id"
	case "personal_spaces":
		return "owner_user_id"
	default:
		panic("unsupported lifecycle table")
	}
}
