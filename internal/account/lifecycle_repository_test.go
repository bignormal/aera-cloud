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
	agentAuditID := seedAgentControlPlaneState(t, fixture, registration.UserID, registration.PersonalSpaceID)
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
	for _, table := range []string{
		"agent_definitions",
		"agent_versions",
		"agent_version_revocations",
		"installations",
		"policy_snapshots",
		"runtime_binding_records",
		"agent_control_idempotency_keys",
	} {
		var count int64
		if err := fixture.postgres.QueryRow(
			fixture.ctx,
			`SELECT count(*) FROM `+table+` WHERE owner_id = $1`,
			registration.UserID,
		).Scan(&count); err != nil {
			t.Fatalf("count finalized %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("finalized %s rows = %d", table, count)
		}
	}
	var agentObjectCleared bool
	var agentMetadataCleared bool
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT object_id IS NULL, metadata = '{}'::jsonb
		FROM audit_events
		WHERE id = $1
	`, agentAuditID).Scan(&agentObjectCleared, &agentMetadataCleared); err != nil {
		t.Fatalf("read anonymized Agent audit: %v", err)
	}
	if !agentObjectCleared || !agentMetadataCleared {
		t.Fatalf("Agent audit anonymization object=%v metadata=%v", agentObjectCleared, agentMetadataCleared)
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

func seedAgentControlPlaneState(
	t *testing.T,
	fixture *repositoryFixture,
	userID uuid.UUID,
	personalSpaceID uuid.UUID,
) uuid.UUID {
	t.Helper()
	var deviceID uuid.UUID
	var deviceInstallationID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT id, installation_id FROM devices WHERE user_id = $1
	`, userID).Scan(&deviceID, &deviceInstallationID); err != nil {
		t.Fatalf("read lifecycle device: %v", err)
	}

	definitionID := uuid.New()
	versionID := uuid.New()
	installationID := uuid.New()
	policyID := uuid.New()
	runtimeProfileID := uuid.New()
	digest := bytes.Repeat([]byte{0x91}, 32)
	signature := bytes.Repeat([]byte{0x92}, 64)
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO agent_definitions (
			id, tenant_id, owner_scope, owner_id, display_name, status, created_by, created_at, updated_at
		) VALUES ($1, $2, 'USER', $3, 'Deletion fixture', 'active', $3, $4, $4)
	`, definitionID, personalSpaceID, userID, fixture.now); err != nil {
		t.Fatalf("insert Agent definition fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO agent_versions (
			id, definition_id, tenant_id, owner_scope, owner_id, version_number,
			canonical_manifest, bundle, content_digest, signing_key_id, signature,
			runtime_minimum_version, published_by, published_at
		) VALUES (
			$1, $2, $3, 'USER', $4, 1,
			'{"schema_version":1}'::jsonb, '{"assets":[]}'::jsonb, $5, 'agent-control-1', $6,
			'0.18.2-agentera.1', $4, $7
		)
	`, versionID, definitionID, personalSpaceID, userID, digest, signature, fixture.now); err != nil {
		t.Fatalf("insert Agent version fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE agent_definitions SET latest_version_id = $2 WHERE id = $1
	`, definitionID, versionID); err != nil {
		t.Fatalf("link Agent latest version fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO installations (
			id, tenant_id, owner_scope, owner_id, device_id, device_installation_id,
			definition_id, selected_version_id, update_policy, status, created_by, created_at, updated_at
		) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, 'manual', 'pending', $3, $8, $8)
	`, installationID, personalSpaceID, userID, deviceID, deviceInstallationID, definitionID, versionID, fixture.now); err != nil {
		t.Fatalf("insert Agent installation fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO policy_snapshots (
			id, installation_id, agent_version_id, tenant_id, owner_scope, owner_id,
			policy_version, policy_document, content_digest, issuer, signing_key_id, signature, created_by, created_at
		) VALUES (
			$1, $2, $3, $4, 'USER', $5,
			1, '{"tools":{"allowed":[]}}'::jsonb, $6, 'agentera-cloud', 'agent-control-1', $7, $5, $8
		)
	`, policyID, installationID, versionID, personalSpaceID, userID, digest, signature, fixture.now); err != nil {
		t.Fatalf("insert Agent policy fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE installations
		SET runtime_profile_id = $2, policy_snapshot_id = $3, status = 'active', activated_at = $4, updated_at = $4
		WHERE id = $1
	`, installationID, runtimeProfileID, policyID, fixture.now); err != nil {
		t.Fatalf("activate Agent installation fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO agent_version_revocations (
			id, version_id, tenant_id, owner_scope, owner_id, reason_code,
			actor_user_id, policy_snapshot_id, created_at
		) VALUES ($1, $2, $3, 'USER', $4, 'owner_revoked', $4, $5, $6)
	`, uuid.New(), versionID, personalSpaceID, userID, policyID, fixture.now); err != nil {
		t.Fatalf("insert Agent revocation fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO runtime_binding_records (
			id, tenant_id, owner_scope, owner_id, device_id, agent_installation_id,
			agent_version_id, runtime_profile_id, runtime_version, policy_snapshot_id,
			tool_permission_digest, created_at
		) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, '0.18.2-agentera.1', $8, $9, $10)
	`, uuid.New(), personalSpaceID, userID, deviceID, installationID, versionID, runtimeProfileID, policyID, digest, fixture.now); err != nil {
		t.Fatalf("insert RuntimeBinding record fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO agent_control_idempotency_keys (
			id, tenant_id, owner_scope, owner_id, operation, key_hash, request_hash,
			resource_type, resource_id, response_document, created_at, expires_at
		) VALUES (
			$1, $2, 'USER', $3, 'publish_initial', $4, $5,
			'agent_version', $6, '{"version_number":1}'::jsonb, $7, $8
		)
	`, uuid.New(), personalSpaceID, userID, bytes.Repeat([]byte{0x93}, 32), bytes.Repeat([]byte{0x94}, 32), versionID, fixture.now, fixture.now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert Agent idempotency fixture: %v", err)
	}

	auditID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, device_id, object_type, object_id, outcome, metadata, created_at
		) VALUES (
			$1, 'agent_version_published', $2, $3, 'agent_version', $4, 'success',
			jsonb_build_object(
				'tenant_id', $5::uuid::text,
				'owner_scope', 'USER',
				'owner_id', $2::uuid::text,
				'agent_definition_id', $6::uuid::text,
				'agent_version_id', $4::uuid::text,
				'content_digest', encode($7::bytea, 'hex')
			),
			$8
		)
	`, auditID, userID, deviceID, versionID, personalSpaceID, definitionID, digest, fixture.now); err != nil {
		t.Fatalf("insert Agent audit fixture: %v", err)
	}
	return auditID
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
