package account

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPostgresProfileCountsOwnedWorkspacesWithoutCountingMemberships(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ownerClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "workspace-owner@example.com", verification.PurposeRegistration, 21)
	owner := fixture.registrationRecord(t, ownerClaims, "Workspace Owner")
	if _, err := fixture.repository.Register(fixture.ctx, owner); err != nil {
		t.Fatalf("Register(owner) error = %v", err)
	}
	otherClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "other-owner@example.com", verification.PurposeRegistration, 22)
	other := fixture.registrationRecord(t, otherClaims, "Other Owner")
	if _, err := fixture.repository.Register(fixture.ctx, other); err != nil {
		t.Fatalf("Register(other) error = %v", err)
	}
	seedLifecycleWorkspace(t, fixture, owner.UserID, "active", other.UserID)
	seedLifecycleWorkspace(t, fixture, owner.UserID, "archived")
	seedLifecycleWorkspace(t, fixture, other.UserID, "active", owner.UserID)

	profile, found, err := fixture.repository.Profile(fixture.ctx, owner.UserID)
	if err != nil || !found || profile.OwnedWorkspaceCount != 2 {
		t.Fatalf("Profile(owner) = %+v found=%v error=%v", profile, found, err)
	}
	otherProfile, found, err := fixture.repository.Profile(fixture.ctx, other.UserID)
	if err != nil || !found || otherProfile.OwnedWorkspaceCount != 1 {
		t.Fatalf("Profile(other) = %+v found=%v error=%v", otherProfile, found, err)
	}
}

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

func TestPostgresLifecycleFinalizationCleansWorkspaceOwnershipAndMembershipBoundaries(t *testing.T) {
	fixture := newRepositoryFixture(t)
	targetClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "workspace-delete@example.com", verification.PurposeRegistration, 91)
	target := fixture.registrationRecord(t, targetClaims, "Workspace Delete")
	if _, err := fixture.repository.Register(fixture.ctx, target); err != nil {
		t.Fatalf("Register(target) error = %v", err)
	}
	otherClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "workspace-keeper@example.com", verification.PurposeRegistration, 92)
	other := fixture.registrationRecord(t, otherClaims, "Workspace Keeper")
	if _, err := fixture.repository.Register(fixture.ctx, other); err != nil {
		t.Fatalf("Register(other) error = %v", err)
	}

	ownedWorkspaceID := seedLifecycleWorkspace(t, fixture, target.UserID, "active", other.UserID)
	seedLifecycleWorkspace(t, fixture, target.UserID, "archived")
	externalWorkspaceID := seedLifecycleWorkspace(t, fixture, other.UserID, "active", target.UserID)
	createdInviteID := uuid.New()
	acceptedInviteID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, createdInviteID, externalWorkspaceID, bytes.Repeat([]byte{0xa1}, 32), target.UserID,
		fixture.now, fixture.now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert created invitation: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, accepted_by_user_id,
			created_at, expires_at, accepted_at
		) VALUES ($1, $2, $3, $4, 'accepted', $5, $6, $7, $8)
	`, acceptedInviteID, externalWorkspaceID, bytes.Repeat([]byte{0xa2}, 32), other.UserID, target.UserID,
		fixture.now, fixture.now.Add(7*24*time.Hour), fixture.now.Add(time.Hour)); err != nil {
		t.Fatalf("insert accepted invitation: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO workspace_idempotency_records (
			actor_user_id, workspace_id, operation, key_digest, request_digest,
			resource_type, resource_id, created_at, expires_at
		) VALUES ($1, $2, 'workspace_invitation_accept', $3, $4, 'workspace_membership', $1, $5, $6)
	`, target.UserID, externalWorkspaceID, bytes.Repeat([]byte{0xa3}, 32), bytes.Repeat([]byte{0xa4}, 32),
		fixture.now, fixture.now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert workspace idempotency: %v", err)
	}
	workspaceAuditID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, object_type, object_id, outcome, metadata, created_at
		) VALUES (
			$1, 'workspace_member_removed', $2, 'workspace', $3, 'success',
			jsonb_build_object('workspace_id', $3::uuid::text, 'membership_user_id', $2::uuid::text, 'role', 'member'), $4
		)
	`, workspaceAuditID, other.UserID, ownedWorkspaceID, fixture.now); err != nil {
		t.Fatalf("insert workspace audit: %v", err)
	}

	deletionClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "workspace-delete@example.com", verification.PurposeAccountDeletion, 93)
	requestedAt := fixture.now.Add(2 * time.Hour)
	if err := fixture.repository.RequestDeletion(fixture.ctx, DeletionRequestRecord{
		ReceiptClaims: deletionClaims, UserID: target.UserID, AuditEventID: uuid.New(), RequestedAt: requestedAt,
	}); err != nil {
		t.Fatalf("RequestDeletion() error = %v", err)
	}
	if err := fixture.repository.FinalizeDeletion(fixture.ctx, target.UserID, uuid.New(), requestedAt.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("FinalizeDeletion() error = %v", err)
	}

	for name, query := range map[string]string{
		"owned workspaces":    `SELECT count(*) FROM workspaces WHERE owner_user_id = $1`,
		"external membership": `SELECT count(*) FROM workspace_memberships WHERE user_id = $1`,
		"actor idempotency":   `SELECT count(*) FROM workspace_idempotency_records WHERE actor_user_id = $1`,
	} {
		var count int
		if err := fixture.postgres.QueryRow(fixture.ctx, query, target.UserID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s after finalization = %d, error=%v", name, count, err)
		}
	}
	var externalWorkspaceCount int
	var externalOwnerCount int
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM workspaces WHERE id = $1`, externalWorkspaceID).Scan(&externalWorkspaceCount); err != nil {
		t.Fatalf("count external workspace: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2 AND role = 'owner'
	`, externalWorkspaceID, other.UserID).Scan(&externalOwnerCount); err != nil {
		t.Fatalf("count external Owner: %v", err)
	}
	if externalWorkspaceCount != 1 || externalOwnerCount != 1 {
		t.Fatalf("external workspace=%d owner=%d", externalWorkspaceCount, externalOwnerCount)
	}
	var creatorCleared bool
	var acceptorCleared bool
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT created_by_user_id IS NULL FROM workspace_invitations WHERE id = $1`, createdInviteID).Scan(&creatorCleared); err != nil {
		t.Fatalf("read invitation creator: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT accepted_by_user_id IS NULL FROM workspace_invitations WHERE id = $1`, acceptedInviteID).Scan(&acceptorCleared); err != nil {
		t.Fatalf("read invitation acceptor: %v", err)
	}
	if !creatorCleared || !acceptorCleared {
		t.Fatalf("invitation references creator=%v acceptor=%v", creatorCleared, acceptorCleared)
	}
	var retainedActor uuid.UUID
	var objectCleared bool
	var metadataCleared bool
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT actor_user_id, object_id IS NULL, metadata = '{}'::jsonb FROM audit_events WHERE id = $1
	`, workspaceAuditID).Scan(&retainedActor, &objectCleared, &metadataCleared); err != nil {
		t.Fatalf("read workspace audit: %v", err)
	}
	if retainedActor != other.UserID || !objectCleared || !metadataCleared {
		t.Fatalf("workspace audit actor=%s objectCleared=%v metadataCleared=%v", retainedActor, objectCleared, metadataCleared)
	}
}

func TestPostgresDeletionRequestBlocksOrganizationOwnerWithoutConsumingReceipt(t *testing.T) {
	fixture := newRepositoryFixture(t)
	claims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-owner-delete@example.com", verification.PurposeRegistration, 101)
	owner := fixture.registrationRecord(t, claims, "Organization Owner")
	if _, err := fixture.repository.Register(fixture.ctx, owner); err != nil {
		t.Fatalf("Register(owner) error = %v", err)
	}
	seedLifecycleOrganization(t, fixture, owner.UserID, "active")
	seedLifecycleOrganization(t, fixture, owner.UserID, "archived")

	deletionClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-owner-delete@example.com", verification.PurposeAccountDeletion, 102)
	err := fixture.repository.RequestDeletion(fixture.ctx, DeletionRequestRecord{
		ReceiptClaims: deletionClaims, UserID: owner.UserID, AuditEventID: uuid.New(), RequestedAt: fixture.now.Add(time.Hour),
	})
	var ownership *OrganizationOwnerTransferRequiredError
	if !errors.As(err, &ownership) || ownership.OwnedOrganizationCount != 2 {
		t.Fatalf("RequestDeletion() error = %#v", err)
	}
	var status string
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM users WHERE id = $1`, owner.UserID).Scan(&status); err != nil || status != "active" {
		t.Fatalf("user status = %q, error = %v", status, err)
	}
	fixture.requireReceiptAvailable(t, deletionClaims.ChallengeID)
}

func TestPostgresLifecycleFinalizationRechecksOrganizationOwnership(t *testing.T) {
	fixture := newRepositoryFixture(t)
	claims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-owner-finalize@example.com", verification.PurposeRegistration, 107)
	owner := fixture.registrationRecord(t, claims, "Organization Owner Finalize")
	if _, err := fixture.repository.Register(fixture.ctx, owner); err != nil {
		t.Fatalf("Register(owner) error = %v", err)
	}
	deletionClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-owner-finalize@example.com", verification.PurposeAccountDeletion, 108)
	requestedAt := fixture.now.Add(time.Hour)
	if err := fixture.repository.RequestDeletion(fixture.ctx, DeletionRequestRecord{
		ReceiptClaims: deletionClaims, UserID: owner.UserID, AuditEventID: uuid.New(), RequestedAt: requestedAt,
	}); err != nil {
		t.Fatalf("RequestDeletion() error = %v", err)
	}
	organizationID := seedLifecycleOrganization(t, fixture, owner.UserID, "active")

	err := fixture.repository.FinalizeDeletion(fixture.ctx, owner.UserID, uuid.New(), requestedAt.Add(7*24*time.Hour))
	var ownership *OrganizationOwnerTransferRequiredError
	if !errors.As(err, &ownership) || ownership.OwnedOrganizationCount != 1 {
		t.Fatalf("FinalizeDeletion() error = %#v", err)
	}
	var status string
	var organizationCount int
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM users WHERE id = $1`, owner.UserID).Scan(&status); err != nil {
		t.Fatalf("read user status: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM organizations WHERE id = $1`, organizationID).Scan(&organizationCount); err != nil {
		t.Fatalf("read Organization: %v", err)
	}
	if status != "pending_deletion" || organizationCount != 1 {
		t.Fatalf("finalization boundary status=%s organization_count=%d", status, organizationCount)
	}
}

func TestPostgresLifecycleFinalizationRemovesOnlyDeletedOrganizationMemberIdentity(t *testing.T) {
	fixture := newRepositoryFixture(t)
	targetClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-member-delete@example.com", verification.PurposeRegistration, 103)
	target := fixture.registrationRecord(t, targetClaims, "Organization Member Delete")
	if _, err := fixture.repository.Register(fixture.ctx, target); err != nil {
		t.Fatalf("Register(target) error = %v", err)
	}
	ownerClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-owner-keep@example.com", verification.PurposeRegistration, 104)
	owner := fixture.registrationRecord(t, ownerClaims, "Organization Owner Keep")
	if _, err := fixture.repository.Register(fixture.ctx, owner); err != nil {
		t.Fatalf("Register(owner) error = %v", err)
	}
	otherClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-member-keep@example.com", verification.PurposeRegistration, 105)
	other := fixture.registrationRecord(t, otherClaims, "Organization Member Keep")
	if _, err := fixture.repository.Register(fixture.ctx, other); err != nil {
		t.Fatalf("Register(other) error = %v", err)
	}
	organizationID := seedLifecycleOrganization(t, fixture, owner.UserID, "active", target.UserID, other.UserID)
	departmentID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_departments (
			organization_id, id, display_name, name_key, status, revision, created_at, updated_at
		) VALUES ($1, $2, 'Research', 'research', 'active', 1, $3, $3)
	`, organizationID, departmentID, fixture.now); err != nil {
		t.Fatalf("insert Department: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organization_memberships SET department_id = $3, revision = 2, updated_at = $4
		WHERE organization_id = $1 AND user_id = $2
	`, organizationID, target.UserID, departmentID, fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("assign target Department: %v", err)
	}
	createdInvitationID := uuid.New()
	acceptedInvitationID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_invitations (
			id, organization_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, createdInvitationID, organizationID, bytes.Repeat([]byte{0xd1}, 32), target.UserID,
		fixture.now, fixture.now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert created invitation: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_invitations (
			id, organization_id, token_digest, created_by_user_id, status, accepted_by_user_id,
			created_at, expires_at, accepted_at
		) VALUES ($1, $2, $3, $4, 'accepted', $5, $6, $7, $8)
	`, acceptedInvitationID, organizationID, bytes.Repeat([]byte{0xd2}, 32), owner.UserID, target.UserID,
		fixture.now, fixture.now.Add(7*24*time.Hour), fixture.now.Add(time.Hour)); err != nil {
		t.Fatalf("insert accepted invitation: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_idempotency_records (
			actor_user_id, organization_id, operation, key_digest, request_digest,
			resource_type, resource_id, created_at, expires_at
		) VALUES ($1, $2, 'organization_invitation_accept', $3, $4, 'organization_membership', $1, $5, $6)
	`, target.UserID, organizationID, bytes.Repeat([]byte{0xd3}, 32), bytes.Repeat([]byte{0xd4}, 32),
		fixture.now, fixture.now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert Organization idempotency: %v", err)
	}
	auditID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, subject_user_id, organization_id,
			object_type, object_id, outcome, metadata, created_at
		) VALUES (
			$1, 'organization_member_patched', $2, $2, $3,
			'organization_membership', $2, 'success',
			jsonb_build_object('organization_id', $3::uuid::text, 'membership_user_id', $2::uuid::text, 'role', 'member'), $4
		)
	`, auditID, target.UserID, organizationID, fixture.now); err != nil {
		t.Fatalf("insert Organization audit: %v", err)
	}

	deletionClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "organization-member-delete@example.com", verification.PurposeAccountDeletion, 106)
	requestedAt := fixture.now.Add(2 * time.Hour)
	if err := fixture.repository.RequestDeletion(fixture.ctx, DeletionRequestRecord{
		ReceiptClaims: deletionClaims, UserID: target.UserID, AuditEventID: uuid.New(), RequestedAt: requestedAt,
	}); err != nil {
		t.Fatalf("RequestDeletion() error = %v", err)
	}
	if err := fixture.repository.FinalizeDeletion(fixture.ctx, target.UserID, uuid.New(), requestedAt.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("FinalizeDeletion() error = %v", err)
	}

	for _, test := range []struct {
		name  string
		query string
		args  []any
		want  int
	}{
		{name: "Organization", query: `SELECT count(*) FROM organizations WHERE id = $1`, args: []any{organizationID}, want: 1},
		{name: "Owner", query: `SELECT count(*) FROM organization_memberships WHERE organization_id = $1 AND user_id = $2 AND role = 'owner'`, args: []any{organizationID, owner.UserID}, want: 1},
		{name: "other Member", query: `SELECT count(*) FROM organization_memberships WHERE organization_id = $1 AND user_id = $2`, args: []any{organizationID, other.UserID}, want: 1},
		{name: "deleted Member", query: `SELECT count(*) FROM organization_memberships WHERE organization_id = $1 AND user_id = $2`, args: []any{organizationID, target.UserID}, want: 0},
		{name: "Department", query: `SELECT count(*) FROM organization_departments WHERE organization_id = $1 AND id = $2`, args: []any{organizationID, departmentID}, want: 1},
		{name: "idempotency", query: `SELECT count(*) FROM organization_idempotency_records WHERE actor_user_id = $1`, args: []any{target.UserID}, want: 0},
	} {
		var count int
		if err := fixture.postgres.QueryRow(fixture.ctx, test.query, test.args...).Scan(&count); err != nil || count != test.want {
			t.Fatalf("%s count = %d, error = %v", test.name, count, err)
		}
	}
	var creatorCleared, acceptorCleared bool
	var acceptedStatus string
	var retainedAcceptedAt pgtype.Timestamptz
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT created_by_user_id IS NULL FROM organization_invitations WHERE id = $1`, createdInvitationID).Scan(&creatorCleared); err != nil {
		t.Fatalf("read invitation creator: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT accepted_by_user_id IS NULL, status, accepted_at
		FROM organization_invitations WHERE id = $1
	`, acceptedInvitationID).Scan(&acceptorCleared, &acceptedStatus, &retainedAcceptedAt); err != nil {
		t.Fatalf("read invitation acceptor: %v", err)
	}
	if !creatorCleared || !acceptorCleared || acceptedStatus != "accepted" || !retainedAcceptedAt.Valid {
		t.Fatalf("invitation references creator=%v acceptor=%v status=%s accepted_at=%v", creatorCleared, acceptorCleared, acceptedStatus, retainedAcceptedAt.Valid)
	}
	var actorCleared, subjectCleared, objectCleared, metadataCleared bool
	var retainedOrganizationID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT actor_user_id IS NULL, subject_user_id IS NULL, object_id IS NULL,
		       metadata = '{}'::jsonb, organization_id
		FROM audit_events WHERE id = $1
	`, auditID).Scan(&actorCleared, &subjectCleared, &objectCleared, &metadataCleared, &retainedOrganizationID); err != nil {
		t.Fatalf("read Organization audit: %v", err)
	}
	if !actorCleared || !subjectCleared || !objectCleared || !metadataCleared || retainedOrganizationID != organizationID {
		t.Fatalf("audit cleared actor=%v subject=%v object=%v metadata=%v organization=%s", actorCleared, subjectCleared, objectCleared, metadataCleared, retainedOrganizationID)
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

func seedLifecycleWorkspace(
	t *testing.T,
	fixture *repositoryFixture,
	ownerUserID uuid.UUID,
	status string,
	memberUserIDs ...uuid.UUID,
) uuid.UUID {
	t.Helper()
	workspaceID := uuid.New()
	tx, err := fixture.postgres.BeginTx(fixture.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin workspace fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(fixture.ctx) }()
	var archivedAt any
	if status == "archived" {
		archivedAt = fixture.now
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at, archived_at)
		VALUES ($1, $2, 'Lifecycle Workspace', $3, 1, $4, $4, $5)
	`, workspaceID, ownerUserID, status, fixture.now, archivedAt); err != nil {
		t.Fatalf("insert workspace fixture: %v", err)
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, workspaceID, ownerUserID, fixture.now); err != nil {
		t.Fatalf("insert workspace Owner fixture: %v", err)
	}
	for _, memberUserID := range memberUserIDs {
		if _, err := tx.Exec(fixture.ctx, `
			INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
			VALUES ($1, $2, 'member', 1, $3, $3)
		`, workspaceID, memberUserID, fixture.now); err != nil {
			t.Fatalf("insert workspace Member fixture: %v", err)
		}
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatalf("commit workspace fixture: %v", err)
	}
	return workspaceID
}

func seedLifecycleOrganization(
	t *testing.T,
	fixture *repositoryFixture,
	ownerUserID uuid.UUID,
	status string,
	memberUserIDs ...uuid.UUID,
) uuid.UUID {
	t.Helper()
	organizationID := uuid.New()
	policyID := uuid.New()
	tx, err := fixture.postgres.BeginTx(fixture.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin Organization fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(fixture.ctx) }()
	var archivedAt any
	if status == "archived" {
		archivedAt = fixture.now
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organizations (
			id, display_name, status, revision, current_policy_snapshot_id,
			created_at, updated_at, archived_at
		) VALUES ($1, 'Lifecycle Organization', $2, 1, $3, $4, $4, $5)
	`, organizationID, status, policyID, fixture.now, archivedAt); err != nil {
		t.Fatalf("insert Organization fixture: %v", err)
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organization_memberships (
			organization_id, user_id, role, revision, joined_at, updated_at
		) VALUES ($1, $2, 'owner', 1, $3, $3)
	`, organizationID, ownerUserID, fixture.now); err != nil {
		t.Fatalf("insert Organization Owner fixture: %v", err)
	}
	for _, memberUserID := range memberUserIDs {
		if _, err := tx.Exec(fixture.ctx, `
			INSERT INTO organization_memberships (
				organization_id, user_id, role, revision, joined_at, updated_at
			) VALUES ($1, $2, 'member', 1, $3, $3)
		`, organizationID, memberUserID, fixture.now); err != nil {
			t.Fatalf("insert Organization Member fixture: %v", err)
		}
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document,
			content_digest, issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES (
			$1, $2, 1, 1,
			'{"schema_version":1,"models":{"allowlist":null},"tools":{"allowlist":null},"experience_candidates":{"mode":"manual_review"},"official_agents":{"installation":"allowed"}}'::jsonb,
			$3, 'https://accounts.example.com', 'organization-v1', $4, $5, $6
		)
	`, policyID, organizationID, bytes.Repeat([]byte{0xc1}, 32), bytes.Repeat([]byte{0xc2}, 64), ownerUserID, fixture.now); err != nil {
		t.Fatalf("insert Organization policy fixture: %v", err)
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatalf("commit Organization fixture: %v", err)
	}
	return organizationID
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
