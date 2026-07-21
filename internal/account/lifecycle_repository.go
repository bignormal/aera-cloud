package account

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const deletionRecoveryWindow = 7 * 24 * time.Hour

func (r *PostgresRepository) Profile(ctx context.Context, userID uuid.UUID) (Profile, bool, error) {
	if r == nil || r.postgres == nil || userID == uuid.Nil {
		return Profile{}, false, ErrServiceUnavailable
	}
	var profile Profile
	var identityKinds []string
	err := r.postgres.QueryRow(ctx, `
		SELECT u.id, ps.id, COALESCE(u.nickname, ''), u.status,
			array_agg(i.kind ORDER BY i.kind),
			(SELECT count(*) FROM workspaces owned WHERE owned.owner_user_id = u.id)
		FROM users u
		JOIN personal_spaces ps ON ps.owner_user_id = u.id
		JOIN identities i ON i.user_id = u.id
		WHERE u.id = $1
		GROUP BY u.id, ps.id
	`, userID).Scan(
		&profile.UserID, &profile.PersonalSpaceID, &profile.Nickname, &profile.Status, &identityKinds,
		&profile.OwnedWorkspaceCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, false, nil
	}
	if err != nil {
		return Profile{}, false, ErrServiceUnavailable
	}
	profile.IdentityKinds = make([]secure.IdentityKind, 0, len(identityKinds))
	for _, kind := range identityKinds {
		profile.IdentityKinds = append(profile.IdentityKinds, secure.IdentityKind(kind))
	}
	return profile, true, nil
}

func (r *PostgresRepository) FindCredentialByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (Credential, bool, error) {
	if r == nil || r.postgres == nil || userID == uuid.Nil {
		return Credential{}, false, nil
	}
	var credential Credential
	err := r.postgres.QueryRow(ctx, `
		SELECT
			u.id, ps.id, COALESCE(u.nickname, ''), u.status,
			pc.password_hash, pc.params_version
		FROM users u
		JOIN password_credentials pc ON pc.user_id = u.id
		JOIN personal_spaces ps ON ps.owner_user_id = u.id
		WHERE u.id = $1
	`, userID).Scan(
		&credential.UserID, &credential.PersonalSpaceID, &credential.Nickname,
		&credential.Status, &credential.PasswordHash, &credential.ParamsVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, ErrServiceUnavailable
	}
	return credential, true, nil
}

func (r *PostgresRepository) RemoveIdentity(ctx context.Context, record IdentityRemovalRecord) error {
	if r == nil || r.postgres == nil || record.UserID == uuid.Nil || record.AuditEventID == uuid.Nil ||
		(record.Kind != secure.IdentityEmail && record.Kind != secure.IdentityPhone) || record.RemovedAt.IsZero() {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockAccountUser(ctx, tx, record.UserID); err != nil {
		return err
	}
	status, err := accountStatusForUpdate(ctx, tx, record.UserID)
	if err != nil {
		return err
	}
	if status != "active" {
		return ErrAccountNotFound
	}
	rows, err := tx.Query(ctx, `SELECT kind FROM identities WHERE user_id = $1 FOR UPDATE`, record.UserID)
	if err != nil {
		return ErrServiceUnavailable
	}
	count := 0
	found := false
	for rows.Next() {
		var kind secure.IdentityKind
		if err := rows.Scan(&kind); err != nil {
			rows.Close()
			return ErrServiceUnavailable
		}
		count++
		found = found || kind == record.Kind
	}
	rows.Close()
	if rows.Err() != nil {
		return ErrServiceUnavailable
	}
	if !found {
		return ErrAccountNotFound
	}
	if count <= 1 {
		return ErrLastIdentity
	}
	result, err := tx.Exec(ctx, `DELETE FROM identities WHERE user_id = $1 AND kind = $2`, record.UserID, record.Kind)
	if err != nil {
		return ErrServiceUnavailable
	}
	if result.RowsAffected() != 1 {
		return ErrAccountNotFound
	}
	if err := insertAuditEvent(ctx, tx, record.AuditEventID, "identity_removed", record.UserID, "user", record.UserID, record.RemovedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (r *PostgresRepository) ChangePassword(ctx context.Context, record PasswordChangeRecord) error {
	if r == nil || r.postgres == nil || record.UserID == uuid.Nil || record.CurrentSessionID == uuid.Nil ||
		record.PasswordHash == "" || record.PasswordParamsVersion <= 0 || record.AuditEventID == uuid.Nil || record.ChangedAt.IsZero() {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockAccountUser(ctx, tx, record.UserID); err != nil {
		return err
	}
	status, err := accountStatusForUpdate(ctx, tx, record.UserID)
	if err != nil {
		return err
	}
	if status != "active" {
		return ErrAccountNotFound
	}
	var currentDeviceID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT device_id FROM sessions
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > $3
		FOR UPDATE
	`, record.CurrentSessionID, record.UserID, record.ChangedAt).Scan(&currentDeviceID); errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountNotFound
	} else if err != nil {
		return ErrServiceUnavailable
	}
	result, err := tx.Exec(ctx, `
		UPDATE password_credentials
		SET password_hash = $2, params_version = $3, changed_at = $4
		WHERE user_id = $1
	`, record.UserID, record.PasswordHash, record.PasswordParamsVersion, record.ChangedAt)
	if err != nil || result.RowsAffected() != 1 {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET password_security_version = password_security_version + 1, updated_at = $2
		WHERE id = $1
	`, record.UserID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, $3), updated_at = $3
		WHERE user_id = $1 AND id <> $2
	`, record.UserID, currentDeviceID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $3), revoked_reason = COALESCE(revoked_reason, 'password_change')
		WHERE user_id = $1 AND id <> $2
	`, record.UserID, record.CurrentSessionID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE offline_entitlement_issuances
		SET revoked_at = COALESCE(revoked_at, $3)
		WHERE user_id = $1 AND device_id <> $2
	`, record.UserID, currentDeviceID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := insertAuditEvent(ctx, tx, record.AuditEventID, "password_changed", record.UserID, "user", record.UserID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (r *PostgresRepository) RequestDeletion(ctx context.Context, record DeletionRequestRecord) error {
	if r == nil || r.postgres == nil || r.identity == nil || record.UserID == uuid.Nil || record.AuditEventID == uuid.Nil ||
		record.ReceiptClaims.Purpose != verification.PurposeAccountDeletion || record.RequestedAt.IsZero() {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockAccountUser(ctx, tx, record.UserID); err != nil {
		return err
	}
	status, err := accountStatusForUpdate(ctx, tx, record.UserID)
	if err != nil {
		return err
	}
	if status != "active" {
		return ErrAccountNotFound
	}
	if err := r.lockAvailableReceipt(ctx, tx, record.ReceiptClaims); err != nil {
		return err
	}
	ownerID, found, err := r.findUserByClaims(ctx, tx, record.ReceiptClaims)
	if err != nil {
		return err
	}
	if !found || ownerID != record.UserID {
		return ErrAccountNotFound
	}
	ownedOrganizationCount, err := lockOwnedOrganizations(ctx, tx, record.UserID)
	if err != nil {
		return err
	}
	if ownedOrganizationCount > 0 {
		return &OrganizationOwnerTransferRequiredError{OwnedOrganizationCount: ownedOrganizationCount}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET status = 'pending_deletion', deletion_requested_at = $2, deletion_finalized_at = NULL, updated_at = $2
		WHERE id = $1
	`, record.UserID, record.RequestedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE personal_spaces SET status = 'disabled', updated_at = $2 WHERE owner_user_id = $1`, record.UserID, record.RequestedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2), updated_at = $2
		WHERE user_id = $1
	`, record.UserID, record.RequestedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $2), revoked_reason = COALESCE(revoked_reason, 'account_deletion')
		WHERE user_id = $1
	`, record.UserID, record.RequestedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE offline_entitlement_issuances SET revoked_at = COALESCE(revoked_at, $2) WHERE user_id = $1
	`, record.UserID, record.RequestedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := insertAuditEvent(ctx, tx, record.AuditEventID, "account_deletion_requested", record.UserID, "user", record.UserID, record.RequestedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := markReceiptConsumed(ctx, tx, record.ReceiptClaims.ChallengeID, record.RequestedAt); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func lockOwnedOrganizations(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int, error) {
	rows, err := tx.Query(ctx, `
		SELECT organization.id
		FROM organizations organization
		JOIN organization_memberships membership
		  ON membership.organization_id = organization.id
		WHERE membership.user_id = $1
		  AND membership.role = 'owner'
		  AND organization.status IN ('active', 'archived')
		ORDER BY organization.id
		FOR UPDATE OF organization, membership
	`, userID)
	if err != nil {
		return 0, ErrServiceUnavailable
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var organizationID uuid.UUID
		if err := rows.Scan(&organizationID); err != nil || organizationID == uuid.Nil {
			return 0, ErrServiceUnavailable
		}
		count++
	}
	if rows.Err() != nil {
		return 0, ErrServiceUnavailable
	}
	return count, nil
}

func (r *PostgresRepository) RecoverDeletion(ctx context.Context, record DeletionRecoveryRecord) error {
	if r == nil || r.postgres == nil || r.identity == nil || record.UserID == uuid.Nil || record.AuditEventID == uuid.Nil ||
		record.ReceiptClaims.Purpose != verification.PurposeDeletionRecovery || record.RecoveredAt.IsZero() {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockAccountUser(ctx, tx, record.UserID); err != nil {
		return err
	}
	var status string
	var requestedAt pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		SELECT status, deletion_requested_at FROM users WHERE id = $1 FOR UPDATE
	`, record.UserID).Scan(&status, &requestedAt); errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountNotFound
	} else if err != nil {
		return ErrServiceUnavailable
	}
	if status != "pending_deletion" || !requestedAt.Valid {
		return ErrAccountNotFound
	}
	if !record.RecoveredAt.Before(requestedAt.Time.Add(deletionRecoveryWindow)) {
		return ErrDeletionWindowExpired
	}
	if err := r.lockAvailableReceipt(ctx, tx, record.ReceiptClaims); err != nil {
		return err
	}
	ownerID, found, err := r.findUserByClaims(ctx, tx, record.ReceiptClaims)
	if err != nil {
		return err
	}
	if !found || ownerID != record.UserID {
		return ErrAccountNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET status = 'active', deletion_requested_at = NULL, deletion_finalized_at = NULL, updated_at = $2
		WHERE id = $1
	`, record.UserID, record.RecoveredAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE personal_spaces SET status = 'active', updated_at = $2 WHERE owner_user_id = $1`, record.UserID, record.RecoveredAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := insertAuditEvent(ctx, tx, record.AuditEventID, "account_deletion_recovered", record.UserID, "user", record.UserID, record.RecoveredAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := markReceiptConsumed(ctx, tx, record.ReceiptClaims.ChallengeID, record.RecoveredAt); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (r *PostgresRepository) FinalizeDeletion(
	ctx context.Context,
	userID uuid.UUID,
	auditEventID uuid.UUID,
	finalizedAt time.Time,
) error {
	if r == nil || r.postgres == nil || userID == uuid.Nil || auditEventID == uuid.Nil || finalizedAt.IsZero() {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockAccountUser(ctx, tx, userID); err != nil {
		return err
	}
	var status string
	var requestedAt pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		SELECT status, deletion_requested_at FROM users WHERE id = $1 FOR UPDATE
	`, userID).Scan(&status, &requestedAt); errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountNotFound
	} else if err != nil {
		return ErrServiceUnavailable
	}
	if status != "pending_deletion" || !requestedAt.Valid || finalizedAt.Before(requestedAt.Time.Add(deletionRecoveryWindow)) {
		return ErrDeletionWindowExpired
	}
	ownedOrganizationCount, err := lockOwnedOrganizations(ctx, tx, userID)
	if err != nil {
		return err
	}
	if ownedOrganizationCount > 0 {
		return &OrganizationOwnerTransferRequiredError{OwnedOrganizationCount: ownedOrganizationCount}
	}
	ownedWorkspaceRows, err := tx.Query(ctx, `
		SELECT id FROM workspaces WHERE owner_user_id = $1 ORDER BY id FOR UPDATE
	`, userID)
	if err != nil {
		return ErrServiceUnavailable
	}
	ownedWorkspaceIDs := make([]uuid.UUID, 0)
	for ownedWorkspaceRows.Next() {
		var workspaceID uuid.UUID
		if err := ownedWorkspaceRows.Scan(&workspaceID); err != nil {
			ownedWorkspaceRows.Close()
			return ErrServiceUnavailable
		}
		ownedWorkspaceIDs = append(ownedWorkspaceIDs, workspaceID)
	}
	ownedWorkspaceRows.Close()
	if ownedWorkspaceRows.Err() != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE audit_events
		SET actor_user_id = CASE WHEN actor_user_id = $1 THEN NULL ELSE actor_user_id END,
			subject_user_id = CASE WHEN subject_user_id = $1 THEN NULL ELSE subject_user_id END,
			device_id = CASE WHEN device_id IN (SELECT id FROM devices WHERE user_id = $1) THEN NULL ELSE device_id END,
			metadata = CASE
				WHEN metadata->>'owner_id' = $1::text
					OR metadata->>'membership_user_id' = $1::text
					OR metadata->>'workspace_id' IN (
						SELECT owned_workspace_id::text FROM unnest($2::uuid[]) AS owned(owned_workspace_id)
					)
					OR metadata->>'invitation_id' IN (
						SELECT invitation.id::text
						FROM workspace_invitations invitation
						WHERE invitation.workspace_id = ANY($2::uuid[])
						   OR invitation.created_by_user_id = $1
						   OR invitation.accepted_by_user_id = $1
					)
					OR metadata->>'invitation_id' IN (
						SELECT invitation.id::text
						FROM organization_invitations invitation
						WHERE invitation.created_by_user_id = $1
						   OR invitation.accepted_by_user_id = $1
					)
				THEN '{}'::jsonb
				ELSE metadata
			END,
			object_id = CASE
				WHEN actor_user_id = $1 OR subject_user_id = $1 OR object_id = $1
					OR device_id IN (SELECT id FROM devices WHERE user_id = $1)
					OR object_id IN (SELECT id FROM devices WHERE user_id = $1)
					OR metadata->>'owner_id' = $1::text
					OR object_id = ANY($2::uuid[])
					OR object_id IN (
						SELECT invitation.id
						FROM workspace_invitations invitation
						WHERE invitation.workspace_id = ANY($2::uuid[])
						   OR invitation.created_by_user_id = $1
						   OR invitation.accepted_by_user_id = $1
					)
					OR object_id IN (
						SELECT invitation.id
						FROM organization_invitations invitation
						WHERE invitation.created_by_user_id = $1
						   OR invitation.accepted_by_user_id = $1
					)
					OR object_id IN (
						SELECT id FROM agent_definitions WHERE owner_id = $1
						UNION ALL SELECT id FROM agent_versions WHERE owner_id = $1
						UNION ALL SELECT id FROM agent_version_revocations WHERE owner_id = $1
						UNION ALL SELECT id FROM installations WHERE owner_id = $1
						UNION ALL SELECT id FROM policy_snapshots WHERE owner_id = $1
						UNION ALL SELECT id FROM runtime_binding_records WHERE owner_id = $1
					) THEN NULL
				ELSE object_id
			END
		WHERE actor_user_id = $1
		   OR subject_user_id = $1
		   OR device_id IN (SELECT id FROM devices WHERE user_id = $1)
		   OR object_id = $1
		   OR object_id IN (SELECT id FROM devices WHERE user_id = $1)
		   OR metadata->>'owner_id' = $1::text
		   OR metadata->>'membership_user_id' = $1::text
		   OR object_id = ANY($2::uuid[])
		   OR metadata->>'workspace_id' IN (
				SELECT owned_workspace_id::text FROM unnest($2::uuid[]) AS owned(owned_workspace_id)
		   )
		   OR metadata->>'invitation_id' IN (
				SELECT invitation.id::text
				FROM workspace_invitations invitation
				WHERE invitation.workspace_id = ANY($2::uuid[])
				   OR invitation.created_by_user_id = $1
				   OR invitation.accepted_by_user_id = $1
		   )
		   OR metadata->>'invitation_id' IN (
				SELECT invitation.id::text
				FROM organization_invitations invitation
				WHERE invitation.created_by_user_id = $1
				   OR invitation.accepted_by_user_id = $1
		   )
		   OR object_id IN (
				SELECT invitation.id
				FROM workspace_invitations invitation
				WHERE invitation.workspace_id = ANY($2::uuid[])
				   OR invitation.created_by_user_id = $1
				   OR invitation.accepted_by_user_id = $1
		   )
		   OR object_id IN (
				SELECT invitation.id
				FROM organization_invitations invitation
				WHERE invitation.created_by_user_id = $1
				   OR invitation.accepted_by_user_id = $1
		   )
		   OR object_id IN (
				SELECT id FROM agent_definitions WHERE owner_id = $1
				UNION ALL SELECT id FROM agent_versions WHERE owner_id = $1
				UNION ALL SELECT id FROM agent_version_revocations WHERE owner_id = $1
				UNION ALL SELECT id FROM installations WHERE owner_id = $1
				UNION ALL SELECT id FROM policy_snapshots WHERE owner_id = $1
				UNION ALL SELECT id FROM runtime_binding_records WHERE owner_id = $1
		   )
	`, userID, ownedWorkspaceIDs); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE workspace_invitations
		SET created_by_user_id = CASE WHEN created_by_user_id = $1 THEN NULL ELSE created_by_user_id END,
			accepted_by_user_id = CASE WHEN accepted_by_user_id = $1 THEN NULL ELSE accepted_by_user_id END
		WHERE created_by_user_id = $1 OR accepted_by_user_id = $1
	`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM workspace_idempotency_records WHERE actor_user_id = $1`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE user_id = $1 AND role <> 'owner'`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE organization_invitations
		SET created_by_user_id = CASE WHEN created_by_user_id = $1 THEN NULL ELSE created_by_user_id END,
			accepted_by_user_id = CASE WHEN accepted_by_user_id = $1 THEN NULL ELSE accepted_by_user_id END
		WHERE created_by_user_id = $1 OR accepted_by_user_id = $1
	`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM organization_idempotency_records WHERE actor_user_id = $1`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM organization_memberships WHERE user_id = $1 AND role <> 'owner'`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM workspaces WHERE id = ANY($1::uuid[])`, ownedWorkspaceIDs); err != nil {
		return ErrServiceUnavailable
	}
	for _, statement := range []string{
		`DELETE FROM agent_control_idempotency_keys WHERE owner_id = $1`,
		`DELETE FROM runtime_binding_records WHERE owner_id = $1`,
		`DELETE FROM agent_version_revocations WHERE owner_id = $1`,
	} {
		if _, err := tx.Exec(ctx, statement, userID); err != nil {
			return ErrServiceUnavailable
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE installations
		SET status = 'archived', archived_at = COALESCE(archived_at, $2), updated_at = $2
		WHERE owner_id = $1
	`, userID, finalizedAt); err != nil {
		return ErrServiceUnavailable
	}
	for _, statement := range []string{
		`DELETE FROM policy_snapshots WHERE owner_id = $1`,
		`DELETE FROM installations WHERE owner_id = $1`,
		`UPDATE agent_definitions SET latest_version_id = NULL WHERE owner_id = $1`,
		`DELETE FROM agent_versions WHERE owner_id = $1`,
		`DELETE FROM agent_definitions WHERE owner_id = $1`,
	} {
		if _, err := tx.Exec(ctx, statement, userID); err != nil {
			return ErrServiceUnavailable
		}
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM verification_challenges vc
		USING identities i
		WHERE i.user_id = $1 AND vc.identity_kind = i.kind
		  AND vc.target_lookup_key_id = i.lookup_key_id AND vc.target_lookup_hmac = i.lookup_hmac
	`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_requests WHERE approved_user_id = $1`, userID); err != nil {
		return ErrServiceUnavailable
	}
	for _, statement := range []string{
		`DELETE FROM identities WHERE user_id = $1`,
		`DELETE FROM password_credentials WHERE user_id = $1`,
		`DELETE FROM legal_acceptances WHERE user_id = $1`,
		`DELETE FROM devices WHERE user_id = $1`,
		`DELETE FROM personal_spaces WHERE owner_user_id = $1`,
	} {
		if _, err := tx.Exec(ctx, statement, userID); err != nil {
			return ErrServiceUnavailable
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET nickname = NULL, status = 'disabled', administratively_disabled = FALSE,
			deletion_finalized_at = $2, updated_at = $2
		WHERE id = $1
	`, userID, finalizedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE experience_candidates
		SET submitted_by_user_id = NULL
		WHERE submitted_by_user_id = $1
	`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE experience_candidate_reviews
		SET reviewed_by_user_id = NULL
		WHERE reviewed_by_user_id = $1
	`, userID); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (id, event_type, outcome, metadata, created_at)
		VALUES ($1, 'account_deletion_finalized', 'success', '{}'::jsonb, $2)
	`, auditEventID, finalizedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func lockAccountUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	lockID := int64(binary.BigEndian.Uint64(userID[:8]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func accountStatusForUpdate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (string, error) {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAccountNotFound
	} else if err != nil {
		return "", ErrServiceUnavailable
	}
	return status, nil
}
