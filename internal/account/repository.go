package account

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/space"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
	identity *secure.IdentityCodec
}

func NewPostgresRepository(postgres *pgxpool.Pool, identity *secure.IdentityCodec) *PostgresRepository {
	return &PostgresRepository{postgres: postgres, identity: identity}
}

func (r *PostgresRepository) Register(ctx context.Context, record RegistrationRecord) (Registration, error) {
	if r == nil || r.postgres == nil || r.identity == nil || record.ReceiptClaims.Purpose != verification.PurposeRegistration ||
		record.UserID == uuid.Nil || record.IdentityID == uuid.Nil || record.PersonalSpaceID == uuid.Nil ||
		record.TermsAcceptanceID == uuid.Nil || record.PrivacyAcceptanceID == uuid.Nil || record.AuditEventID == uuid.Nil ||
		!sealedMatchesClaims(r.identity, record.SealedIdentity, record.ReceiptClaims) {
		return Registration{}, ErrInvalidRequest
	}
	if record.Direct {
		if record.ReceiptClaims.ChallengeID != uuid.Nil || record.ReceiptClaims.Kind != secure.IdentityEmail {
			return Registration{}, ErrInvalidRequest
		}
	} else if record.ReceiptClaims.ChallengeID == uuid.Nil {
		return Registration{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Registration{}, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if !record.Direct {
		if err := r.lockAvailableReceipt(ctx, tx, record.ReceiptClaims); err != nil {
			return Registration{}, err
		}
	}
	if err := r.lockIdentityScope(ctx, tx, record.ReceiptClaims); err != nil {
		return Registration{}, err
	}
	if exists, err := r.identityExists(ctx, tx, record.ReceiptClaims); err != nil {
		return Registration{}, err
	} else if exists {
		return Registration{}, ErrIdentityConflict
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at)
		VALUES ($1, NULLIF($2, ''), 'active', $3, $3)
	`, record.UserID, record.Nickname, record.CreatedAt); err != nil {
		return Registration{}, classifyWriteError(err)
	}
	var verifiedAt any = record.CreatedAt
	if record.Direct {
		verifiedAt = nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identities (
			id, user_id, kind, encryption_key_id, nonce, ciphertext,
			lookup_key_id, lookup_hmac, verified_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, record.IdentityID, record.UserID, record.ReceiptClaims.Kind, record.SealedIdentity.EncryptionKeyID,
		record.SealedIdentity.Nonce, record.SealedIdentity.Ciphertext, record.SealedIdentity.LookupKeyID,
		record.SealedIdentity.LookupHMAC, verifiedAt, record.CreatedAt); err != nil {
		return Registration{}, classifyWriteError(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO password_credentials (user_id, password_hash, params_version, changed_at)
		VALUES ($1, $2, $3, $4)
	`, record.UserID, record.PasswordHash, record.PasswordParamsVersion, record.CreatedAt); err != nil {
		return Registration{}, classifyWriteError(err)
	}
	if err := space.InsertPersonal(ctx, tx, record.PersonalSpaceID, record.UserID, record.Nickname, record.CreatedAt); err != nil {
		return Registration{}, classifyWriteError(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO legal_acceptances (id, user_id, document_type, document_version, accepted_at)
		VALUES
			($1, $3, 'terms', $4, $6),
			($2, $3, 'privacy', $5, $6)
	`, record.TermsAcceptanceID, record.PrivacyAcceptanceID, record.UserID,
		record.TermsVersion, record.PrivacyVersion, record.CreatedAt); err != nil {
		return Registration{}, classifyWriteError(err)
	}
	if err := insertAuditEvent(ctx, tx, record.AuditEventID, "account_registered", record.UserID, "user", record.UserID, record.CreatedAt); err != nil {
		return Registration{}, classifyWriteError(err)
	}
	if !record.Direct {
		if err := markReceiptConsumed(ctx, tx, record.ReceiptClaims.ChallengeID, record.CreatedAt); err != nil {
			return Registration{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Registration{}, classifyWriteError(err)
	}
	return Registration{UserID: record.UserID, PersonalSpaceID: record.PersonalSpaceID}, nil
}

func (r *PostgresRepository) FindCredential(
	ctx context.Context,
	kind secure.IdentityKind,
	candidates []secure.LookupIndex,
) (Credential, bool, error) {
	if r == nil || r.postgres == nil || len(candidates) == 0 {
		return Credential{}, false, nil
	}
	for _, candidate := range candidates {
		var credential Credential
		err := r.postgres.QueryRow(ctx, `
			SELECT
				u.id, ps.id, COALESCE(u.nickname, ''), u.status,
				pc.password_hash, pc.params_version
			FROM identities i
			JOIN users u ON u.id = i.user_id
			JOIN password_credentials pc ON pc.user_id = u.id
			JOIN personal_spaces ps ON ps.owner_user_id = u.id
			WHERE i.kind = $1 AND i.lookup_key_id = $2 AND i.lookup_hmac = $3
		`, kind, candidate.KeyID, candidate.HMAC).Scan(
			&credential.UserID, &credential.PersonalSpaceID, &credential.Nickname,
			&credential.Status, &credential.PasswordHash, &credential.ParamsVersion,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return Credential{}, false, ErrServiceUnavailable
		}
		return credential, true, nil
	}
	return Credential{}, false, nil
}

func (r *PostgresRepository) UpdatePasswordHash(
	ctx context.Context,
	userID uuid.UUID,
	passwordHash string,
	paramsVersion int,
	changedAt time.Time,
) error {
	result, err := r.postgres.Exec(ctx, `
		UPDATE password_credentials
		SET password_hash = $2, params_version = $3, changed_at = $4
		WHERE user_id = $1
	`, userID, passwordHash, paramsVersion, changedAt)
	if err != nil {
		return ErrServiceUnavailable
	}
	if result.RowsAffected() != 1 {
		return ErrAccountNotFound
	}
	return nil
}

func (r *PostgresRepository) ResetPassword(ctx context.Context, record PasswordResetRecord) error {
	if r == nil || r.postgres == nil || r.identity == nil || record.ReceiptClaims.Purpose != verification.PurposePasswordReset ||
		record.AuditEventID == uuid.Nil {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	userID, found, err := r.findUserByClaims(ctx, tx, record.ReceiptClaims)
	if err != nil {
		return err
	}
	if !found {
		return ErrAccountNotFound
	}
	if err := lockAccountUser(ctx, tx, userID); err != nil {
		return err
	}
	status, err := accountStatusForUpdate(ctx, tx, userID)
	if err != nil {
		return err
	}
	if status != "active" && status != "pending_deletion" {
		return ErrAccountNotFound
	}
	if err := r.lockAvailableReceipt(ctx, tx, record.ReceiptClaims); err != nil {
		return err
	}
	ownerID, stillBound, err := r.findUserByClaims(ctx, tx, record.ReceiptClaims)
	if err != nil {
		return err
	}
	if !stillBound || ownerID != userID {
		return ErrAccountNotFound
	}
	result, err := tx.Exec(ctx, `
		UPDATE password_credentials
		SET password_hash = $2, params_version = $3, changed_at = $4
		WHERE user_id = $1
	`, userID, record.PasswordHash, record.PasswordParamsVersion, record.ChangedAt)
	if err != nil || result.RowsAffected() != 1 {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET password_security_version = password_security_version + 1, updated_at = $2
		WHERE id = $1
	`, userID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = $2, revoked_reason = 'password_reset'
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := insertAuditEvent(ctx, tx, record.AuditEventID, "password_reset", userID, "user", userID, record.ChangedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := markReceiptConsumed(ctx, tx, record.ReceiptClaims.ChallengeID, record.ChangedAt); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyWriteError(err)
	}
	return nil
}

func (r *PostgresRepository) BindIdentity(ctx context.Context, record IdentityBindingRecord) error {
	if r == nil || r.postgres == nil || r.identity == nil || record.ReceiptClaims.Purpose != verification.PurposeBindIdentity ||
		record.UserID == uuid.Nil || record.IdentityID == uuid.Nil || record.AuditEventID == uuid.Nil ||
		!sealedMatchesClaims(r.identity, record.SealedIdentity, record.ReceiptClaims) {
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
	if err := r.lockIdentityScope(ctx, tx, record.ReceiptClaims); err != nil {
		return err
	}
	if bound, err := r.identityExists(ctx, tx, record.ReceiptClaims); err != nil {
		return err
	} else if bound {
		return ErrIdentityConflict
	}
	var kindAlreadyBound bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM identities WHERE user_id = $1 AND kind = $2)
	`, record.UserID, record.ReceiptClaims.Kind).Scan(&kindAlreadyBound); err != nil {
		return ErrServiceUnavailable
	}
	if kindAlreadyBound {
		return ErrIdentityConflict
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identities (
			id, user_id, kind, encryption_key_id, nonce, ciphertext,
			lookup_key_id, lookup_hmac, verified_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
	`, record.IdentityID, record.UserID, record.ReceiptClaims.Kind, record.SealedIdentity.EncryptionKeyID,
		record.SealedIdentity.Nonce, record.SealedIdentity.Ciphertext, record.SealedIdentity.LookupKeyID,
		record.SealedIdentity.LookupHMAC, record.CreatedAt); err != nil {
		return classifyWriteError(err)
	}
	if err := insertAuditEvent(ctx, tx, record.AuditEventID, "identity_bound", record.UserID, "user", record.UserID, record.CreatedAt); err != nil {
		return ErrServiceUnavailable
	}
	if err := markReceiptConsumed(ctx, tx, record.ReceiptClaims.ChallengeID, record.CreatedAt); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyWriteError(err)
	}
	return nil
}

func (r *PostgresRepository) lockAvailableReceipt(
	ctx context.Context,
	tx pgx.Tx,
	claims verification.ReceiptClaims,
) error {
	var kind secure.IdentityKind
	var lookupKeyID string
	var lookupHMAC []byte
	var consumedAt pgtype.Timestamptz
	var receiptConsumedAt pgtype.Timestamptz
	err := tx.QueryRow(ctx, `
		SELECT identity_kind, target_lookup_key_id, target_lookup_hmac, consumed_at, receipt_consumed_at
		FROM verification_challenges
		WHERE id = $1 AND purpose = $2
		FOR UPDATE
	`, claims.ChallengeID, claims.Purpose).Scan(&kind, &lookupKeyID, &lookupHMAC, &consumedAt, &receiptConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrReceiptUnavailable
	}
	if err != nil {
		return ErrServiceUnavailable
	}
	if !consumedAt.Valid || receiptConsumedAt.Valid || kind != claims.Kind {
		return ErrReceiptUnavailable
	}
	for _, candidate := range r.identity.LookupCandidates(claims.Kind, claims.NormalizedIdentity) {
		if candidate.KeyID == lookupKeyID && len(candidate.HMAC) == len(lookupHMAC) &&
			subtle.ConstantTimeCompare(candidate.HMAC, lookupHMAC) == 1 {
			return nil
		}
	}
	return ErrReceiptUnavailable
}

func (r *PostgresRepository) findUserByClaims(
	ctx context.Context,
	tx pgx.Tx,
	claims verification.ReceiptClaims,
) (uuid.UUID, bool, error) {
	for _, candidate := range r.identity.LookupCandidates(claims.Kind, claims.NormalizedIdentity) {
		var userID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT user_id FROM identities
			WHERE kind = $1 AND lookup_key_id = $2 AND lookup_hmac = $3
		`, claims.Kind, candidate.KeyID, candidate.HMAC).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return uuid.Nil, false, ErrServiceUnavailable
		}
		return userID, true, nil
	}
	return uuid.Nil, false, nil
}

func (r *PostgresRepository) lockIdentityScope(
	ctx context.Context,
	tx pgx.Tx,
	claims verification.ReceiptClaims,
) error {
	candidates := r.identity.LookupCandidates(claims.Kind, claims.NormalizedIdentity)
	if len(candidates) == 0 {
		return ErrReceiptUnavailable
	}
	stable := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.KeyID < stable.KeyID {
			stable = candidate
		}
	}
	if len(stable.HMAC) < 8 {
		return ErrReceiptUnavailable
	}
	lockID := int64(binary.BigEndian.Uint64(stable.HMAC[:8]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (r *PostgresRepository) identityExists(
	ctx context.Context,
	tx pgx.Tx,
	claims verification.ReceiptClaims,
) (bool, error) {
	for _, candidate := range r.identity.LookupCandidates(claims.Kind, claims.NormalizedIdentity) {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM identities
				WHERE kind = $1 AND lookup_key_id = $2 AND lookup_hmac = $3
			)
		`, claims.Kind, candidate.KeyID, candidate.HMAC).Scan(&exists); err != nil {
			return false, ErrServiceUnavailable
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

func markReceiptConsumed(ctx context.Context, tx pgx.Tx, challengeID uuid.UUID, consumedAt time.Time) error {
	result, err := tx.Exec(ctx, `
		UPDATE verification_challenges
		SET receipt_consumed_at = $2
		WHERE id = $1 AND consumed_at IS NOT NULL AND receipt_consumed_at IS NULL
	`, challengeID, consumedAt)
	if err != nil {
		return ErrServiceUnavailable
	}
	if result.RowsAffected() != 1 {
		return ErrReceiptUnavailable
	}
	return nil
}

func sealedMatchesClaims(codec *secure.IdentityCodec, sealed secure.SealedIdentity, claims verification.ReceiptClaims) bool {
	for _, candidate := range codec.LookupCandidates(claims.Kind, claims.NormalizedIdentity) {
		if candidate.KeyID == sealed.LookupKeyID && len(candidate.HMAC) == len(sealed.LookupHMAC) &&
			subtle.ConstantTimeCompare(candidate.HMAC, sealed.LookupHMAC) == 1 {
			return true
		}
	}
	return false
}

func insertAuditEvent(
	ctx context.Context,
	tx pgx.Tx,
	eventID uuid.UUID,
	eventType string,
	actorUserID uuid.UUID,
	objectType string,
	objectID uuid.UUID,
	createdAt time.Time,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, object_type, object_id,
			outcome, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, 'success', '{}'::jsonb, $6)
	`, eventID, eventType, actorUserID, objectType, objectID, createdAt)
	return err
}

func classifyWriteError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" &&
		postgresError.ConstraintName == "identities_kind_lookup_hmac_key" {
		return ErrIdentityConflict
	}
	return ErrServiceUnavailable
}
