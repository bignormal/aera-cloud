package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
}

func (r *PostgresRepository) Save(ctx context.Context, record AuthorizationRecord) error {
	if r == nil || r.postgres == nil || !validAuthorizationRecord(record) {
		return ErrInvalidRequest
	}
	_, err := r.postgres.Exec(ctx, `
		INSERT INTO oauth_requests (
			id, client_id, redirect_uri, pkce_challenge, pkce_method,
			state_hash, state_ciphertext, state_encryption_key_id, state_nonce,
			installation_id, device_public_key, device_key_digest,
			device_display_name, device_platform, app_version,
			expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`, record.ID, record.ClientID, record.RedirectURI, record.CodeChallenge, record.CodeChallengeMethod,
		record.StateHash, record.StateCiphertext, record.StateEncryptionKeyID, record.StateNonce,
		record.InstallationID, record.DevicePublicKey, record.DeviceKeyDigest,
		record.DeviceDisplayName, record.DevicePlatform, record.AppVersion,
		record.ExpiresAt, record.CreatedAt)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *PostgresRepository) Approve(ctx context.Context, approval ApprovalRecord) (ApprovedRequest, error) {
	if r == nil || r.postgres == nil || approval.RequestID == uuid.Nil || approval.UserID == uuid.Nil ||
		approval.CodeID == uuid.Nil || len(approval.CodeHash) != 32 || !approval.CodeExpiresAt.After(approval.ApprovedAt) {
		return ApprovedRequest{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ApprovedRequest{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	record, approvedUserID, approvedAt, consumedAt, err := readAuthorizationForUpdate(ctx, tx, approval.RequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApprovedRequest{}, ErrInvalidAuthorization
	}
	if err != nil {
		return ApprovedRequest{}, ErrUnavailable
	}
	if !approval.ApprovedAt.Before(record.ExpiresAt) || approvedUserID.Valid || approvedAt.Valid || consumedAt.Valid {
		return ApprovedRequest{}, ErrInvalidAuthorization
	}
	var active bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users u
			JOIN personal_spaces ps ON ps.owner_user_id = u.id
			WHERE u.id = $1 AND u.status = 'active' AND ps.status = 'active'
		)
	`, approval.UserID).Scan(&active); err != nil {
		return ApprovedRequest{}, ErrUnavailable
	}
	if !active {
		return ApprovedRequest{}, ErrInvalidAuthorization
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_requests SET approved_user_id = $2, approved_at = $3 WHERE id = $1
	`, approval.RequestID, approval.UserID, approval.ApprovedAt); err != nil {
		return ApprovedRequest{}, ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO authorization_codes (id, oauth_request_id, code_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, approval.CodeID, approval.RequestID, approval.CodeHash, approval.CodeExpiresAt, approval.ApprovedAt); err != nil {
		return ApprovedRequest{}, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ApprovedRequest{}, ErrUnavailable
	}
	return ApprovedRequest{AuthorizationRecord: record}, nil
}

func (r *PostgresRepository) Exchange(
	ctx context.Context,
	codeHash []byte,
	now time.Time,
	finalize func(context.Context, pgx.Tx, Grant) (session.TokenSet, error),
) (session.TokenSet, error) {
	if r == nil || r.postgres == nil || len(codeHash) != 32 || finalize == nil {
		return session.TokenSet{}, ErrInvalidAuthorization
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return session.TokenSet{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var grant Grant
	var codeID uuid.UUID
	var codeExpiresAt time.Time
	var codeConsumedAt pgtype.Timestamptz
	var requestConsumedAt pgtype.Timestamptz
	err = tx.QueryRow(ctx, `
		SELECT
			r.id, r.client_id, r.redirect_uri, r.pkce_challenge, r.pkce_method,
			r.state_encryption_key_id, r.state_nonce, r.state_ciphertext, r.state_hash,
			r.installation_id, r.device_public_key, r.device_key_digest,
			r.device_display_name, r.device_platform, r.app_version,
			r.expires_at, r.created_at, r.approved_user_id, ps.id,
			ac.id, ac.expires_at, ac.consumed_at, r.consumed_at
		FROM authorization_codes ac
		JOIN oauth_requests r ON r.id = ac.oauth_request_id
		JOIN personal_spaces ps ON ps.owner_user_id = r.approved_user_id
		JOIN users u ON u.id = r.approved_user_id
		WHERE ac.code_hash = $1 AND u.status = 'active' AND ps.status = 'active'
		FOR UPDATE OF ac, r
	`, codeHash).Scan(
		&grant.ID, &grant.ClientID, &grant.RedirectURI, &grant.CodeChallenge, &grant.CodeChallengeMethod,
		&grant.StateEncryptionKeyID, &grant.StateNonce, &grant.StateCiphertext, &grant.StateHash,
		&grant.InstallationID, &grant.DevicePublicKey, &grant.DeviceKeyDigest,
		&grant.DeviceDisplayName, &grant.DevicePlatform, &grant.AppVersion,
		&grant.ExpiresAt, &grant.CreatedAt, &grant.UserID, &grant.PersonalSpaceID,
		&codeID, &codeExpiresAt, &codeConsumedAt, &requestConsumedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return session.TokenSet{}, ErrInvalidAuthorization
	}
	if err != nil {
		return session.TokenSet{}, ErrUnavailable
	}
	if codeConsumedAt.Valid || requestConsumedAt.Valid {
		return session.TokenSet{}, ErrAuthorizationReplayed
	}
	if !now.Before(codeExpiresAt) || !now.Before(grant.ExpiresAt) {
		return session.TokenSet{}, ErrInvalidAuthorization
	}
	tokens, err := finalize(ctx, tx, grant)
	if err != nil {
		return session.TokenSet{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE authorization_codes SET consumed_at = $2 WHERE id = $1`, codeID, now); err != nil {
		return session.TokenSet{}, ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_requests SET consumed_at = $2 WHERE id = $1`, grant.ID, now); err != nil {
		return session.TokenSet{}, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return session.TokenSet{}, ErrUnavailable
	}
	return tokens, nil
}

func readAuthorizationForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	requestID uuid.UUID,
) (AuthorizationRecord, pgtype.UUID, pgtype.Timestamptz, pgtype.Timestamptz, error) {
	var record AuthorizationRecord
	var approvedUserID pgtype.UUID
	var approvedAt pgtype.Timestamptz
	var consumedAt pgtype.Timestamptz
	err := tx.QueryRow(ctx, `
		SELECT
			id, client_id, redirect_uri, pkce_challenge, pkce_method,
			state_encryption_key_id, state_nonce, state_ciphertext, state_hash,
			installation_id, device_public_key, device_key_digest,
			device_display_name, device_platform, app_version,
			expires_at, created_at, approved_user_id, approved_at, consumed_at
		FROM oauth_requests WHERE id = $1 FOR UPDATE
	`, requestID).Scan(
		&record.ID, &record.ClientID, &record.RedirectURI, &record.CodeChallenge, &record.CodeChallengeMethod,
		&record.StateEncryptionKeyID, &record.StateNonce, &record.StateCiphertext, &record.StateHash,
		&record.InstallationID, &record.DevicePublicKey, &record.DeviceKeyDigest,
		&record.DeviceDisplayName, &record.DevicePlatform, &record.AppVersion,
		&record.ExpiresAt, &record.CreatedAt, &approvedUserID, &approvedAt, &consumedAt,
	)
	return record, approvedUserID, approvedAt, consumedAt, err
}

func validAuthorizationRecord(record AuthorizationRecord) bool {
	return record.ID != uuid.Nil && record.ClientID == DesktopClientID && validRedirectURI(record.RedirectURI) &&
		record.CodeChallengeMethod == "S256" && validCodeChallenge(record.CodeChallenge) &&
		len(record.StateHash) == 32 && len(record.StateNonce) == 12 && len(record.StateCiphertext) > 16 &&
		record.StateEncryptionKeyID != "" && record.InstallationID != uuid.Nil &&
		len(record.DevicePublicKey) == 32 && len(record.DeviceKeyDigest) == 32 &&
		record.DeviceDisplayName != "" && record.DevicePlatform != "" && record.AppVersion != "" &&
		record.ExpiresAt.After(record.CreatedAt)
}
