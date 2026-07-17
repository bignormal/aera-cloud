package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
}

func (r *PostgresRepository) AccessActive(ctx context.Context, binding AccessBinding, now time.Time) (bool, error) {
	if r == nil || r.postgres == nil || !validAccessBinding(binding) {
		return false, ErrUnavailable
	}
	var active bool
	if err := r.postgres.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM sessions s
			JOIN users u ON u.id = s.user_id
			JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
			JOIN personal_spaces ps ON ps.id = $4 AND ps.owner_user_id = s.user_id
			WHERE s.id = $1 AND s.user_id = $2 AND s.device_id = $3
			  AND s.revoked_at IS NULL AND s.expires_at > $5
			  AND u.status = 'active' AND d.status = 'active' AND ps.status = 'active'
		)
	`, binding.SessionID, binding.UserID, binding.DeviceID, binding.PersonalSpaceID, now.UTC()).Scan(&active); err != nil {
		return false, ErrUnavailable
	}
	return active, nil
}

func (r *PostgresRepository) Create(ctx context.Context, record CreateRecord) error {
	if r == nil || r.postgres == nil {
		return ErrUnavailable
	}
	return createSession(ctx, r.postgres, record)
}

func (r *PostgresRepository) CreateInTx(ctx context.Context, tx pgx.Tx, record CreateRecord) error {
	if r == nil || r.postgres == nil || tx == nil {
		return ErrUnavailable
	}
	return createSession(ctx, tx, record)
}

type sessionExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func createSession(ctx context.Context, executor sessionExecutor, record CreateRecord) error {
	if !validBinding(record.Binding) || record.SessionID == uuid.Nil ||
		record.FamilyID == uuid.Nil || len(record.RefreshTokenHash) != 32 || !record.ExpiresAt.After(record.IssuedAt) {
		return ErrSessionRevoked
	}
	var valid bool
	if err := executor.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM users u
			JOIN devices d ON d.user_id = u.id
			JOIN personal_spaces ps ON ps.owner_user_id = u.id
			WHERE u.id = $1 AND d.id = $2 AND d.installation_id = $3 AND ps.id = $4
			  AND u.status = 'active' AND d.status = 'active' AND ps.status = 'active'
		)
	`, record.Binding.UserID, record.Binding.DeviceID, record.Binding.InstallationID, record.Binding.PersonalSpaceID).Scan(&valid); err != nil {
		return ErrUnavailable
	}
	if !valid {
		return ErrSessionRevoked
	}
	_, err := executor.Exec(ctx, `
		INSERT INTO sessions (
			id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, record.SessionID, record.Binding.UserID, record.Binding.DeviceID, record.FamilyID,
		record.RefreshTokenHash, record.IssuedAt, record.ExpiresAt)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *PostgresRepository) Rotate(
	ctx context.Context,
	refreshTokenHash []byte,
	successor SuccessorRecord,
	now time.Time,
) (Rotation, error) {
	if r == nil || r.postgres == nil || len(refreshTokenHash) != 32 || successor.SessionID == uuid.Nil ||
		len(successor.RefreshTokenHash) != 32 || !successor.ExpiresAt.After(successor.IssuedAt) {
		return Rotation{}, ErrSessionRevoked
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Rotation{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var sourceID uuid.UUID
	var familyID uuid.UUID
	var binding Binding
	var expiresAt time.Time
	var replacedAt pgtype.Timestamptz
	var revokedAt pgtype.Timestamptz
	var userStatus string
	var deviceStatus string
	err = tx.QueryRow(ctx, `
		SELECT
			s.id, s.family_id, s.user_id, s.device_id, d.installation_id, ps.id,
			s.expires_at, s.replaced_at, s.revoked_at, u.status, d.status
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN devices d ON d.id = s.device_id
		JOIN personal_spaces ps ON ps.owner_user_id = s.user_id
		WHERE s.refresh_token_hash = $1
		FOR UPDATE OF s
	`, refreshTokenHash).Scan(
		&sourceID, &familyID, &binding.UserID, &binding.DeviceID, &binding.InstallationID, &binding.PersonalSpaceID,
		&expiresAt, &replacedAt, &revokedAt, &userStatus, &deviceStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rotation{}, ErrSessionRevoked
	}
	if err != nil {
		return Rotation{}, ErrUnavailable
	}
	if replacedAt.Valid {
		if _, err := tx.Exec(ctx, `
			UPDATE sessions
			SET revoked_at = COALESCE(revoked_at, $2), revoked_reason = 'refresh_replay',
				replay_detected_at = CASE WHEN id = $3 THEN $2 ELSE replay_detected_at END
			WHERE family_id = $1
		`, familyID, now, sourceID); err != nil {
			return Rotation{}, ErrUnavailable
		}
		if err := tx.Commit(ctx); err != nil {
			return Rotation{}, ErrUnavailable
		}
		return Rotation{}, ErrSessionRevoked
	}
	accountStateError := error(ErrSessionRevoked)
	if userStatus == "pending_deletion" {
		accountStateError = ErrAccountPendingDeletion
	} else if userStatus == "disabled" {
		accountStateError = ErrAccountDisabled
	}
	if revokedAt.Valid || !now.Before(expiresAt) || userStatus != "active" || deviceStatus != "active" {
		if _, err := tx.Exec(ctx, `
			UPDATE sessions
			SET revoked_at = COALESCE(revoked_at, $2), revoked_reason = COALESCE(revoked_reason, 'session_invalid')
			WHERE family_id = $1
		`, familyID, now); err != nil {
			return Rotation{}, ErrUnavailable
		}
		if err := tx.Commit(ctx); err != nil {
			return Rotation{}, ErrUnavailable
		}
		return Rotation{}, accountStateError
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sessions (
			id, user_id, device_id, family_id, refresh_token_hash,
			rotated_from_session_id, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, successor.SessionID, binding.UserID, binding.DeviceID, familyID, successor.RefreshTokenHash,
		sourceID, successor.IssuedAt, successor.ExpiresAt); err != nil {
		return Rotation{}, ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE sessions SET replaced_at = $2 WHERE id = $1`, sourceID, now); err != nil {
		return Rotation{}, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return Rotation{}, ErrUnavailable
	}
	return Rotation{SessionID: successor.SessionID, FamilyID: familyID, Binding: binding}, nil
}

func (r *PostgresRepository) RevokeFamily(ctx context.Context, familyID uuid.UUID, reason string, revokedAt time.Time) error {
	if r == nil || r.postgres == nil || familyID == uuid.Nil || reason == "" {
		return ErrUnavailable
	}
	_, err := r.postgres.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $2), revoked_reason = COALESCE(revoked_reason, $3)
		WHERE family_id = $1
	`, familyID, revokedAt, reason)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *PostgresRepository) RevokeByToken(ctx context.Context, refreshTokenHash []byte, revokedAt time.Time) error {
	if r == nil || r.postgres == nil || len(refreshTokenHash) != 32 {
		return ErrSessionRevoked
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var familyID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT family_id FROM sessions WHERE refresh_token_hash = $1 FOR UPDATE
	`, refreshTokenHash).Scan(&familyID); errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionRevoked
	} else if err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $2), revoked_reason = COALESCE(revoked_reason, 'user_logout')
		WHERE family_id = $1
	`, familyID, revokedAt); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}
