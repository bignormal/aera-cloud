package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
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

func (r *PostgresRepository) Authorize(ctx context.Context, record AuthorizationRecord, activeLimit int) (Device, error) {
	if r == nil || r.postgres == nil {
		return Device{}, ErrUnavailable
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Device{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	created, err := r.AuthorizeInTx(ctx, tx, record, activeLimit)
	if err != nil {
		return Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Device{}, classifyDeviceWriteError(err)
	}
	return created, nil
}

func (r *PostgresRepository) AuthorizeInTx(
	ctx context.Context,
	tx pgx.Tx,
	record AuthorizationRecord,
	activeLimit int,
) (Device, error) {
	if tx == nil {
		return Device{}, ErrUnavailable
	}
	if err := lockUser(ctx, tx, record.UserID); err != nil {
		return Device{}, err
	}
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, record.UserID).Scan(&accountStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Device{}, ErrAccountUnavailable
		}
		return Device{}, ErrUnavailable
	}
	if accountStatus != "active" {
		return Device{}, ErrAccountUnavailable
	}

	existing, found, err := findByInstallationForUpdate(ctx, tx, record.InstallationID)
	if err != nil {
		return Device{}, err
	}
	if found {
		if !bytes.Equal(existing.PublicKey, record.PublicKey) {
			return Device{}, ErrDeviceConflict
		}
		// A device key may move between product accounts only after the old
		// account has explicitly revoked it. Active/inactive installations stay
		// pinned to their owner, and a changed key is never accepted. This keeps
		// account switching possible without weakening installation ownership.
		if existing.UserID != record.UserID && existing.Status != "revoked" {
			return Device{}, ErrDeviceConflict
		}
		if existing.Status != "active" {
			allowed, err := hasCapacity(ctx, tx, record.UserID, activeLimit)
			if err != nil {
				return Device{}, err
			}
			if !allowed {
				return Device{}, ErrDeviceLimitReached
			}
		}
		_, err := tx.Exec(ctx, `
			UPDATE devices
			SET user_id = $2, display_name = $3, platform = $4, app_version = $5,
				status = 'active', last_seen_at = $6, revoked_at = NULL, updated_at = $6
			WHERE id = $1
		`, existing.ID, record.UserID, record.DisplayName, record.Platform, record.AppVersion, record.AuthorizedAt)
		if err != nil {
			return Device{}, ErrUnavailable
		}
		existing.UserID = record.UserID
		existing.DisplayName = record.DisplayName
		existing.Platform = record.Platform
		existing.AppVersion = record.AppVersion
		existing.Status = "active"
		existing.LastSeenAt = record.AuthorizedAt
		if err := insertDeviceAudit(ctx, tx, record.AuditEventID, "device_authorized", record.UserID, existing.ID, record.AuthorizedAt); err != nil {
			return Device{}, ErrUnavailable
		}
		return existing, nil
	}

	allowed, err := hasCapacity(ctx, tx, record.UserID, activeLimit)
	if err != nil {
		return Device{}, err
	}
	if !allowed {
		return Device{}, ErrDeviceLimitReached
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $8, $8)
	`, record.DeviceID, record.UserID, record.InstallationID, record.PublicKey, record.DisplayName,
		record.Platform, record.AppVersion, record.AuthorizedAt)
	if err != nil {
		return Device{}, classifyDeviceWriteError(err)
	}
	if err := insertDeviceAudit(ctx, tx, record.AuditEventID, "device_authorized", record.UserID, record.DeviceID, record.AuthorizedAt); err != nil {
		return Device{}, ErrUnavailable
	}
	return Device{
		ID: record.DeviceID, UserID: record.UserID, InstallationID: record.InstallationID,
		PublicKey: append([]byte(nil), record.PublicKey...), DisplayName: record.DisplayName,
		Platform: record.Platform, AppVersion: record.AppVersion, Status: "active", LastSeenAt: record.AuthorizedAt,
	}, nil
}

func (r *PostgresRepository) Revoke(
	ctx context.Context,
	userID uuid.UUID,
	deviceID uuid.UUID,
	auditEventID uuid.UUID,
	revokedAt time.Time,
) error {
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockUser(ctx, tx, userID); err != nil {
		return err
	}
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&accountStatus); errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountUnavailable
	} else if err != nil {
		return ErrUnavailable
	}
	if accountStatus != "active" {
		return ErrAccountUnavailable
	}
	result, err := tx.Exec(ctx, `
		UPDATE devices
		SET status = 'revoked', revoked_at = $3, updated_at = $3
		WHERE id = $1 AND user_id = $2 AND status <> 'revoked'
	`, deviceID, userID, revokedAt)
	if err != nil {
		return ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return ErrDeviceNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = $2, revoked_reason = 'device_revoked'
		WHERE device_id = $1 AND revoked_at IS NULL
	`, deviceID, revokedAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE offline_entitlement_issuances
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE device_id = $1
	`, deviceID, revokedAt); err != nil {
		return ErrUnavailable
	}
	if err := insertDeviceAudit(ctx, tx, auditEventID, "device_revoked", userID, deviceID, revokedAt); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *PostgresRepository) List(ctx context.Context, userID uuid.UUID) ([]Device, error) {
	if r == nil || r.postgres == nil || userID == uuid.Nil {
		return nil, ErrInvalidDevice
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR SHARE`, userID).Scan(&accountStatus); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAccountUnavailable
	} else if err != nil {
		return nil, ErrUnavailable
	}
	if accountStatus != "active" {
		return nil, ErrAccountUnavailable
	}
	rows, err := tx.Query(ctx, `
		SELECT id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at
		FROM devices
		WHERE user_id = $1 AND status = 'active'
		ORDER BY last_seen_at DESC, id
	`, userID)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	devices := make([]Device, 0)
	for rows.Next() {
		var found Device
		if err := rows.Scan(
			&found.ID, &found.UserID, &found.InstallationID, &found.PublicKey,
			&found.DisplayName, &found.Platform, &found.AppVersion, &found.Status, &found.LastSeenAt,
		); err != nil {
			return nil, ErrUnavailable
		}
		devices = append(devices, found)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrUnavailable
	}
	return devices, nil
}

func (r *PostgresRepository) FindForSelfRevoke(ctx context.Context, deviceID uuid.UUID) (Device, error) {
	if r == nil || r.postgres == nil || deviceID == uuid.Nil {
		return Device{}, ErrInvalidDevice
	}
	var found Device
	err := r.postgres.QueryRow(ctx, `
		SELECT id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at
		FROM devices WHERE id = $1
	`, deviceID).Scan(
		&found.ID, &found.UserID, &found.InstallationID, &found.PublicKey,
		&found.DisplayName, &found.Platform, &found.AppVersion, &found.Status, &found.LastSeenAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	if err != nil {
		return Device{}, ErrUnavailable
	}
	return found, nil
}

func (r *PostgresRepository) SelfRevoke(ctx context.Context, record SelfRevocationRecord) error {
	if r == nil || r.postgres == nil || record.UserID == uuid.Nil || record.DeviceID == uuid.Nil ||
		record.InstallationID == uuid.Nil || len(record.NonceHash) != sha256.Size ||
		record.AuditEventID == uuid.Nil || record.RevokedAt.IsZero() {
		return ErrInvalidDevice
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var status string
	var userID uuid.UUID
	var installationID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT user_id, installation_id, status FROM devices WHERE id = $1 FOR UPDATE
	`, record.DeviceID).Scan(&userID, &installationID, &status); errors.Is(err, pgx.ErrNoRows) {
		return ErrDeviceNotFound
	} else if err != nil {
		return ErrUnavailable
	}
	var replayed bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM device_self_revocation_nonces WHERE device_id = $1 AND nonce_hash = $2
		)
	`, record.DeviceID, record.NonceHash).Scan(&replayed); err != nil {
		return ErrUnavailable
	}
	if replayed {
		return ErrSelfRevokeReplay
	}
	if userID != record.UserID || installationID != record.InstallationID || status != "active" {
		return ErrDeviceNotFound
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_self_revocation_nonces (device_id, nonce_hash, used_at) VALUES ($1, $2, $3)
	`, record.DeviceID, record.NonceHash, record.RevokedAt); err != nil {
		return classifySelfRevokeWriteError(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET status = 'revoked', revoked_at = $2, updated_at = $2 WHERE id = $1
	`, record.DeviceID, record.RevokedAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $2), revoked_reason = COALESCE(revoked_reason, 'device_self_revoked')
		WHERE device_id = $1
	`, record.DeviceID, record.RevokedAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE offline_entitlement_issuances SET revoked_at = COALESCE(revoked_at, $2) WHERE device_id = $1
	`, record.DeviceID, record.RevokedAt); err != nil {
		return ErrUnavailable
	}
	if err := insertDeviceAudit(ctx, tx, record.AuditEventID, "device_self_revoked", record.UserID, record.DeviceID, record.RevokedAt); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func lockUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	lockID := int64(binary.BigEndian.Uint64(userID[:8]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return ErrUnavailable
	}
	return nil
}

func hasCapacity(ctx context.Context, tx pgx.Tx, userID uuid.UUID, activeLimit int) (bool, error) {
	var active int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM devices WHERE user_id = $1 AND status = 'active'
	`, userID).Scan(&active); err != nil {
		return false, ErrUnavailable
	}
	return active < activeLimit, nil
}

func findByInstallationForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	installationID uuid.UUID,
) (Device, bool, error) {
	var found Device
	var revokedAt pgtype.Timestamptz
	err := tx.QueryRow(ctx, `
		SELECT id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, revoked_at
		FROM devices
		WHERE installation_id = $1
		FOR UPDATE
	`, installationID).Scan(
		&found.ID, &found.UserID, &found.InstallationID, &found.PublicKey, &found.DisplayName,
		&found.Platform, &found.AppVersion, &found.Status, &found.LastSeenAt, &revokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, false, nil
	}
	if err != nil {
		return Device{}, false, ErrUnavailable
	}
	return found, true, nil
}

func insertDeviceAudit(
	ctx context.Context,
	tx pgx.Tx,
	eventID uuid.UUID,
	eventType string,
	userID uuid.UUID,
	deviceID uuid.UUID,
	createdAt time.Time,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, device_id, object_type, object_id,
			outcome, metadata, created_at
		) VALUES ($1, $2, $3, $4, 'device', $4, 'success', '{}'::jsonb, $5)
	`, eventID, eventType, userID, deviceID, createdAt)
	return err
}

func classifyDeviceWriteError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" &&
		(postgresError.ConstraintName == "devices_installation_id_key" || postgresError.ConstraintName == "devices_public_key_key") {
		return ErrDeviceConflict
	}
	return ErrUnavailable
}

func classifySelfRevokeWriteError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" &&
		postgresError.ConstraintName == "device_self_revocation_nonces_pkey" {
		return ErrSelfRevokeReplay
	}
	return ErrUnavailable
}
