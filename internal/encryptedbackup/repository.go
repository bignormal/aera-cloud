package encryptedbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
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

func (repository *PostgresRepository) AuthenticationDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID uuid.UUID,
) (AuthenticationDevice, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || deviceID == uuid.Nil {
		return AuthenticationDevice{}, ErrInvalidRequest
	}
	var found AuthenticationDevice
	err := repository.postgres.QueryRow(ctx, `
		SELECT user_id, id, public_key, status
		FROM devices
		WHERE user_id = $1 AND id = $2
	`, userID, deviceID).Scan(
		&found.UserID,
		&found.DeviceID,
		&found.PublicKey,
		&found.Status,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthenticationDevice{}, ErrUnauthorized
	}
	if err != nil {
		return AuthenticationDevice{}, ErrEncryptedUnavailable
	}
	return found, nil
}

func (repository *PostgresRepository) RegisterBackupDevice(
	ctx context.Context,
	record RegistrationRecord,
) (BackupDevice, bool, error) {
	if repository == nil || repository.postgres == nil ||
		record.UserID == uuid.Nil ||
		record.DeviceID == uuid.Nil ||
		record.KeyEpoch <= 0 ||
		record.Revision <= 0 ||
		len(record.PublicKey) != 32 ||
		len(record.Signature) != 64 ||
		record.RecordedAt.IsZero() {
		return BackupDevice{}, false, ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return BackupDevice{}, false, ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var identityStatus string
	if err := tx.QueryRow(ctx, `
		SELECT status FROM devices
		WHERE user_id = $1 AND id = $2
		FOR UPDATE
	`, record.UserID, record.DeviceID).Scan(&identityStatus); errors.Is(err, pgx.ErrNoRows) {
		return BackupDevice{}, false, ErrUnauthorized
	} else if err != nil {
		return BackupDevice{}, false, ErrEncryptedUnavailable
	}
	if identityStatus != "active" {
		return BackupDevice{}, false, ErrDeviceRevoked
	}

	latest, latestSignature, found, err := findLatestBackupDeviceForUpdate(
		ctx,
		tx,
		record.UserID,
		record.DeviceID,
	)
	if err != nil {
		return BackupDevice{}, false, err
	}
	if found &&
		latest.KeyEpoch == record.KeyEpoch &&
		latest.Revision == record.Revision &&
		bytes.Equal(latest.PublicKey, record.PublicKey) &&
		bytes.Equal(latestSignature, record.Signature) {
		if err := tx.Commit(ctx); err != nil {
			return BackupDevice{}, false, ErrEncryptedUnavailable
		}
		return latest, true, nil
	}
	if (!found && record.Revision != 1) ||
		(found && record.Revision != latest.Revision+1) ||
		(found && (record.KeyEpoch < latest.KeyEpoch || record.KeyEpoch > latest.KeyEpoch+1)) {
		return BackupDevice{}, false, ErrBackupConflict
	}

	var saved BackupDevice
	if found && record.KeyEpoch == latest.KeyEpoch {
		if latest.Status != "active" {
			return BackupDevice{}, false, ErrDeviceRevoked
		}
		_, err = tx.Exec(ctx, `
			UPDATE backup_devices
			SET public_key = $2,
			    registration_signature = $3,
			    revision = $4,
			    updated_at = $5
			WHERE id = $1
		`, latest.ID, record.PublicKey, record.Signature, record.Revision, record.RecordedAt)
		if err != nil {
			return BackupDevice{}, false, classifyBackupWriteError(err)
		}
		saved = latest
		saved.PublicKey = append([]byte(nil), record.PublicKey...)
		saved.Revision = record.Revision
		saved.UpdatedAt = record.RecordedAt
	} else {
		deviceID, err := secure.RandomUUID()
		if err != nil {
			return BackupDevice{}, false, ErrEncryptedUnavailable
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO backup_devices (
				id, user_id, device_id, key_epoch, public_key,
				registration_signature, revision, status, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $8)
		`, deviceID, record.UserID, record.DeviceID, record.KeyEpoch,
			record.PublicKey, record.Signature, record.Revision, record.RecordedAt)
		if err != nil {
			return BackupDevice{}, false, classifyBackupWriteError(err)
		}
		saved = BackupDevice{
			ID:        deviceID,
			UserID:    record.UserID,
			DeviceID:  record.DeviceID,
			KeyEpoch:  record.KeyEpoch,
			PublicKey: append([]byte(nil), record.PublicKey...),
			Revision:  record.Revision,
			Status:    "active",
			CreatedAt: record.RecordedAt,
			UpdatedAt: record.RecordedAt,
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return BackupDevice{}, false, classifyBackupWriteError(err)
	}
	return saved, false, nil
}

func (repository *PostgresRepository) RevokeBackupDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID uuid.UUID,
	revokedAt time.Time,
) error {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || deviceID == uuid.Nil || revokedAt.IsZero() {
		return ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	rows, err := tx.Query(ctx, `
		UPDATE backup_devices
		SET status = 'revoked', revoked_at = $3, updated_at = $3
		WHERE user_id = $1 AND device_id = $2 AND status = 'active'
		RETURNING id
	`, userID, deviceID, revokedAt)
	if err != nil {
		return ErrEncryptedUnavailable
	}
	var backupDeviceIDs []uuid.UUID
	for rows.Next() {
		var backupDeviceID uuid.UUID
		if err := rows.Scan(&backupDeviceID); err != nil {
			rows.Close()
			return ErrEncryptedUnavailable
		}
		backupDeviceIDs = append(backupDeviceIDs, backupDeviceID)
	}
	rows.Close()
	if rows.Err() != nil {
		return ErrEncryptedUnavailable
	}
	if len(backupDeviceIDs) == 0 {
		return ErrBackupNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE encrypted_backup_key_envelopes
		SET root_key_envelope = NULL,
		    destroyed_at = COALESCE(destroyed_at, $2)
		WHERE backup_device_id = ANY($1::uuid[])
		  AND root_key_envelope IS NOT NULL
	`, backupDeviceIDs, revokedAt); err != nil {
		return ErrEncryptedUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrEncryptedUnavailable
	}
	return nil
}

func (repository *PostgresRepository) BackupDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID uuid.UUID,
	keyEpoch int64,
) (BackupDevice, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || deviceID == uuid.Nil || keyEpoch <= 0 {
		return BackupDevice{}, ErrInvalidRequest
	}
	found, _, err := scanBackupDevice(repository.postgres.QueryRow(ctx, `
		SELECT id, user_id, device_id, key_epoch, public_key,
		       registration_signature, revision, status, created_at, updated_at, revoked_at
		FROM backup_devices
		WHERE user_id = $1 AND device_id = $2 AND key_epoch = $3
	`, userID, deviceID, keyEpoch))
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupDevice{}, ErrUnauthorized
	}
	if err != nil {
		return BackupDevice{}, ErrEncryptedUnavailable
	}
	return found, nil
}

func (repository *PostgresRepository) LatestBackupDeviceStatus(
	ctx context.Context,
	userID uuid.UUID,
	deviceID uuid.UUID,
) (string, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || deviceID == uuid.Nil {
		return "", ErrInvalidRequest
	}
	var status string
	err := repository.postgres.QueryRow(ctx, `
		SELECT status
		FROM backup_devices
		WHERE user_id = $1 AND device_id = $2
		ORDER BY revision DESC, key_epoch DESC
		LIMIT 1
	`, userID, deviceID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", ErrEncryptedUnavailable
	}
	return status, nil
}

func (repository *PostgresRepository) Initiate(
	ctx context.Context,
	record InitiateRecord,
) (Backup, bool, error) {
	if repository == nil || repository.postgres == nil ||
		record.ID == uuid.Nil || record.UserID == uuid.Nil ||
		len(record.Chunks) != record.ChunkCount ||
		record.SourceDeviceEnvelope.ID == uuid.Nil {
		return Backup{}, false, ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Backup{}, false, ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var existingUser uuid.UUID
	var existingDigest []byte
	var existingState string
	var existingExpiry time.Time
	err = tx.QueryRow(ctx, `
		SELECT user_id, public_envelope_digest, state, upload_expires_at
		FROM encrypted_profile_backups
		WHERE id = $1
		FOR UPDATE
	`, record.ID).Scan(&existingUser, &existingDigest, &existingState, &existingExpiry)
	if err == nil {
		if existingUser != record.UserID {
			return Backup{}, false, ErrBackupConflict
		}
		if bytes.Equal(existingDigest, record.PublicEnvelopeDigest[:]) {
			record.Backup.State = BackupState(existingState)
			record.Backup.UploadExpiresAt = existingExpiry
			if err := tx.Commit(ctx); err != nil {
				return Backup{}, false, ErrEncryptedUnavailable
			}
			return record.Backup, true, nil
		}
		return Backup{}, false, ErrBackupConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Backup{}, false, ErrEncryptedUnavailable
	}

	objectIDs := make(map[string]struct{}, len(record.Chunks)+1)
	objectIDs[record.Manifest.ObjectID] = struct{}{}
	for _, chunk := range record.Chunks {
		if _, exists := objectIDs[chunk.ObjectID]; exists {
			return Backup{}, false, ErrInvalidRequest
		}
		objectIDs[chunk.ObjectID] = struct{}{}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO encrypted_profile_backups (
			id, user_id, source_device_id, source_installation_id,
			source_definition_id, source_version_id, profile_lineage_id,
			parent_backup_id, format_version, cipher_suite, state,
			chunk_count, total_ciphertext_size,
			manifest_object_key, manifest_ciphertext_digest, manifest_ciphertext_size,
			public_envelope_digest, public_signature,
			recovery_salt, recovery_memory_kib, recovery_iterations, recovery_parallelism,
			recovery_root_key_envelope, wrapped_data_key,
			created_at, updated_at, upload_expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16,
			$17, $18, $19, $20, $21, $22, $23, $24, $25, $25, $26
		)
	`, record.ID, record.UserID, record.SourceDeviceID, record.SourceInstallationID,
		record.SourceDefinitionID, record.SourceVersionID, record.ProfileLineageID,
		record.ParentBackupID, record.FormatVersion, record.CipherSuite, record.State,
		record.ChunkCount, record.TotalCiphertextSize,
		record.Manifest.ObjectID, record.Manifest.CiphertextDigest[:], record.Manifest.CiphertextSize,
		record.PublicEnvelopeDigest[:], record.PublicSignature,
		record.Recovery.Salt, record.Recovery.MemoryKiB, record.Recovery.Iterations,
		record.Recovery.Parallelism, record.RecoveryRootKeyEnvelope, record.WrappedDataKey,
		record.CreatedAt, record.UploadExpiresAt)
	if err != nil {
		return Backup{}, false, classifyBackupWriteError(err)
	}
	for _, chunk := range record.Chunks {
		if _, err := tx.Exec(ctx, `
			INSERT INTO encrypted_backup_chunks (
				backup_id, chunk_index, object_key, ciphertext_digest,
				ciphertext_size, created_at
			) VALUES ($1, $2, $3, $4, $5, $6)
		`, record.ID, chunk.Index, chunk.ObjectID, chunk.CiphertextDigest[:],
			chunk.CiphertextSize, record.CreatedAt); err != nil {
			return Backup{}, false, classifyBackupWriteError(err)
		}
	}
	source := record.SourceDeviceEnvelope
	if _, err := tx.Exec(ctx, `
		INSERT INTO encrypted_backup_key_envelopes (
			id, backup_id, backup_device_id, key_epoch,
			root_key_envelope, root_key_envelope_digest, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, source.ID, source.BackupID, source.BackupDeviceID, source.KeyEpoch,
		source.RootKeyEnvelope, source.RootKeyEnvelopeDigest[:], source.CreatedAt); err != nil {
		return Backup{}, false, classifyBackupWriteError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Backup{}, false, classifyBackupWriteError(err)
	}
	return record.Backup, false, nil
}

func (repository *PostgresRepository) ChunkUploadTarget(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	index int,
) (UploadTarget, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil ||
		index < 0 || index >= maximumChunkCount {
		return UploadTarget{}, ErrInvalidRequest
	}
	var target UploadTarget
	var state string
	var digest []byte
	err := repository.postgres.QueryRow(ctx, `
		SELECT backup.id, backup.user_id, backup.source_device_id,
		       backup.state, backup.upload_expires_at,
		       chunk.object_key, chunk.ciphertext_digest, chunk.ciphertext_size
		FROM encrypted_profile_backups AS backup
		JOIN encrypted_backup_chunks AS chunk ON chunk.backup_id = backup.id
		WHERE backup.id = $1 AND backup.user_id = $2 AND chunk.chunk_index = $3
	`, backupID, userID, index).Scan(
		&target.BackupID, &target.UserID, &target.SourceDeviceID,
		&state, &target.UploadExpiresAt,
		&target.Object.ObjectID, &digest, &target.Object.CiphertextSize,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return UploadTarget{}, ErrBackupNotFound
	}
	if err != nil || !copyDigest(&target.Object.CiphertextDigest, digest) {
		return UploadTarget{}, ErrEncryptedUnavailable
	}
	target.State = BackupState(state)
	return target, nil
}

func (repository *PostgresRepository) ManifestUploadTarget(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
) (UploadTarget, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil {
		return UploadTarget{}, ErrInvalidRequest
	}
	var target UploadTarget
	var state string
	var digest []byte
	err := repository.postgres.QueryRow(ctx, `
		SELECT id, user_id, source_device_id, state, upload_expires_at,
		       manifest_object_key, manifest_ciphertext_digest, manifest_ciphertext_size
		FROM encrypted_profile_backups
		WHERE id = $1 AND user_id = $2
	`, backupID, userID).Scan(
		&target.BackupID, &target.UserID, &target.SourceDeviceID,
		&state, &target.UploadExpiresAt,
		&target.Object.ObjectID, &digest, &target.Object.CiphertextSize,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return UploadTarget{}, ErrBackupNotFound
	}
	if err != nil || !copyDigest(&target.Object.CiphertextDigest, digest) {
		return UploadTarget{}, ErrEncryptedUnavailable
	}
	target.State = BackupState(state)
	return target, nil
}

func (repository *PostgresRepository) MarkUploading(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	updatedAt time.Time,
) error {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil || updatedAt.IsZero() {
		return ErrInvalidRequest
	}
	result, err := repository.postgres.Exec(ctx, `
		UPDATE encrypted_profile_backups
		SET state = CASE WHEN state = 'initiated' THEN 'uploading' ELSE state END,
		    updated_at = $3
		WHERE id = $1 AND user_id = $2 AND state IN ('initiated', 'uploading')
	`, backupID, userID, updatedAt)
	if err != nil {
		return classifyBackupWriteError(err)
	}
	if result.RowsAffected() != 1 {
		return ErrBackupConflict
	}
	return nil
}

func (repository *PostgresRepository) BackupForSeal(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
) (BackupDetail, error) {
	return repository.readBackupDetail(ctx, userID, backupID, uuid.Nil, false)
}

func (repository *PostgresRepository) Seal(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	sealedAt time.Time,
) (Backup, bool, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil || sealedAt.IsZero() {
		return Backup{}, false, ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Backup{}, false, ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var state string
	if err := tx.QueryRow(ctx, `
		SELECT state
		FROM encrypted_profile_backups
		WHERE id = $1 AND user_id = $2
		FOR UPDATE
	`, backupID, userID).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
		return Backup{}, false, ErrBackupNotFound
	} else if err != nil {
		return Backup{}, false, ErrEncryptedUnavailable
	}
	if state == string(BackupStateSealed) {
		found, err := readBackupCore(ctx, tx, userID, backupID, false)
		if err != nil {
			return Backup{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Backup{}, false, ErrEncryptedUnavailable
		}
		return found, true, nil
	}
	if state != string(BackupStateInitiated) && state != string(BackupStateUploading) {
		return Backup{}, false, ErrBackupConflict
	}
	if _, err := tx.Exec(ctx, `
		UPDATE encrypted_profile_backups
		SET state = 'sealed', sealed_at = $3, updated_at = $3
		WHERE id = $1 AND user_id = $2
	`, backupID, userID, sealedAt); err != nil {
		return Backup{}, false, classifyBackupWriteError(err)
	}
	found, err := readBackupCore(ctx, tx, userID, backupID, false)
	if err != nil {
		return Backup{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Backup{}, false, classifyBackupWriteError(err)
	}
	return found, false, nil
}

func (repository *PostgresRepository) ListSealed(
	ctx context.Context,
	userID uuid.UUID,
) ([]Backup, error) {
	if repository == nil || repository.postgres == nil || userID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	rows, err := repository.postgres.Query(ctx, backupCoreQuery(`
		WHERE backup.user_id = $1 AND backup.state = 'sealed'
		ORDER BY backup.sealed_at DESC, backup.id
	`), userID)
	if err != nil {
		return nil, ErrEncryptedUnavailable
	}
	defer rows.Close()
	result := make([]Backup, 0)
	for rows.Next() {
		found, err := scanBackupCore(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, found)
	}
	if rows.Err() != nil {
		return nil, ErrEncryptedUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) GetSealed(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	currentDeviceID uuid.UUID,
) (BackupDetail, error) {
	return repository.readBackupDetail(
		ctx,
		userID,
		backupID,
		currentDeviceID,
		true,
	)
}

func (repository *PostgresRepository) AddDeviceEnvelope(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	record EnvelopeRecord,
) (bool, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil ||
		record.ID == uuid.Nil || record.BackupID != backupID ||
		record.BackupDeviceID == uuid.Nil ||
		record.KeyEpoch <= 0 ||
		!validEnvelope(record.RootKeyEnvelope) ||
		!digestMatches(record.RootKeyEnvelope, record.RootKeyEnvelopeDigest) {
		return false, ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var backupState string
	var deviceStatus string
	var deviceUserID uuid.UUID
	var deviceEpoch int64
	if err := tx.QueryRow(ctx, `
		SELECT backup.state, device.status, device.user_id, device.key_epoch
		FROM encrypted_profile_backups AS backup
		JOIN backup_devices AS device ON device.id = $3
		WHERE backup.id = $1 AND backup.user_id = $2
		FOR UPDATE OF backup, device
	`, backupID, userID, record.BackupDeviceID).Scan(
		&backupState,
		&deviceStatus,
		&deviceUserID,
		&deviceEpoch,
	); errors.Is(err, pgx.ErrNoRows) {
		return false, ErrBackupNotFound
	} else if err != nil {
		return false, ErrEncryptedUnavailable
	}
	if backupState != string(BackupStateSealed) {
		return false, ErrBackupConflict
	}
	if deviceUserID != userID || deviceEpoch != record.KeyEpoch {
		return false, ErrUnauthorized
	}
	if deviceStatus != "active" {
		return false, ErrDeviceRevoked
	}

	var existingEnvelope []byte
	var existingDigest []byte
	err = tx.QueryRow(ctx, `
		SELECT root_key_envelope, root_key_envelope_digest
		FROM encrypted_backup_key_envelopes
		WHERE backup_id = $1 AND backup_device_id = $2 AND key_epoch = $3
		FOR UPDATE
	`, backupID, record.BackupDeviceID, record.KeyEpoch).Scan(
		&existingEnvelope,
		&existingDigest,
	)
	if err == nil {
		if bytes.Equal(existingEnvelope, record.RootKeyEnvelope) &&
			bytes.Equal(existingDigest, record.RootKeyEnvelopeDigest[:]) {
			if err := tx.Commit(ctx); err != nil {
				return false, ErrEncryptedUnavailable
			}
			return true, nil
		}
		return false, ErrBackupConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, ErrEncryptedUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO encrypted_backup_key_envelopes (
			id, backup_id, backup_device_id, key_epoch,
			root_key_envelope, root_key_envelope_digest, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, record.ID, backupID, record.BackupDeviceID, record.KeyEpoch,
		record.RootKeyEnvelope, record.RootKeyEnvelopeDigest[:], record.CreatedAt); err != nil {
		return false, classifyBackupWriteError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, classifyBackupWriteError(err)
	}
	return false, nil
}

func (repository *PostgresRepository) BeginDeletion(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	startedAt time.Time,
) (DeletionRecord, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil || startedAt.IsZero() {
		return DeletionRecord{}, ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DeletionRecord{}, ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	rows, err := tx.Query(ctx, `
		SELECT object_key
		FROM begin_encrypted_profile_backup_deletion($1, $2, $3)
	`, backupID, userID, startedAt)
	if err != nil {
		return DeletionRecord{}, classifyBackupWriteError(err)
	}
	var objectIDs []string
	for rows.Next() {
		var objectID string
		if err := rows.Scan(&objectID); err != nil {
			rows.Close()
			return DeletionRecord{}, ErrEncryptedUnavailable
		}
		objectIDs = append(objectIDs, objectID)
	}
	rows.Close()
	if rows.Err() != nil {
		return DeletionRecord{}, ErrEncryptedUnavailable
	}
	operationID, err := secure.RandomUUID()
	if err != nil {
		return DeletionRecord{}, ErrEncryptedUnavailable
	}
	var existingOperationID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM encrypted_backup_operations
		WHERE backup_id = $1 AND operation = 'delete_backup'
		  AND state IN ('pending', 'running')
		FOR UPDATE
	`, backupID).Scan(&existingOperationID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = tx.Exec(ctx, `
			INSERT INTO encrypted_backup_operations (
				id, user_id, backup_id, operation, state, object_keys,
				attempt_count, next_attempt_at, created_at, updated_at
			) VALUES ($1, $2, $3, 'delete_backup', 'pending', $4, 0, $5, $5, $5)
		`, operationID, userID, backupID, objectIDs, startedAt)
	case err == nil:
		_, err = tx.Exec(ctx, `
			UPDATE encrypted_backup_operations
			SET object_keys = $2, state = 'pending', next_attempt_at = $3, updated_at = $3
			WHERE id = $1
		`, existingOperationID, objectIDs, startedAt)
	}
	if err != nil {
		return DeletionRecord{}, classifyBackupWriteError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return DeletionRecord{}, ErrEncryptedUnavailable
	}
	return DeletionRecord{
		BackupID:  backupID,
		UserID:    userID,
		State:     BackupStateDeleting,
		ObjectIDs: objectIDs,
	}, nil
}

func (repository *PostgresRepository) CompleteDeletion(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	completedAt time.Time,
) error {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil || completedAt.IsZero() {
		return ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	result, err := tx.Exec(ctx, `
		UPDATE encrypted_profile_backups
		SET state = 'deleted', deleted_at = $3, updated_at = $3
		WHERE id = $1 AND user_id = $2 AND state = 'deleting'
	`, backupID, userID, completedAt)
	if err != nil {
		return classifyBackupWriteError(err)
	}
	if result.RowsAffected() != 1 {
		var state string
		if err := tx.QueryRow(ctx, `
			SELECT state FROM encrypted_profile_backups
			WHERE id = $1 AND user_id = $2
		`, backupID, userID).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
			return ErrBackupNotFound
		} else if err != nil {
			return ErrEncryptedUnavailable
		}
		if state != string(BackupStateDeleted) {
			return ErrBackupConflict
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE encrypted_backup_operations
		SET state = 'completed', completed_at = $3,
		    next_attempt_at = NULL, last_error_code = NULL, updated_at = $3
		WHERE backup_id = $1 AND user_id = $2
		  AND operation = 'delete_backup' AND state IN ('pending', 'running')
	`, backupID, userID, completedAt); err != nil {
		return ErrEncryptedUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrEncryptedUnavailable
	}
	return nil
}

func (repository *PostgresRepository) readBackupDetail(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	currentDeviceID uuid.UUID,
	sealedOnly bool,
) (BackupDetail, error) {
	if repository == nil || repository.postgres == nil ||
		userID == uuid.Nil || backupID == uuid.Nil {
		return BackupDetail{}, ErrInvalidRequest
	}
	tx, err := repository.postgres.BeginTx(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return BackupDetail{}, ErrEncryptedUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	found, err := readBackupCore(ctx, tx, userID, backupID, sealedOnly)
	if err != nil {
		return BackupDetail{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT chunk_index, object_key, ciphertext_digest, ciphertext_size
		FROM encrypted_backup_chunks
		WHERE backup_id = $1
		ORDER BY chunk_index
	`, backupID)
	if err != nil {
		return BackupDetail{}, ErrEncryptedUnavailable
	}
	chunks := make([]ChunkSpec, 0, found.ChunkCount)
	for rows.Next() {
		var chunk ChunkSpec
		var digest []byte
		if err := rows.Scan(
			&chunk.Index,
			&chunk.ObjectID,
			&digest,
			&chunk.CiphertextSize,
		); err != nil || !copyDigest(&chunk.CiphertextDigest, digest) {
			rows.Close()
			return BackupDetail{}, ErrEncryptedUnavailable
		}
		chunks = append(chunks, chunk)
	}
	rows.Close()
	if rows.Err() != nil {
		return BackupDetail{}, ErrEncryptedUnavailable
	}
	var currentEnvelope *KeyEnvelope
	if currentDeviceID != uuid.Nil {
		var value KeyEnvelope
		var digest []byte
		err := tx.QueryRow(ctx, `
			SELECT envelope.id, envelope.backup_id, envelope.backup_device_id,
			       device.device_id, envelope.key_epoch, envelope.root_key_envelope,
			       envelope.root_key_envelope_digest, envelope.created_at
			FROM encrypted_backup_key_envelopes AS envelope
			JOIN backup_devices AS device ON device.id = envelope.backup_device_id
			WHERE envelope.backup_id = $1
			  AND device.user_id = $2
			  AND device.device_id = $3
			  AND device.status = 'active'
			  AND envelope.root_key_envelope IS NOT NULL
			ORDER BY envelope.key_epoch DESC
			LIMIT 1
		`, backupID, userID, currentDeviceID).Scan(
			&value.ID,
			&value.BackupID,
			&value.BackupDeviceID,
			&value.DeviceID,
			&value.KeyEpoch,
			&value.RootKeyEnvelope,
			&digest,
			&value.CreatedAt,
		)
		if err == nil {
			if !copyDigest(&value.RootKeyEnvelopeDigest, digest) {
				return BackupDetail{}, ErrEncryptedUnavailable
			}
			currentEnvelope = &value
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return BackupDetail{}, ErrEncryptedUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return BackupDetail{}, ErrEncryptedUnavailable
	}
	return BackupDetail{
		Backup:           found,
		Chunks:           chunks,
		CurrentDeviceKey: currentEnvelope,
	}, nil
}

type backupRow interface {
	Scan(...any) error
}

func backupCoreQuery(suffix string) string {
	return `
		SELECT backup.id, backup.user_id, backup.source_device_id,
		       backup.source_installation_id, backup.source_definition_id,
		       backup.source_version_id, backup.profile_lineage_id,
		       backup.parent_backup_id, backup.format_version, backup.cipher_suite,
		       backup.state, backup.chunk_count, backup.total_ciphertext_size,
		       backup.manifest_object_key, backup.manifest_ciphertext_digest,
		       backup.manifest_ciphertext_size, backup.public_envelope_digest,
		       backup.public_signature, backup.recovery_salt,
		       backup.recovery_memory_kib, backup.recovery_iterations,
		       backup.recovery_parallelism, backup.recovery_root_key_envelope,
		       backup.wrapped_data_key, backup.created_at, backup.updated_at,
		       backup.upload_expires_at, backup.sealed_at,
		       backup.deletion_started_at, backup.deleted_at,
		       COALESCE((
		           SELECT envelope.key_epoch
		           FROM encrypted_backup_key_envelopes AS envelope
		           JOIN backup_devices AS source_device
		             ON source_device.id = envelope.backup_device_id
		           WHERE envelope.backup_id = backup.id
		             AND source_device.device_id = backup.source_device_id
		           ORDER BY envelope.key_epoch DESC
		           LIMIT 1
		       ), 0) AS key_epoch
		FROM encrypted_profile_backups AS backup
	` + suffix
}

func readBackupCore(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	backupID uuid.UUID,
	sealedOnly bool,
) (Backup, error) {
	suffix := ` WHERE backup.user_id = $1 AND backup.id = $2`
	if sealedOnly {
		suffix += ` AND backup.state = 'sealed'`
	}
	found, err := scanBackupCore(tx.QueryRow(ctx, backupCoreQuery(suffix), userID, backupID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Backup{}, ErrBackupNotFound
	}
	return found, err
}

func scanBackupCore(row backupRow) (Backup, error) {
	var found Backup
	var parent pgtype.UUID
	var state string
	var manifestDigest []byte
	var publicDigest []byte
	var sealedAt pgtype.Timestamptz
	var deletionStartedAt pgtype.Timestamptz
	var deletedAt pgtype.Timestamptz
	err := row.Scan(
		&found.ID,
		&found.UserID,
		&found.SourceDeviceID,
		&found.SourceInstallationID,
		&found.SourceDefinitionID,
		&found.SourceVersionID,
		&found.ProfileLineageID,
		&parent,
		&found.FormatVersion,
		&found.CipherSuite,
		&state,
		&found.ChunkCount,
		&found.TotalCiphertextSize,
		&found.Manifest.ObjectID,
		&manifestDigest,
		&found.Manifest.CiphertextSize,
		&publicDigest,
		&found.PublicSignature,
		&found.Recovery.Salt,
		&found.Recovery.MemoryKiB,
		&found.Recovery.Iterations,
		&found.Recovery.Parallelism,
		&found.RecoveryRootKeyEnvelope,
		&found.WrappedDataKey,
		&found.CreatedAt,
		&found.UpdatedAt,
		&found.UploadExpiresAt,
		&sealedAt,
		&deletionStartedAt,
		&deletedAt,
		&found.KeyEpoch,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Backup{}, err
		}
		return Backup{}, ErrEncryptedUnavailable
	}
	if !copyDigest(&found.Manifest.CiphertextDigest, manifestDigest) ||
		!copyDigest(&found.PublicEnvelopeDigest, publicDigest) {
		return Backup{}, ErrEncryptedUnavailable
	}
	found.State = BackupState(state)
	if parent.Valid {
		value := uuid.UUID(parent.Bytes)
		found.ParentBackupID = &value
	}
	if sealedAt.Valid {
		value := sealedAt.Time
		found.SealedAt = &value
	}
	if deletionStartedAt.Valid {
		value := deletionStartedAt.Time
		found.DeletionStartedAt = &value
	}
	if deletedAt.Valid {
		value := deletedAt.Time
		found.DeletedAt = &value
	}
	return found, nil
}

func findLatestBackupDeviceForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	deviceID uuid.UUID,
) (BackupDevice, []byte, bool, error) {
	found, signature, err := scanBackupDevice(tx.QueryRow(ctx, `
		SELECT id, user_id, device_id, key_epoch, public_key,
		       registration_signature, revision, status, created_at, updated_at, revoked_at
		FROM backup_devices
		WHERE user_id = $1 AND device_id = $2
		ORDER BY revision DESC, key_epoch DESC
		LIMIT 1
		FOR UPDATE
	`, userID, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupDevice{}, nil, false, nil
	}
	if err != nil {
		return BackupDevice{}, nil, false, ErrEncryptedUnavailable
	}
	return found, signature, true, nil
}

func scanBackupDevice(row backupRow) (BackupDevice, []byte, error) {
	var found BackupDevice
	var signature []byte
	var revokedAt pgtype.Timestamptz
	err := row.Scan(
		&found.ID,
		&found.UserID,
		&found.DeviceID,
		&found.KeyEpoch,
		&found.PublicKey,
		&signature,
		&found.Revision,
		&found.Status,
		&found.CreatedAt,
		&found.UpdatedAt,
		&revokedAt,
	)
	if err != nil {
		return BackupDevice{}, nil, err
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		found.RevokedAt = &value
	}
	return found, signature, nil
}

func copyDigest(target *[sha256.Size]byte, source []byte) bool {
	if len(source) != sha256.Size {
		return false
	}
	copy(target[:], source)
	return true
}

func classifyBackupWriteError(err error) error {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return ErrEncryptedUnavailable
	}
	message := strings.ToLower(postgresError.Message)
	if postgresError.Code == "P0002" || strings.Contains(message, "not found") {
		return ErrBackupNotFound
	}
	if strings.Contains(message, "quota exceeded") {
		return ErrQuotaExceeded
	}
	if strings.Contains(message, "provenance") ||
		postgresError.Code == "23503" {
		return ErrUnauthorized
	}
	if postgresError.Code == "23505" ||
		postgresError.Code == "23514" {
		return ErrBackupConflict
	}
	return ErrEncryptedUnavailable
}
