package encryptedbackup_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const backupCipherSuite = "HPKE-X25519-HKDF-SHA256-AES256GCM+ARGON2ID+AES256GCM"

type backupSchemaFixture struct {
	ctx            context.Context
	postgres       *pgxpool.Pool
	now            time.Time
	userID         uuid.UUID
	deviceID       uuid.UUID
	installationID uuid.UUID
	definitionID   uuid.UUID
	versionID      uuid.UUID
}

func newBackupSchemaFixture(t *testing.T) *backupSchemaFixture {
	t.Helper()
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	t.Cleanup(postgres.Close)
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate encrypted backup fixture: %v", err)
	}

	fixture := &backupSchemaFixture{
		ctx: ctx, postgres: postgres,
		now:            time.Date(2026, 7, 23, 2, 0, 0, 0, time.UTC),
		userID:         uuid.New(),
		deviceID:       uuid.New(),
		installationID: uuid.New(),
		definitionID:   uuid.New(),
		versionID:      uuid.New(),
	}
	spaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, created_at, updated_at)
		VALUES ($1, 'active', $2, $2)
	`, fixture.userID, fixture.now); err != nil {
		t.Fatalf("seed encrypted backup owner: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, display_name, status, created_at, updated_at)
		VALUES ($1, $2, 'Backup fixture', 'active', $3, $3)
	`, spaceID, fixture.userID, fixture.now); err != nil {
		t.Fatalf("seed encrypted backup personal space: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Backup Mac', 'darwin', '0.7.3', 'active', $5, $5, $5)
	`, fixture.deviceID, fixture.userID, uuid.New(), bytes.Repeat([]byte{0x21}, 32), fixture.now); err != nil {
		t.Fatalf("seed encrypted backup device: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO agent_definitions (
			id, tenant_id, owner_scope, owner_id, display_name, status, created_by, created_at, updated_at
		) VALUES ($1, $2, 'USER', $3, 'Backup Agent', 'active', $3, $4, $4)
	`, fixture.definitionID, spaceID, fixture.userID, fixture.now); err != nil {
		t.Fatalf("seed encrypted backup definition: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO agent_versions (
			id, definition_id, tenant_id, owner_scope, owner_id, version_number,
			canonical_manifest, bundle, content_digest, signing_key_id, signature,
			runtime_minimum_version, published_by, published_at
		) VALUES (
			$1, $2, $3, 'USER', $4, 1, '{"schema_version":1}'::jsonb, '{"assets":[]}'::jsonb,
			$5, 'backup-fixture', $6, '0.18.2-agentera.1', $4, $7
		)
	`, fixture.versionID, fixture.definitionID, spaceID, fixture.userID, bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x23}, 64), fixture.now); err != nil {
		t.Fatalf("seed encrypted backup version: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO installations (
			id, tenant_id, owner_scope, owner_id, device_id, device_installation_id,
			definition_id, selected_version_id, update_policy, status, created_by, created_at, updated_at
		) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, 'manual', 'pending', $3, $8, $8)
	`, fixture.installationID, spaceID, fixture.userID, fixture.deviceID, uuid.New(), fixture.definitionID, fixture.versionID, fixture.now); err != nil {
		t.Fatalf("seed encrypted backup installation: %v", err)
	}
	return fixture
}

func (f *backupSchemaFixture) insertBackup(
	backupID uuid.UUID,
	lineageID uuid.UUID,
	state string,
	size int64,
) error {
	var sealedAt any
	if state == "sealed" {
		sealedAt = f.now
	}
	_, err := f.postgres.Exec(f.ctx, `
		INSERT INTO encrypted_profile_backups (
			id, user_id, source_device_id, source_installation_id, source_definition_id,
			source_version_id, profile_lineage_id, format_version, cipher_suite, state,
			chunk_count, total_ciphertext_size, manifest_object_key, manifest_ciphertext_digest,
			manifest_ciphertext_size, public_envelope_digest, public_signature, recovery_salt,
			recovery_memory_kib, recovery_iterations, recovery_parallelism,
			recovery_root_key_envelope, wrapped_data_key, created_at, updated_at,
			upload_expires_at, sealed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, 1, $8, $9,
			1, $10, $11, $12, 48, $13, $14, $15,
			65536, 3, 1, $16, $17, $18, $18, $19, $20
		)
	`, backupID, f.userID, f.deviceID, f.installationID, f.definitionID, f.versionID,
		lineageID, backupCipherSuite, state, size, fmt.Sprintf("%064x", backupID.ID()),
		bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x32}, 32), bytes.Repeat([]byte{0x33}, 64),
		bytes.Repeat([]byte{0x34}, 16), bytes.Repeat([]byte{0x35}, 48), bytes.Repeat([]byte{0x36}, 48),
		f.now, f.now.Add(24*time.Hour), sealedAt)
	return err
}

func TestEncryptedBackupSchemaContainsOnlyCiphertextMetadata(t *testing.T) {
	fixture := newBackupSchemaFixture(t)
	rows, err := fixture.postgres.Query(fixture.ctx, `
		SELECT table_name, column_name
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name IN (
			'backup_devices', 'encrypted_profile_backups', 'encrypted_backup_chunks',
			'encrypted_backup_key_envelopes', 'encrypted_backup_operations'
		  )
	`)
	if err != nil {
		t.Fatalf("inspect encrypted backup columns: %v", err)
	}
	defer rows.Close()
	forbidden := []string{
		"plaintext", "filename", "file_path", "profile_path", "recovery_phrase",
		"device_private_key", "data_encryption_key", "manifest_json", "content_json",
	}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatalf("scan encrypted backup column: %v", err)
		}
		for _, fragment := range forbidden {
			if strings.Contains(column, fragment) {
				t.Fatalf("%s.%s contains forbidden plaintext semantic %q", table, column, fragment)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate encrypted backup columns: %v", err)
	}
}

func TestEncryptedBackupSchemaEnforcesQuotasAndActiveUpload(t *testing.T) {
	fixture := newBackupSchemaFixture(t)
	activeLineage := uuid.New()
	if err := fixture.insertBackup(uuid.New(), activeLineage, "initiated", 1024); err != nil {
		t.Fatalf("insert active encrypted backup: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE encrypted_profile_backups
		SET upload_expires_at = created_at + INTERVAL '24 hours 1 second'
		WHERE profile_lineage_id = $1
	`, activeLineage); err == nil {
		t.Fatal("upload lifetime beyond 24 hours unexpectedly succeeded")
	}
	if err := fixture.insertBackup(uuid.New(), activeLineage, "uploading", 1024); err == nil {
		t.Fatal("second active upload for one lineage unexpectedly succeeded")
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `DELETE FROM encrypted_profile_backups WHERE profile_lineage_id = $1`, activeLineage); err != nil {
		t.Fatalf("clear active encrypted backup: %v", err)
	}
	if err := fixture.insertBackup(uuid.New(), uuid.New(), "initiated", 1_073_741_825); err == nil {
		t.Fatal("oversized encrypted backup unexpectedly succeeded")
	}

	lineage := uuid.New()
	for range 3 {
		if err := fixture.insertBackup(uuid.New(), lineage, "sealed", 1_073_741_824); err != nil {
			t.Fatalf("insert allowed lineage backup: %v", err)
		}
	}
	if err := fixture.insertBackup(uuid.New(), lineage, "sealed", 1); err == nil {
		t.Fatal("fourth sealed lineage backup unexpectedly succeeded")
	}
	for range 2 {
		if err := fixture.insertBackup(uuid.New(), uuid.New(), "sealed", 1_073_741_824); err != nil {
			t.Fatalf("insert allowed account backup: %v", err)
		}
	}
	if err := fixture.insertBackup(uuid.New(), uuid.New(), "sealed", 1); err == nil {
		t.Fatal("backup beyond five GiB account quota unexpectedly succeeded")
	}
}

func TestEncryptedBackupDeletionDestroysEnvelopesBeforeObjectCleanup(t *testing.T) {
	fixture := newBackupSchemaFixture(t)
	backupID := uuid.New()
	if err := fixture.insertBackup(backupID, uuid.New(), "initiated", 2048); err != nil {
		t.Fatalf("insert deletion backup: %v", err)
	}
	backupDeviceID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO backup_devices (
			id, user_id, device_id, key_epoch, public_key, registration_signature,
			revision, status, created_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, $5, 1, 'active', $6, $6)
	`, backupDeviceID, fixture.userID, fixture.deviceID, bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 64), fixture.now); err != nil {
		t.Fatalf("insert backup device: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO encrypted_backup_chunks (
			backup_id, chunk_index, object_key, ciphertext_digest, ciphertext_size, created_at
		) VALUES ($1, 0, $2, $3, 2048, $4)
	`, backupID, strings.Repeat("b", 64), bytes.Repeat([]byte{0x43}, 32), fixture.now); err != nil {
		t.Fatalf("seed encrypted backup chunk inventory: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO encrypted_backup_key_envelopes (
			id, backup_id, backup_device_id, key_epoch, root_key_envelope,
			root_key_envelope_digest, created_at
		) VALUES ($1, $2, $3, 1, $4, $5, $6)
	`, uuid.New(), backupID, backupDeviceID, bytes.Repeat([]byte{0x44}, 80), bytes.Repeat([]byte{0x45}, 32), fixture.now); err != nil {
		t.Fatalf("seed encrypted backup key envelope: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE encrypted_profile_backups
		SET state = 'sealed', sealed_at = $2, updated_at = $2
		WHERE id = $1
	`, backupID, fixture.now); err != nil {
		t.Fatalf("seal deletion backup fixture: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE encrypted_backup_chunks SET ciphertext_size = 1024 WHERE backup_id = $1
	`, backupID); err == nil {
		t.Fatal("sealed encrypted backup chunk mutation unexpectedly succeeded")
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT object_key FROM begin_encrypted_profile_backup_deletion($1, $2, $3)
	`, backupID, uuid.New(), fixture.now.Add(time.Hour)).Scan(new(string)); err == nil {
		t.Fatal("cross-account encrypted backup deletion unexpectedly succeeded")
	}
	rows, err := fixture.postgres.Query(fixture.ctx, `
		SELECT object_key FROM begin_encrypted_profile_backup_deletion($1, $2, $3)
	`, backupID, fixture.userID, fixture.now.Add(time.Hour))
	if err != nil {
		t.Fatalf("begin encrypted backup deletion: %v", err)
	}
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatalf("scan deletion object key: %v", err)
		}
		keys = append(keys, key)
	}
	rows.Close()
	if len(keys) != 2 {
		t.Fatalf("deletion object key count = %d, want 2", len(keys))
	}
	var state string
	var recoveryEnvelope, wrappedDataKey []byte
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT state, recovery_root_key_envelope, wrapped_data_key
		FROM encrypted_profile_backups WHERE id = $1
	`, backupID).Scan(&state, &recoveryEnvelope, &wrappedDataKey); err != nil {
		t.Fatalf("read cryptographic deletion state: %v", err)
	}
	if state != "deleting" || recoveryEnvelope != nil || wrappedDataKey != nil {
		t.Fatalf("backup deletion state/envelopes = %s/%v/%v", state, recoveryEnvelope, wrappedDataKey)
	}
	var deviceEnvelope []byte
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT root_key_envelope FROM encrypted_backup_key_envelopes WHERE backup_id = $1
	`, backupID).Scan(&deviceEnvelope); err != nil {
		t.Fatalf("read destroyed device envelope: %v", err)
	}
	if deviceEnvelope != nil {
		t.Fatal("device root-key envelope remained after deletion began")
	}
}
