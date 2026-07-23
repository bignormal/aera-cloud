ALTER TABLE devices
    ADD CONSTRAINT devices_id_user_key UNIQUE (id, user_id);

CREATE TABLE backup_devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    device_id UUID NOT NULL,
    key_epoch BIGINT NOT NULL,
    public_key BYTEA NOT NULL,
    registration_signature BYTEA NOT NULL,
    revision BIGINT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT backup_devices_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT backup_devices_device_user_fk
        FOREIGN KEY (device_id, user_id)
        REFERENCES devices(id, user_id) ON DELETE CASCADE,
    CONSTRAINT backup_devices_epoch_check CHECK (key_epoch > 0),
    CONSTRAINT backup_devices_public_key_length_check CHECK (
        octet_length(public_key) = 32
    ),
    CONSTRAINT backup_devices_signature_length_check CHECK (
        octet_length(registration_signature) = 64
    ),
    CONSTRAINT backup_devices_revision_check CHECK (revision > 0),
    CONSTRAINT backup_devices_status_check CHECK (
        status IN ('active', 'revoked')
    ),
    CONSTRAINT backup_devices_time_check CHECK (
        updated_at >= created_at
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    ),
    CONSTRAINT backup_devices_revocation_check CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT backup_devices_user_device_epoch_key
        UNIQUE (user_id, device_id, key_epoch),
    CONSTRAINT backup_devices_public_key_key UNIQUE (public_key)
);

CREATE INDEX backup_devices_user_status_idx
    ON backup_devices (user_id, status, key_epoch DESC);

CREATE TABLE encrypted_profile_backups (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    source_device_id UUID NOT NULL,
    source_installation_id UUID NOT NULL,
    source_definition_id UUID NOT NULL,
    source_version_id UUID NOT NULL,
    profile_lineage_id UUID NOT NULL,
    parent_backup_id UUID,
    format_version SMALLINT NOT NULL,
    cipher_suite TEXT NOT NULL,
    state TEXT NOT NULL,
    chunk_count INTEGER NOT NULL,
    total_ciphertext_size BIGINT NOT NULL,
    manifest_object_key TEXT,
    manifest_ciphertext_digest BYTEA,
    manifest_ciphertext_size BIGINT,
    public_envelope_digest BYTEA NOT NULL,
    public_signature BYTEA NOT NULL,
    recovery_salt BYTEA NOT NULL,
    recovery_memory_kib INTEGER NOT NULL,
    recovery_iterations INTEGER NOT NULL,
    recovery_parallelism INTEGER NOT NULL,
    recovery_root_key_envelope BYTEA,
    wrapped_data_key BYTEA,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    upload_expires_at TIMESTAMPTZ NOT NULL,
    sealed_at TIMESTAMPTZ,
    deletion_started_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT encrypted_profile_backups_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_profile_backups_device_user_fk
        FOREIGN KEY (source_device_id, user_id)
        REFERENCES devices(id, user_id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_profile_backups_installation_fk
        FOREIGN KEY (source_installation_id)
        REFERENCES installations(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_profile_backups_definition_fk
        FOREIGN KEY (source_definition_id)
        REFERENCES agent_definitions(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_profile_backups_version_fk
        FOREIGN KEY (source_version_id)
        REFERENCES agent_versions(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_profile_backups_parent_fk
        FOREIGN KEY (parent_backup_id)
        REFERENCES encrypted_profile_backups(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_profile_backups_parent_self_check CHECK (
        parent_backup_id IS NULL OR parent_backup_id <> id
    ),
    CONSTRAINT encrypted_profile_backups_format_check CHECK (
        format_version = 1
    ),
    CONSTRAINT encrypted_profile_backups_cipher_suite_check CHECK (
        cipher_suite = 'HPKE-X25519-HKDF-SHA256-AES256GCM+ARGON2ID+AES256GCM'
    ),
    CONSTRAINT encrypted_profile_backups_state_check CHECK (
        state IN ('initiated', 'uploading', 'sealed', 'deleting', 'deleted', 'expired')
    ),
    CONSTRAINT encrypted_profile_backups_chunk_count_check CHECK (
        chunk_count BETWEEN 1 AND 131072
    ),
    CONSTRAINT encrypted_profile_backups_size_check CHECK (
        total_ciphertext_size BETWEEN 17 AND 1073741824
    ),
    CONSTRAINT encrypted_profile_backups_manifest_key_check CHECK (
        manifest_object_key IS NULL
        OR (
            char_length(manifest_object_key) = 64
            AND manifest_object_key ~ '^[0-9a-f]{64}$'
        )
    ),
    CONSTRAINT encrypted_profile_backups_manifest_digest_check CHECK (
        manifest_ciphertext_digest IS NULL
        OR octet_length(manifest_ciphertext_digest) = 32
    ),
    CONSTRAINT encrypted_profile_backups_manifest_size_check CHECK (
        manifest_ciphertext_size IS NULL
        OR manifest_ciphertext_size BETWEEN 17 AND 16777216
    ),
    CONSTRAINT encrypted_profile_backups_public_digest_length_check CHECK (
        octet_length(public_envelope_digest) = 32
    ),
    CONSTRAINT encrypted_profile_backups_signature_length_check CHECK (
        octet_length(public_signature) = 64
    ),
    CONSTRAINT encrypted_profile_backups_recovery_salt_length_check CHECK (
        octet_length(recovery_salt) BETWEEN 16 AND 32
    ),
    CONSTRAINT encrypted_profile_backups_recovery_params_check CHECK (
        recovery_memory_kib = 65536
        AND recovery_iterations = 3
        AND recovery_parallelism = 1
    ),
    CONSTRAINT encrypted_profile_backups_recovery_envelope_size_check CHECK (
        recovery_root_key_envelope IS NULL
        OR octet_length(recovery_root_key_envelope) BETWEEN 48 AND 4096
    ),
    CONSTRAINT encrypted_profile_backups_wrapped_data_key_size_check CHECK (
        wrapped_data_key IS NULL
        OR octet_length(wrapped_data_key) BETWEEN 48 AND 4096
    ),
    CONSTRAINT encrypted_profile_backups_upload_expiry_check CHECK (
        upload_expires_at > created_at
        AND upload_expires_at <= created_at + INTERVAL '24 hours'
    ),
    CONSTRAINT encrypted_profile_backups_time_check CHECK (
        updated_at >= created_at
        AND (sealed_at IS NULL OR sealed_at >= created_at)
        AND (deletion_started_at IS NULL OR deletion_started_at >= created_at)
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    CONSTRAINT encrypted_profile_backups_lifecycle_check CHECK (
        (
            state IN ('initiated', 'uploading')
            AND sealed_at IS NULL
            AND deletion_started_at IS NULL
            AND deleted_at IS NULL
            AND recovery_root_key_envelope IS NOT NULL
            AND wrapped_data_key IS NOT NULL
        )
        OR (
            state = 'sealed'
            AND sealed_at IS NOT NULL
            AND deletion_started_at IS NULL
            AND deleted_at IS NULL
            AND manifest_object_key IS NOT NULL
            AND manifest_ciphertext_digest IS NOT NULL
            AND manifest_ciphertext_size IS NOT NULL
            AND recovery_root_key_envelope IS NOT NULL
            AND wrapped_data_key IS NOT NULL
        )
        OR (
            state = 'deleting'
            AND sealed_at IS NOT NULL
            AND deletion_started_at IS NOT NULL
            AND deleted_at IS NULL
            AND recovery_root_key_envelope IS NULL
            AND wrapped_data_key IS NULL
        )
        OR (
            state = 'deleted'
            AND sealed_at IS NOT NULL
            AND deletion_started_at IS NOT NULL
            AND deleted_at IS NOT NULL
            AND recovery_root_key_envelope IS NULL
            AND wrapped_data_key IS NULL
        )
        OR (
            state = 'expired'
            AND sealed_at IS NULL
            AND deletion_started_at IS NOT NULL
            AND deleted_at IS NOT NULL
            AND recovery_root_key_envelope IS NULL
            AND wrapped_data_key IS NULL
        )
    )
);

CREATE UNIQUE INDEX encrypted_profile_backups_one_active_upload_idx
    ON encrypted_profile_backups (user_id, profile_lineage_id)
    WHERE state IN ('initiated', 'uploading');

CREATE INDEX encrypted_profile_backups_user_sealed_idx
    ON encrypted_profile_backups (user_id, sealed_at DESC, id)
    WHERE state = 'sealed';

CREATE INDEX encrypted_profile_backups_lineage_sealed_idx
    ON encrypted_profile_backups (user_id, profile_lineage_id, sealed_at DESC, id)
    WHERE state = 'sealed';

CREATE INDEX encrypted_profile_backups_expiry_idx
    ON encrypted_profile_backups (upload_expires_at, id)
    WHERE state IN ('initiated', 'uploading');

CREATE TABLE encrypted_backup_chunks (
    backup_id UUID NOT NULL,
    chunk_index INTEGER NOT NULL,
    object_key TEXT NOT NULL,
    ciphertext_digest BYTEA NOT NULL,
    ciphertext_size BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (backup_id, chunk_index),
    CONSTRAINT encrypted_backup_chunks_backup_fk
        FOREIGN KEY (backup_id)
        REFERENCES encrypted_profile_backups(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_backup_chunks_index_check CHECK (
        chunk_index BETWEEN 0 AND 131071
    ),
    CONSTRAINT encrypted_backup_chunks_object_key_check CHECK (
        char_length(object_key) = 64
        AND object_key ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT encrypted_backup_chunks_object_key_key UNIQUE (object_key),
    CONSTRAINT encrypted_backup_chunks_digest_length_check CHECK (
        octet_length(ciphertext_digest) = 32
    ),
    CONSTRAINT encrypted_backup_chunks_size_check CHECK (
        ciphertext_size BETWEEN 17 AND 9437200
    )
);

CREATE INDEX encrypted_backup_chunks_backup_idx
    ON encrypted_backup_chunks (backup_id, chunk_index);

CREATE TABLE encrypted_backup_key_envelopes (
    id UUID PRIMARY KEY,
    backup_id UUID NOT NULL,
    backup_device_id UUID NOT NULL,
    key_epoch BIGINT NOT NULL,
    root_key_envelope BYTEA,
    root_key_envelope_digest BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    destroyed_at TIMESTAMPTZ,
    CONSTRAINT encrypted_backup_key_envelopes_backup_fk
        FOREIGN KEY (backup_id)
        REFERENCES encrypted_profile_backups(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_backup_key_envelopes_device_fk
        FOREIGN KEY (backup_device_id)
        REFERENCES backup_devices(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_backup_key_envelopes_epoch_check CHECK (
        key_epoch > 0
    ),
    CONSTRAINT encrypted_backup_key_envelopes_size_check CHECK (
        root_key_envelope IS NULL
        OR octet_length(root_key_envelope) BETWEEN 48 AND 4096
    ),
    CONSTRAINT encrypted_backup_key_envelopes_digest_length_check CHECK (
        octet_length(root_key_envelope_digest) = 32
    ),
    CONSTRAINT encrypted_backup_key_envelopes_destroyed_check CHECK (
        (root_key_envelope IS NULL) = (destroyed_at IS NOT NULL)
    ),
    CONSTRAINT encrypted_backup_key_envelopes_backup_device_key
        UNIQUE (backup_id, backup_device_id, key_epoch)
);

CREATE INDEX encrypted_backup_key_envelopes_device_idx
    ON encrypted_backup_key_envelopes (backup_device_id, key_epoch DESC);

CREATE TABLE encrypted_backup_operations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    backup_id UUID NOT NULL,
    operation TEXT NOT NULL,
    state TEXT NOT NULL,
    object_keys TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT encrypted_backup_operations_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_backup_operations_backup_fk
        FOREIGN KEY (backup_id)
        REFERENCES encrypted_profile_backups(id) ON DELETE RESTRICT,
    CONSTRAINT encrypted_backup_operations_operation_check CHECK (
        operation IN ('expire_upload', 'delete_backup', 'prune_lineage')
    ),
    CONSTRAINT encrypted_backup_operations_state_check CHECK (
        state IN ('pending', 'running', 'completed')
    ),
    CONSTRAINT encrypted_backup_operations_object_keys_check CHECK (
        cardinality(object_keys) BETWEEN 0 AND 131073
    ),
    CONSTRAINT encrypted_backup_operations_attempt_check CHECK (
        attempt_count >= 0
    ),
    CONSTRAINT encrypted_backup_operations_error_code_check CHECK (
        last_error_code IS NULL
        OR (
            char_length(last_error_code) BETWEEN 1 AND 64
            AND last_error_code ~ '^[a-z0-9_]+$'
        )
    ),
    CONSTRAINT encrypted_backup_operations_time_check CHECK (
        updated_at >= created_at
        AND (completed_at IS NULL OR completed_at >= created_at)
    ),
    CONSTRAINT encrypted_backup_operations_terminal_check CHECK (
        (state = 'completed' AND completed_at IS NOT NULL)
        OR (state <> 'completed' AND completed_at IS NULL)
    )
);

CREATE UNIQUE INDEX encrypted_backup_operations_active_idx
    ON encrypted_backup_operations (backup_id, operation)
    WHERE state IN ('pending', 'running');

CREATE INDEX encrypted_backup_operations_due_idx
    ON encrypted_backup_operations (state, next_attempt_at, created_at);

CREATE FUNCTION enforce_encrypted_profile_backup_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    lineage_sealed_count BIGINT;
    account_sealed_bytes NUMERIC;
    installation_matches BOOLEAN;
    parent_matches BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.state IN ('sealed', 'deleting', 'deleted', 'expired') THEN
        IF OLD.state = 'sealed' AND NEW.state = 'deleting' THEN
            IF (to_jsonb(NEW) - ARRAY[
                    'state', 'updated_at', 'deletion_started_at',
                    'recovery_root_key_envelope', 'wrapped_data_key'
                ]) IS DISTINCT FROM
               (to_jsonb(OLD) - ARRAY[
                    'state', 'updated_at', 'deletion_started_at',
                    'recovery_root_key_envelope', 'wrapped_data_key'
                ])
               OR NEW.recovery_root_key_envelope IS NOT NULL
               OR NEW.wrapped_data_key IS NOT NULL
               OR NEW.deletion_started_at IS NULL THEN
                RAISE EXCEPTION 'sealed encrypted backup is immutable'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF OLD.state = 'deleting' AND NEW.state = 'deleted' THEN
            IF (to_jsonb(NEW) - ARRAY['state', 'updated_at', 'deleted_at'])
                    IS DISTINCT FROM
               (to_jsonb(OLD) - ARRAY['state', 'updated_at', 'deleted_at'])
               OR NEW.deleted_at IS NULL THEN
                RAISE EXCEPTION 'deleting encrypted backup transition is invalid'
                    USING ERRCODE = '23514';
            END IF;
        ELSE
            RAISE EXCEPTION 'encrypted backup is immutable in state %', OLD.state
                USING ERRCODE = '23514';
        END IF;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM installations AS installation
        JOIN agent_definitions AS definition
          ON definition.id = installation.definition_id
        JOIN agent_versions AS version
          ON version.id = installation.selected_version_id
        JOIN devices AS device
          ON device.id = installation.device_id
        WHERE installation.id = NEW.source_installation_id
          AND installation.owner_scope = 'USER'
          AND installation.owner_id = NEW.user_id
          AND installation.device_id = NEW.source_device_id
          AND installation.definition_id = NEW.source_definition_id
          AND installation.selected_version_id = NEW.source_version_id
          AND definition.owner_scope = 'USER'
          AND definition.owner_id = NEW.user_id
          AND version.owner_scope = 'USER'
          AND version.owner_id = NEW.user_id
          AND version.definition_id = NEW.source_definition_id
          AND device.user_id = NEW.user_id
    ) INTO installation_matches;
    IF NOT installation_matches THEN
        RAISE EXCEPTION 'encrypted backup provenance must be USER-owned and exact'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.parent_backup_id IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1 FROM encrypted_profile_backups AS parent
            WHERE parent.id = NEW.parent_backup_id
              AND parent.user_id = NEW.user_id
              AND parent.profile_lineage_id = NEW.profile_lineage_id
              AND parent.state = 'sealed'
        ) INTO parent_matches;
        IF NOT parent_matches THEN
            RAISE EXCEPTION 'encrypted backup parent must be a sealed same-account lineage backup'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.state = 'sealed' AND (TG_OP = 'INSERT' OR OLD.state <> 'sealed') THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.user_id::TEXT, 0));
        SELECT count(*) INTO lineage_sealed_count
        FROM encrypted_profile_backups
        WHERE user_id = NEW.user_id
          AND profile_lineage_id = NEW.profile_lineage_id
          AND state = 'sealed'
          AND id <> NEW.id;
        IF lineage_sealed_count >= 3 THEN
            RAISE EXCEPTION 'encrypted backup lineage quota exceeded'
                USING ERRCODE = '23514';
        END IF;

        SELECT COALESCE(sum(total_ciphertext_size), 0) INTO account_sealed_bytes
        FROM encrypted_profile_backups
        WHERE user_id = NEW.user_id
          AND state = 'sealed'
          AND id <> NEW.id;
        IF account_sealed_bytes + NEW.total_ciphertext_size > 5368709120 THEN
            RAISE EXCEPTION 'encrypted backup account quota exceeded'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER encrypted_profile_backup_guard_trigger
BEFORE INSERT OR UPDATE ON encrypted_profile_backups
FOR EACH ROW EXECUTE FUNCTION enforce_encrypted_profile_backup_guard();

CREATE FUNCTION enforce_encrypted_backup_chunk_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    backup_state TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT state INTO backup_state
        FROM encrypted_profile_backups WHERE id = NEW.backup_id;
        IF backup_state NOT IN ('initiated', 'uploading') THEN
            RAISE EXCEPTION 'cannot add chunks after encrypted backup sealing'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        SELECT state INTO backup_state
        FROM encrypted_profile_backups WHERE id = OLD.backup_id;
        IF backup_state NOT IN ('deleting', 'deleted', 'expired') THEN
            RAISE EXCEPTION 'cannot delete chunks before cryptographic deletion'
                USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'encrypted backup chunks are immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER encrypted_backup_chunk_immutable_trigger
BEFORE INSERT OR UPDATE OR DELETE ON encrypted_backup_chunks
FOR EACH ROW EXECUTE FUNCTION enforce_encrypted_backup_chunk_immutable();

CREATE FUNCTION begin_encrypted_profile_backup_deletion(
    requested_backup_id UUID,
    requested_user_id UUID,
    requested_at TIMESTAMPTZ
)
RETURNS TABLE (object_key TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    current_state TEXT;
BEGIN
    SELECT state INTO current_state
    FROM encrypted_profile_backups
    WHERE id = requested_backup_id AND user_id = requested_user_id
    FOR UPDATE;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'encrypted backup not found' USING ERRCODE = 'P0002';
    END IF;
    IF current_state NOT IN ('sealed', 'deleting') THEN
        RAISE EXCEPTION 'encrypted backup cannot be deleted from state %', current_state
            USING ERRCODE = '23514';
    END IF;
    IF current_state = 'sealed' THEN
        UPDATE encrypted_profile_backups
        SET state = 'deleting',
            recovery_root_key_envelope = NULL,
            wrapped_data_key = NULL,
            deletion_started_at = requested_at,
            updated_at = requested_at
        WHERE id = requested_backup_id AND user_id = requested_user_id;
    END IF;
    UPDATE encrypted_backup_key_envelopes
    SET root_key_envelope = NULL,
        destroyed_at = COALESCE(destroyed_at, requested_at)
    WHERE backup_id = requested_backup_id
      AND root_key_envelope IS NOT NULL;

    RETURN QUERY
        SELECT backup.manifest_object_key
        FROM encrypted_profile_backups AS backup
        WHERE backup.id = requested_backup_id
          AND backup.manifest_object_key IS NOT NULL
        UNION ALL
        SELECT chunk.object_key
        FROM encrypted_backup_chunks AS chunk
        WHERE chunk.backup_id = requested_backup_id
        ORDER BY 1;
END;
$$;

REVOKE ALL ON FUNCTION begin_encrypted_profile_backup_deletion(UUID, UUID, TIMESTAMPTZ)
    FROM PUBLIC;
