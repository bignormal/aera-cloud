ALTER TABLE users
    ADD COLUMN administrative_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT users_administrative_revision_check CHECK (administrative_revision > 0);

CREATE TABLE admin_operations (
    operation_id UUID PRIMARY KEY,
    idempotency_key_id TEXT NOT NULL,
    idempotency_key_hmac BYTEA NOT NULL,
    request_fingerprint BYTEA NOT NULL,
    service_subject TEXT NOT NULL,
    actor_admin_id UUID NOT NULL,
    approval_id UUID,
    request_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id UUID NOT NULL,
    expected_revision BIGINT NOT NULL,
    result_revision BIGINT,
    status TEXT NOT NULL,
    error_code TEXT,
    reason_code TEXT NOT NULL,
    ticket_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT admin_operations_idempotency_hmac_length_check
        CHECK (octet_length(idempotency_key_hmac) = 32),
    CONSTRAINT admin_operations_request_fingerprint_length_check
        CHECK (octet_length(request_fingerprint) = 32),
    CONSTRAINT admin_operations_action_check
        CHECK (action IN ('revoke_device', 'revoke_session', 'disable_user', 'enable_user')),
    CONSTRAINT admin_operations_target_type_check
        CHECK (target_type IN ('device', 'session', 'user')),
    CONSTRAINT admin_operations_expected_revision_check CHECK (expected_revision > 0),
    CONSTRAINT admin_operations_result_revision_check
        CHECK (result_revision IS NULL OR result_revision > 0),
    CONSTRAINT admin_operations_status_check
        CHECK (status IN ('executing', 'succeeded', 'failed', 'conflict')),
    CONSTRAINT admin_operations_key_id_length_check
        CHECK (char_length(idempotency_key_id) BETWEEN 1 AND 64),
    CONSTRAINT admin_operations_service_subject_check
        CHECK (service_subject ~ '^[a-z][a-z0-9._-]{2,63}$'),
    CONSTRAINT admin_operations_request_id_length_check
        CHECK (char_length(request_id) BETWEEN 1 AND 128),
    CONSTRAINT admin_operations_reason_code_check
        CHECK (reason_code ~ '^[a-z][a-z0-9_]{2,63}$'),
    CONSTRAINT admin_operations_ticket_reference_check
        CHECK (ticket_reference IS NULL OR char_length(ticket_reference) BETWEEN 1 AND 128),
    CONSTRAINT admin_operations_error_code_check
        CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{2,99}$'),
    CONSTRAINT admin_operations_action_target_check CHECK (
        (action = 'revoke_device' AND target_type = 'device') OR
        (action = 'revoke_session' AND target_type = 'session') OR
        (action IN ('disable_user', 'enable_user') AND target_type = 'user')
    ),
    CONSTRAINT admin_operations_approval_check CHECK (
        (action IN ('disable_user', 'enable_user') AND approval_id IS NOT NULL) OR
        (action IN ('revoke_device', 'revoke_session'))
    ),
    CONSTRAINT admin_operations_terminal_state_check CHECK (
        (status = 'executing' AND completed_at IS NULL AND result_revision IS NULL AND error_code IS NULL) OR
        (status = 'succeeded' AND completed_at IS NOT NULL AND result_revision IS NOT NULL AND error_code IS NULL) OR
        (status IN ('failed', 'conflict') AND completed_at IS NOT NULL AND error_code IS NOT NULL)
    ),
    CONSTRAINT admin_operations_time_check CHECK (
        updated_at >= created_at AND (completed_at IS NULL OR completed_at >= created_at)
    ),
    CONSTRAINT admin_operations_idempotency_key_unique
        UNIQUE (idempotency_key_id, idempotency_key_hmac)
);

CREATE INDEX admin_operations_target_time_idx
    ON admin_operations(target_type, target_id, created_at DESC);

CREATE INDEX admin_operations_updated_idx
    ON admin_operations(updated_at DESC);
