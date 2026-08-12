CREATE TABLE official_agent_delivery_verifications (
    request_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    installation_id UUID NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    definition_id UUID NOT NULL,
    version_id UUID NOT NULL,
    release_revision_id UUID NOT NULL,
    content_digest BYTEA NOT NULL,
    verification_status TEXT NOT NULL,
    error_code TEXT,
    runtime_version TEXT NOT NULL,
    desktop_version TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_delivery_verification_digest_check CHECK (octet_length(content_digest) = 32),
    CONSTRAINT official_delivery_verification_status_check CHECK (
        verification_status IN ('catalog_visible', 'signature_verified', 'compatible', 'installed', 'activated', 'failed')
    ),
    CONSTRAINT official_delivery_verification_error_check CHECK (
        (verification_status = 'failed' AND error_code IS NOT NULL)
        OR (verification_status <> 'failed' AND error_code IS NULL)
    ),
    CONSTRAINT official_delivery_verification_error_code_check CHECK (
        error_code IS NULL OR error_code IN (
            'catalog_unavailable',
            'invalid_response',
            'signature_verification_failed',
            'runtime_incompatible',
            'content_digest_mismatch',
            'installation_failed',
            'activation_failed',
            'cloud_unavailable'
        )
    ),
    CONSTRAINT official_delivery_verification_runtime_check CHECK (char_length(runtime_version) BETWEEN 1 AND 128),
    CONSTRAINT official_delivery_verification_desktop_check CHECK (char_length(desktop_version) BETWEEN 1 AND 128)
);

CREATE INDEX official_delivery_verification_timeline_idx
    ON official_agent_delivery_verifications (tenant_id, owner_id, device_id, definition_id, occurred_at DESC);

CREATE TRIGGER official_agent_delivery_verification_immutable_trigger
    BEFORE UPDATE OR DELETE ON official_agent_delivery_verifications
    FOR EACH ROW EXECUTE FUNCTION reject_agent_control_immutable_mutation();
