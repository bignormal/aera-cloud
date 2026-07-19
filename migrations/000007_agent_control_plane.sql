CREATE TABLE agent_definitions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_scope TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    icon_media_type TEXT,
    icon_data BYTEA,
    status TEXT NOT NULL,
    latest_version_id UUID,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT agent_definitions_owner_scope_check CHECK (owner_scope = 'USER'),
    CONSTRAINT agent_definitions_display_name_check CHECK (char_length(display_name) BETWEEN 1 AND 100),
    CONSTRAINT agent_definitions_icon_media_type_check CHECK (icon_media_type IS NULL OR icon_media_type IN ('image/png', 'image/webp')),
    CONSTRAINT agent_definitions_icon_pair_check CHECK ((icon_media_type IS NULL) = (icon_data IS NULL)),
    CONSTRAINT agent_definitions_icon_size_check CHECK (icon_data IS NULL OR octet_length(icon_data) <= 524288),
    CONSTRAINT agent_definitions_status_check CHECK (status IN ('active', 'archived'))
);

CREATE TABLE agent_versions (
    id UUID PRIMARY KEY,
    definition_id UUID NOT NULL REFERENCES agent_definitions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_scope TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version_number BIGINT NOT NULL,
    canonical_manifest JSONB NOT NULL,
    bundle JSONB NOT NULL,
    content_digest BYTEA NOT NULL,
    signing_key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    runtime_minimum_version TEXT NOT NULL,
    runtime_maximum_version_exclusive TEXT,
    published_by UUID NOT NULL REFERENCES users(id),
    published_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT agent_versions_owner_scope_check CHECK (owner_scope = 'USER'),
    CONSTRAINT agent_versions_version_number_check CHECK (version_number > 0),
    CONSTRAINT agent_versions_manifest_object_check CHECK (jsonb_typeof(canonical_manifest) = 'object'),
    CONSTRAINT agent_versions_bundle_object_check CHECK (jsonb_typeof(bundle) = 'object'),
    CONSTRAINT agent_versions_content_digest_length_check CHECK (octet_length(content_digest) = 32),
    CONSTRAINT agent_versions_signing_key_id_check CHECK (char_length(signing_key_id) BETWEEN 1 AND 128),
    CONSTRAINT agent_versions_signature_length_check CHECK (octet_length(signature) = 64),
    CONSTRAINT agent_versions_runtime_minimum_check CHECK (char_length(runtime_minimum_version) BETWEEN 1 AND 128),
    CONSTRAINT agent_versions_runtime_maximum_check CHECK (
        runtime_maximum_version_exclusive IS NULL
        OR char_length(runtime_maximum_version_exclusive) BETWEEN 1 AND 128
    ),
    CONSTRAINT agent_versions_definition_version_key UNIQUE (definition_id, version_number)
);

ALTER TABLE agent_definitions
    ADD CONSTRAINT agent_definitions_latest_version_fk
    FOREIGN KEY (latest_version_id) REFERENCES agent_versions(id)
    ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE installations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_scope TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    device_installation_id UUID NOT NULL,
    definition_id UUID NOT NULL REFERENCES agent_definitions(id) ON DELETE CASCADE,
    selected_version_id UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    runtime_profile_id UUID,
    policy_snapshot_id UUID,
    update_policy TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    archived_at TIMESTAMPTZ,
    CONSTRAINT installations_owner_scope_check CHECK (owner_scope = 'USER'),
    CONSTRAINT installations_update_policy_check CHECK (update_policy = 'manual'),
    CONSTRAINT installations_status_check CHECK (status IN ('pending', 'active', 'archived')),
    CONSTRAINT installations_activation_pair_check CHECK ((runtime_profile_id IS NULL) = (activated_at IS NULL)),
    CONSTRAINT installations_lifecycle_check CHECK (
        (status = 'pending' AND runtime_profile_id IS NULL AND policy_snapshot_id IS NULL AND activated_at IS NULL AND archived_at IS NULL)
        OR
        (status = 'active' AND runtime_profile_id IS NOT NULL AND policy_snapshot_id IS NOT NULL AND activated_at IS NOT NULL AND archived_at IS NULL)
        OR
        (status = 'archived' AND archived_at IS NOT NULL)
    ),
    CONSTRAINT installations_owner_runtime_profile_key UNIQUE (tenant_id, owner_scope, owner_id, runtime_profile_id)
);

CREATE TABLE policy_snapshots (
    id UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    agent_version_id UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_scope TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_version BIGINT NOT NULL,
    policy_document JSONB NOT NULL,
    content_digest BYTEA NOT NULL,
    issuer TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT policy_snapshots_owner_scope_check CHECK (owner_scope = 'USER'),
    CONSTRAINT policy_snapshots_policy_version_check CHECK (policy_version > 0),
    CONSTRAINT policy_snapshots_document_object_check CHECK (jsonb_typeof(policy_document) = 'object'),
    CONSTRAINT policy_snapshots_content_digest_length_check CHECK (octet_length(content_digest) = 32),
    CONSTRAINT policy_snapshots_issuer_check CHECK (char_length(issuer) BETWEEN 1 AND 128),
    CONSTRAINT policy_snapshots_signing_key_id_check CHECK (char_length(signing_key_id) BETWEEN 1 AND 128),
    CONSTRAINT policy_snapshots_signature_length_check CHECK (octet_length(signature) = 64),
    CONSTRAINT policy_snapshots_installation_version_key UNIQUE (installation_id, policy_version)
);

ALTER TABLE installations
    ADD CONSTRAINT installations_policy_snapshot_fk
    FOREIGN KEY (policy_snapshot_id) REFERENCES policy_snapshots(id)
    ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE agent_version_revocations (
    id UUID PRIMARY KEY,
    version_id UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_scope TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason_code TEXT NOT NULL,
    actor_user_id UUID NOT NULL REFERENCES users(id),
    policy_snapshot_id UUID NOT NULL REFERENCES policy_snapshots(id) ON DELETE CASCADE,
    superseding_version_id UUID REFERENCES agent_versions(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT agent_version_revocations_owner_scope_check CHECK (owner_scope = 'USER'),
    CONSTRAINT agent_version_revocations_reason_code_check CHECK (char_length(reason_code) BETWEEN 1 AND 64),
    CONSTRAINT agent_version_revocations_superseding_check CHECK (superseding_version_id IS NULL OR superseding_version_id <> version_id),
    CONSTRAINT agent_version_revocations_version_key UNIQUE (version_id)
);

CREATE TABLE runtime_binding_records (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_scope TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    agent_installation_id UUID NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    agent_version_id UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    runtime_profile_id UUID NOT NULL,
    runtime_version TEXT NOT NULL,
    policy_snapshot_id UUID NOT NULL REFERENCES policy_snapshots(id) ON DELETE CASCADE,
    tool_permission_digest BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT runtime_binding_records_owner_scope_check CHECK (owner_scope = 'USER'),
    CONSTRAINT runtime_binding_records_runtime_version_check CHECK (char_length(runtime_version) BETWEEN 1 AND 128),
    CONSTRAINT runtime_binding_records_tool_digest_length_check CHECK (octet_length(tool_permission_digest) = 32)
);

CREATE TABLE agent_control_idempotency_keys (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    owner_scope TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation TEXT NOT NULL,
    key_hash BYTEA NOT NULL,
    request_hash BYTEA NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NOT NULL,
    response_document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT agent_control_idempotency_owner_scope_check CHECK (owner_scope = 'USER'),
    CONSTRAINT agent_control_idempotency_operation_check CHECK (char_length(operation) BETWEEN 1 AND 64),
    CONSTRAINT agent_control_idempotency_key_hash_length_check CHECK (octet_length(key_hash) = 32),
    CONSTRAINT agent_control_idempotency_request_hash_length_check CHECK (octet_length(request_hash) = 32),
    CONSTRAINT agent_control_idempotency_resource_type_check CHECK (char_length(resource_type) BETWEEN 1 AND 64),
    CONSTRAINT agent_control_idempotency_response_object_check CHECK (jsonb_typeof(response_document) = 'object'),
    CONSTRAINT agent_control_idempotency_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT agent_control_idempotency_owner_operation_key UNIQUE (
        tenant_id, owner_scope, owner_id, operation, key_hash
    )
);

CREATE INDEX agent_definitions_owner_list_idx
    ON agent_definitions (tenant_id, owner_scope, owner_id, updated_at DESC);
CREATE INDEX agent_versions_definition_order_idx
    ON agent_versions (definition_id, version_number DESC);
CREATE INDEX agent_versions_owner_time_idx
    ON agent_versions (tenant_id, owner_scope, owner_id, published_at DESC);
CREATE INDEX agent_version_revocations_owner_lookup_idx
    ON agent_version_revocations (tenant_id, owner_scope, owner_id, version_id);
CREATE INDEX installations_owner_list_idx
    ON installations (tenant_id, owner_scope, owner_id, updated_at DESC);
CREATE INDEX installations_active_idx
    ON installations (tenant_id, owner_scope, owner_id, device_id, definition_id)
    WHERE status = 'active';
CREATE INDEX policy_snapshots_owner_lookup_idx
    ON policy_snapshots (tenant_id, owner_scope, owner_id, installation_id, policy_version DESC);
CREATE INDEX runtime_binding_records_owner_lookup_idx
    ON runtime_binding_records (tenant_id, owner_scope, owner_id, agent_installation_id, created_at DESC);
CREATE INDEX agent_control_idempotency_expiry_idx
    ON agent_control_idempotency_keys (expires_at);

CREATE FUNCTION reject_agent_control_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_owner_status TEXT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'immutable Agent control-plane row cannot be updated'
            USING ERRCODE = '55000';
    END IF;

    SELECT status INTO current_owner_status FROM users WHERE id = OLD.owner_id;
    IF current_owner_status = 'pending_deletion' THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'immutable Agent control-plane row cannot be deleted'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER agent_versions_immutable_trigger
    BEFORE UPDATE OR DELETE ON agent_versions
    FOR EACH ROW EXECUTE FUNCTION reject_agent_control_immutable_mutation();

CREATE TRIGGER policy_snapshots_immutable_trigger
    BEFORE UPDATE OR DELETE ON policy_snapshots
    FOR EACH ROW EXECUTE FUNCTION reject_agent_control_immutable_mutation();

CREATE TRIGGER agent_version_revocations_immutable_trigger
    BEFORE UPDATE OR DELETE ON agent_version_revocations
    FOR EACH ROW EXECUTE FUNCTION reject_agent_control_immutable_mutation();

CREATE TRIGGER runtime_binding_records_immutable_trigger
    BEFORE UPDATE OR DELETE ON runtime_binding_records
    FOR EACH ROW EXECUTE FUNCTION reject_agent_control_immutable_mutation();
