ALTER TABLE agent_definitions
    ADD COLUMN workspace_id UUID,
    ALTER COLUMN tenant_id DROP NOT NULL,
    ALTER COLUMN owner_id DROP NOT NULL,
    DROP CONSTRAINT agent_definitions_owner_scope_check,
    ADD CONSTRAINT agent_definitions_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_definitions_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL AND workspace_id IS NULL)
        OR
        (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL AND workspace_id IS NOT NULL)
    );

ALTER TABLE agent_versions
    ADD COLUMN workspace_id UUID,
    ALTER COLUMN tenant_id DROP NOT NULL,
    ALTER COLUMN owner_id DROP NOT NULL,
    DROP CONSTRAINT agent_versions_owner_scope_check,
    ADD CONSTRAINT agent_versions_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_versions_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL AND workspace_id IS NULL)
        OR
        (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL AND workspace_id IS NOT NULL)
    );

ALTER TABLE agent_control_idempotency_keys
    ADD COLUMN workspace_id UUID,
    ALTER COLUMN tenant_id DROP NOT NULL,
    ALTER COLUMN owner_id DROP NOT NULL,
    DROP CONSTRAINT agent_control_idempotency_owner_scope_check,
    DROP CONSTRAINT agent_control_idempotency_owner_operation_key,
    ADD CONSTRAINT agent_control_idempotency_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    ADD CONSTRAINT agent_control_idempotency_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL AND workspace_id IS NULL)
        OR
        (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL AND workspace_id IS NOT NULL)
    );

CREATE UNIQUE INDEX agent_control_idempotency_user_operation_key
    ON agent_control_idempotency_keys (tenant_id, owner_id, operation, key_hash)
    WHERE owner_scope = 'USER';

CREATE UNIQUE INDEX agent_control_idempotency_workspace_operation_key
    ON agent_control_idempotency_keys (workspace_id, operation, key_hash)
    WHERE owner_scope = 'WORKSPACE';

CREATE INDEX agent_definitions_workspace_list_idx
    ON agent_definitions (workspace_id, updated_at DESC)
    WHERE owner_scope = 'WORKSPACE';

CREATE INDEX agent_versions_workspace_time_idx
    ON agent_versions (workspace_id, published_at DESC)
    WHERE owner_scope = 'WORKSPACE';
