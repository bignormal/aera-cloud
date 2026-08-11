ALTER TABLE devices
    ADD CONSTRAINT devices_id_user_id_key UNIQUE (id, user_id);

CREATE TABLE desktop_control_instances (
    device_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    organization_id UUID,
    workspace_id UUID,
    display_name TEXT NOT NULL,
    instance_type TEXT NOT NULL DEFAULT 'desktop',
    client_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    capabilities JSONB NOT NULL,
    last_heartbeat_at TIMESTAMPTZ,
    health_status TEXT NOT NULL DEFAULT 'unknown',
    health_summary JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT desktop_control_instances_device_user_fk
        FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE CASCADE,
    CONSTRAINT desktop_control_instances_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL,
    CONSTRAINT desktop_control_instances_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL,
    CONSTRAINT desktop_control_instances_display_name_check CHECK (
        display_name = btrim(display_name)
        AND char_length(display_name) BETWEEN 1 AND 100
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT desktop_control_instances_instance_type_check CHECK (instance_type = 'desktop'),
    CONSTRAINT desktop_control_instances_client_version_check CHECK (
        client_version = btrim(client_version)
        AND char_length(client_version) BETWEEN 1 AND 64
        AND client_version !~ '[[:cntrl:]]'
    ),
    CONSTRAINT desktop_control_instances_platform_check CHECK (platform IN ('darwin', 'windows', 'linux')),
    CONSTRAINT desktop_control_instances_arch_check CHECK (arch IN ('arm64', 'x64')),
    CONSTRAINT desktop_control_instances_capabilities_check CHECK (
        jsonb_typeof(capabilities) = 'array'
        AND capabilities <@ '["diagnostics.health.read"]'::jsonb
    ),
    CONSTRAINT desktop_control_instances_health_status_check CHECK (
        health_status IN ('unknown', 'healthy', 'degraded', 'unhealthy')
    ),
    CONSTRAINT desktop_control_instances_health_summary_check CHECK (
        (health_status = 'unknown' AND health_summary IS NULL)
        OR (
            health_status <> 'unknown'
            AND health_summary IS NOT NULL
            AND jsonb_typeof(health_summary) = 'object'
        )
    ),
    CONSTRAINT desktop_control_instances_time_check CHECK (updated_at >= created_at)
);

CREATE INDEX desktop_control_instances_user_updated_idx
    ON desktop_control_instances (user_id, updated_at DESC, device_id);
CREATE INDEX desktop_control_instances_organization_updated_idx
    ON desktop_control_instances (organization_id, updated_at DESC, device_id)
    WHERE organization_id IS NOT NULL;
CREATE INDEX desktop_control_instances_workspace_updated_idx
    ON desktop_control_instances (workspace_id, updated_at DESC, device_id)
    WHERE workspace_id IS NOT NULL;
CREATE INDEX desktop_control_instances_last_heartbeat_idx
    ON desktop_control_instances (last_heartbeat_at DESC, device_id);

CREATE TABLE desktop_control_commands (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    required_capability TEXT NOT NULL,
    idempotency_key_hash BYTEA NOT NULL,
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_code TEXT,
    result_summary JSONB,
    created_by_admin_id UUID NOT NULL,
    request_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT desktop_control_commands_type_check CHECK (type = 'health_check'),
    CONSTRAINT desktop_control_commands_capability_check CHECK (
        required_capability = 'diagnostics.health.read'
    ),
    CONSTRAINT desktop_control_commands_idempotency_key_hash_check CHECK (
        octet_length(idempotency_key_hash) = 32
    ),
    CONSTRAINT desktop_control_commands_state_check CHECK (
        state IN ('queued', 'claimed', 'running', 'succeeded', 'failed', 'expired')
    ),
    CONSTRAINT desktop_control_commands_result_code_check CHECK (
        result_code IS NULL OR result_code IN (
            'HEALTHY', 'DESKTOP_UNHEALTHY', 'RUNTIME_UNAVAILABLE',
            'GATEWAY_UNAVAILABLE', 'HEALTH_CHECK_TIMEOUT', 'CLIENT_INTERRUPTED'
        )
    ),
    CONSTRAINT desktop_control_commands_result_summary_check CHECK (
        result_summary IS NULL OR jsonb_typeof(result_summary) = 'object'
    ),
    CONSTRAINT desktop_control_commands_request_id_check CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128
    ),
    CONSTRAINT desktop_control_commands_device_id_idempotency_key_hash_key
        UNIQUE (device_id, idempotency_key_hash),
    CONSTRAINT desktop_control_commands_lifecycle_check CHECK (
        (
            state = 'queued'
            AND claimed_at IS NULL AND started_at IS NULL AND completed_at IS NULL
            AND result_code IS NULL AND result_summary IS NULL
        ) OR (
            state = 'claimed'
            AND claimed_at IS NOT NULL AND started_at IS NULL AND completed_at IS NULL
            AND result_code IS NULL AND result_summary IS NULL
        ) OR (
            state = 'running'
            AND claimed_at IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NULL
            AND result_code IS NULL AND result_summary IS NULL
        ) OR (
            state IN ('succeeded', 'failed')
            AND claimed_at IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NOT NULL
            AND result_code IS NOT NULL AND result_summary IS NOT NULL
        ) OR (
            state = 'expired'
            AND completed_at IS NOT NULL AND result_code IS NULL AND result_summary IS NULL
        )
    ),
    CONSTRAINT desktop_control_commands_time_check CHECK (
        expires_at = created_at + INTERVAL '10 minutes'
        AND updated_at >= created_at
        AND (claimed_at IS NULL OR claimed_at >= created_at)
        AND (started_at IS NULL OR started_at >= claimed_at)
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE INDEX desktop_control_commands_device_state_created_idx
    ON desktop_control_commands (device_id, state, created_at, id);
CREATE INDEX desktop_control_commands_expiry_idx
    ON desktop_control_commands (expires_at, id)
    WHERE state IN ('queued', 'claimed', 'running');

CREATE FUNCTION enforce_desktop_control_command_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.device_id IS DISTINCT FROM OLD.device_id
        OR NEW.type IS DISTINCT FROM OLD.type
        OR NEW.required_capability IS DISTINCT FROM OLD.required_capability
        OR NEW.idempotency_key_hash IS DISTINCT FROM OLD.idempotency_key_hash
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.created_by_admin_id IS DISTINCT FROM OLD.created_by_admin_id
        OR NEW.request_id IS DISTINCT FROM OLD.request_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'immutable Desktop control command core cannot be updated'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.state = OLD.state THEN
        IF NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
            OR NEW.started_at IS DISTINCT FROM OLD.started_at
            OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
            OR NEW.result_code IS DISTINCT FROM OLD.result_code
            OR NEW.result_summary IS DISTINCT FROM OLD.result_summary THEN
            RAISE EXCEPTION 'Desktop control command state cannot be rewritten'
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.state = 'queued' AND NEW.state IN ('claimed', 'expired'))
        OR (OLD.state = 'claimed' AND NEW.state IN ('running', 'expired'))
        OR (OLD.state = 'running' AND NEW.state IN ('succeeded', 'failed', 'expired'))
    ) THEN
        RAISE EXCEPTION 'invalid Desktop control command transition'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER desktop_control_commands_transition_trigger
    BEFORE UPDATE ON desktop_control_commands
    FOR EACH ROW EXECUTE FUNCTION enforce_desktop_control_command_transition();
