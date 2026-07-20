CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    current_policy_snapshot_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ,
    dissolved_at TIMESTAMPTZ,
    CONSTRAINT organizations_display_name_check CHECK (
        display_name = btrim(display_name)
        AND char_length(display_name) BETWEEN 1 AND 120
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT organizations_status_check CHECK (status IN ('active', 'archived', 'dissolved')),
    CONSTRAINT organizations_revision_check CHECK (revision > 0),
    CONSTRAINT organizations_policy_required_check CHECK (
        status = 'dissolved' OR current_policy_snapshot_id IS NOT NULL
    ),
    CONSTRAINT organizations_lifecycle_check CHECK (
        (status = 'active' AND archived_at IS NULL AND dissolved_at IS NULL)
        OR (status = 'archived' AND archived_at IS NOT NULL AND dissolved_at IS NULL)
        OR (status = 'dissolved' AND archived_at IS NOT NULL AND dissolved_at IS NOT NULL)
    )
);

CREATE TABLE organization_departments (
    organization_id UUID NOT NULL,
    id UUID NOT NULL,
    display_name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    status TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ,
    CONSTRAINT organization_departments_pkey PRIMARY KEY (organization_id, id),
    CONSTRAINT organization_departments_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    CONSTRAINT organization_departments_display_name_check CHECK (
        display_name = btrim(display_name)
        AND char_length(display_name) BETWEEN 1 AND 80
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT organization_departments_name_key_check CHECK (
        name_key = btrim(name_key)
        AND char_length(name_key) BETWEEN 1 AND 256
        AND name_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT organization_departments_status_check CHECK (status IN ('active', 'archived')),
    CONSTRAINT organization_departments_revision_check CHECK (revision > 0),
    CONSTRAINT organization_departments_lifecycle_check CHECK (
        (status = 'active' AND archived_at IS NULL)
        OR (status = 'archived' AND archived_at IS NOT NULL)
    )
);

CREATE TABLE organization_memberships (
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role TEXT NOT NULL,
    department_id UUID,
    revision BIGINT NOT NULL DEFAULT 1,
    joined_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT organization_memberships_pkey PRIMARY KEY (organization_id, user_id),
    CONSTRAINT organization_memberships_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_department_fk
        FOREIGN KEY (organization_id, department_id)
        REFERENCES organization_departments(organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_role_check CHECK (role IN ('owner', 'admin', 'auditor', 'member')),
    CONSTRAINT organization_memberships_revision_check CHECK (revision > 0)
);

CREATE TABLE organization_invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    token_digest BYTEA NOT NULL,
    created_by_user_id UUID,
    status TEXT NOT NULL,
    accepted_by_user_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT organization_invitations_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    CONSTRAINT organization_invitations_created_by_user_fk
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT organization_invitations_accepted_by_user_fk
        FOREIGN KEY (accepted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT organization_invitations_token_digest_key UNIQUE (token_digest),
    CONSTRAINT organization_invitations_token_digest_length_check CHECK (octet_length(token_digest) = 32),
    CONSTRAINT organization_invitations_status_check CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    CONSTRAINT organization_invitations_expiry_check CHECK (expires_at = created_at + INTERVAL '7 days'),
    CONSTRAINT organization_invitations_lifecycle_check CHECK (
        (status = 'pending' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL)
        OR (status = 'accepted' AND accepted_by_user_id IS NOT NULL AND accepted_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'revoked' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NOT NULL)
        OR (status = 'expired' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL)
    )
);

CREATE TABLE organization_policy_snapshots (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    policy_version BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    policy_document JSONB NOT NULL,
    content_digest BYTEA NOT NULL,
    issuer TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    issued_by_user_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT organization_policy_snapshots_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    CONSTRAINT organization_policy_snapshots_issued_by_user_fk
        FOREIGN KEY (issued_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT organization_policy_snapshots_organization_version_key
        UNIQUE (organization_id, policy_version),
    CONSTRAINT organization_policy_snapshots_organization_id_id_key
        UNIQUE (organization_id, id),
    CONSTRAINT organization_policy_snapshots_policy_version_check CHECK (policy_version > 0),
    CONSTRAINT organization_policy_snapshots_schema_version_check CHECK (schema_version = 1),
    CONSTRAINT organization_policy_snapshots_document_check CHECK (jsonb_typeof(policy_document) = 'object'),
    CONSTRAINT organization_policy_snapshots_content_digest_length_check CHECK (octet_length(content_digest) = 32),
    CONSTRAINT organization_policy_snapshots_issuer_check CHECK (
        issuer = btrim(issuer) AND char_length(issuer) BETWEEN 1 AND 512 AND issuer !~ '[[:cntrl:]]'
    ),
    CONSTRAINT organization_policy_snapshots_signing_key_id_check CHECK (
        signing_key_id = btrim(signing_key_id)
        AND char_length(signing_key_id) BETWEEN 1 AND 128
        AND signing_key_id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT organization_policy_snapshots_signature_length_check CHECK (octet_length(signature) = 64)
);

ALTER TABLE organizations
    ADD CONSTRAINT organizations_current_policy_fk
    FOREIGN KEY (id, current_policy_snapshot_id)
    REFERENCES organization_policy_snapshots(organization_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE organization_idempotency_records (
    actor_user_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    operation TEXT NOT NULL,
    key_digest BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT organization_idempotency_records_pkey PRIMARY KEY (actor_user_id, operation, key_digest),
    CONSTRAINT organization_idempotency_records_actor_user_fk
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT organization_idempotency_records_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT organization_idempotency_operation_check CHECK (
        operation = btrim(operation) AND char_length(operation) BETWEEN 1 AND 64
    ),
    CONSTRAINT organization_idempotency_key_digest_length_check CHECK (octet_length(key_digest) = 32),
    CONSTRAINT organization_idempotency_request_digest_length_check CHECK (octet_length(request_digest) = 32),
    CONSTRAINT organization_idempotency_resource_type_check CHECK (
        resource_type = btrim(resource_type) AND char_length(resource_type) BETWEEN 1 AND 64
    ),
    CONSTRAINT organization_idempotency_expiry_check CHECK (expires_at = created_at + INTERVAL '24 hours')
);

ALTER TABLE audit_events
    ADD COLUMN organization_id UUID,
    ADD CONSTRAINT audit_events_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX organization_memberships_one_owner_idx
    ON organization_memberships (organization_id)
    WHERE role = 'owner';

CREATE INDEX organization_memberships_user_list_idx
    ON organization_memberships (user_id, organization_id);

CREATE UNIQUE INDEX organization_departments_active_name_idx
    ON organization_departments (organization_id, name_key)
    WHERE status = 'active';

CREATE INDEX organization_departments_list_idx
    ON organization_departments (organization_id, status, display_name, id);

CREATE INDEX organization_invitations_pending_idx
    ON organization_invitations (organization_id, expires_at, id)
    WHERE status = 'pending';

CREATE INDEX organization_policy_snapshots_history_idx
    ON organization_policy_snapshots (organization_id, policy_version DESC, id DESC);

CREATE INDEX organization_idempotency_expiry_idx
    ON organization_idempotency_records (expires_at);

CREATE INDEX audit_events_organization_created_idx
    ON audit_events (organization_id, created_at DESC, id DESC)
    WHERE organization_id IS NOT NULL;

CREATE FUNCTION enforce_organization_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'dissolved' THEN
        RAISE EXCEPTION 'dissolved organization is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'active' AND NEW.status = 'archived')
        OR (OLD.status = 'archived' AND NEW.status IN ('active', 'dissolved'))
    ) THEN
        RAISE EXCEPTION 'invalid organization status transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_lifecycle_trigger
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_lifecycle();

CREATE FUNCTION assert_organization_owner_membership(target_organization_id UUID)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    organization_status TEXT;
    membership_count BIGINT;
    owner_count BIGINT;
BEGIN
    SELECT status
    INTO organization_status
    FROM organizations
    WHERE id = target_organization_id;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT count(*), count(*) FILTER (WHERE role = 'owner')
    INTO membership_count, owner_count
    FROM organization_memberships
    WHERE organization_id = target_organization_id;

    IF organization_status IN ('active', 'archived') AND owner_count <> 1 THEN
        RAISE EXCEPTION 'active or archived organization must have exactly one Owner membership'
            USING ERRCODE = '23514';
    END IF;
    IF organization_status = 'dissolved' AND membership_count <> 0 THEN
        RAISE EXCEPTION 'dissolved organization must have no memberships'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION enforce_organization_owner_membership()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'organizations' THEN
        IF TG_OP = 'DELETE' THEN
            PERFORM assert_organization_owner_membership(OLD.id);
            RETURN OLD;
        END IF;
        PERFORM assert_organization_owner_membership(NEW.id);
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        PERFORM assert_organization_owner_membership(OLD.organization_id);
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        PERFORM assert_organization_owner_membership(OLD.organization_id);
    END IF;
    PERFORM assert_organization_owner_membership(NEW.organization_id);
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER organizations_owner_membership_constraint_trigger
    AFTER INSERT OR UPDATE OR DELETE ON organizations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_owner_membership();

CREATE CONSTRAINT TRIGGER organization_memberships_owner_constraint_trigger
    AFTER INSERT OR UPDATE OR DELETE ON organization_memberships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_owner_membership();

CREATE FUNCTION enforce_organization_department_assignment()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    department_status TEXT;
BEGIN
    IF NEW.department_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT status
    INTO department_status
    FROM organization_departments
    WHERE organization_id = NEW.organization_id AND id = NEW.department_id;
    IF NOT FOUND OR department_status <> 'active' THEN
        RAISE EXCEPTION 'organization membership department must be active'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_memberships_department_active_trigger
    BEFORE INSERT OR UPDATE OF organization_id, department_id ON organization_memberships
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_department_assignment();

CREATE FUNCTION enforce_organization_department_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF OLD.status = 'active' AND NEW.status = 'archived' THEN
            IF EXISTS (
                SELECT 1 FROM organization_memberships
                WHERE organization_id = OLD.organization_id AND department_id = OLD.id
            ) THEN
                RAISE EXCEPTION 'organization department must be empty before archive'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF NOT (OLD.status = 'archived' AND NEW.status = 'active') THEN
            RAISE EXCEPTION 'invalid organization department status transition'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_departments_lifecycle_trigger
    BEFORE UPDATE ON organization_departments
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_department_lifecycle();

CREATE FUNCTION enforce_organization_invitation_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'organization invitation identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF OLD.status <> 'pending' OR NEW.status NOT IN ('accepted', 'revoked', 'expired') THEN
            RAISE EXCEPTION 'invalid organization invitation status transition'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_invitations_lifecycle_trigger
    BEFORE UPDATE ON organization_invitations
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_invitation_lifecycle();

CREATE FUNCTION reject_organization_policy_snapshot_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'organization policy snapshots are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER organization_policy_snapshots_immutable_trigger
    BEFORE UPDATE OR DELETE ON organization_policy_snapshots
    FOR EACH ROW EXECUTE FUNCTION reject_organization_policy_snapshot_mutation();
