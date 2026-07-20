CREATE TABLE workspaces (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ,
    CONSTRAINT workspaces_owner_user_fk
        FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT workspaces_display_name_check CHECK (
        display_name = btrim(display_name)
        AND char_length(btrim(display_name)) BETWEEN 1 AND 80
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workspaces_status_check CHECK (status IN ('active', 'archived')),
    CONSTRAINT workspaces_revision_check CHECK (revision > 0),
    CONSTRAINT workspaces_lifecycle_check CHECK (
        (status = 'active' AND archived_at IS NULL)
        OR (status = 'archived' AND archived_at IS NOT NULL)
    )
);

CREATE TABLE workspace_memberships (
    workspace_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    joined_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT workspace_memberships_pkey PRIMARY KEY (workspace_id, user_id),
    CONSTRAINT workspace_memberships_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    CONSTRAINT workspace_memberships_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT workspace_memberships_role_check CHECK (role IN ('owner', 'admin', 'member')),
    CONSTRAINT workspace_memberships_revision_check CHECK (revision > 0)
);

CREATE TABLE workspace_invitations (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL,
    token_digest BYTEA NOT NULL,
    created_by_user_id UUID,
    status TEXT NOT NULL,
    accepted_by_user_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT workspace_invitations_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    CONSTRAINT workspace_invitations_created_by_user_fk
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT workspace_invitations_accepted_by_user_fk
        FOREIGN KEY (accepted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT workspace_invitations_token_digest_key UNIQUE (token_digest),
    CONSTRAINT workspace_invitations_token_digest_length_check CHECK (octet_length(token_digest) = 32),
    CONSTRAINT workspace_invitations_status_check CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    CONSTRAINT workspace_invitations_expiry_check CHECK (expires_at = created_at + INTERVAL '7 days'),
    CONSTRAINT workspace_invitations_lifecycle_check CHECK (
        (status = 'pending' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL)
        OR (status = 'accepted' AND accepted_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'revoked' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NOT NULL)
        OR (status = 'expired' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL)
    )
);

CREATE TABLE workspace_idempotency_records (
    actor_user_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    operation TEXT NOT NULL,
    key_digest BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT workspace_idempotency_records_pkey PRIMARY KEY (actor_user_id, operation, key_digest),
    CONSTRAINT workspace_idempotency_records_actor_user_fk
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT workspace_idempotency_records_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    CONSTRAINT workspace_idempotency_operation_check CHECK (char_length(operation) BETWEEN 1 AND 64),
    CONSTRAINT workspace_idempotency_key_digest_length_check CHECK (octet_length(key_digest) = 32),
    CONSTRAINT workspace_idempotency_request_digest_length_check CHECK (octet_length(request_digest) = 32),
    CONSTRAINT workspace_idempotency_resource_type_check CHECK (char_length(resource_type) BETWEEN 1 AND 64),
    CONSTRAINT workspace_idempotency_expiry_check CHECK (expires_at = created_at + INTERVAL '24 hours')
);

CREATE UNIQUE INDEX workspace_memberships_one_owner_idx
    ON workspace_memberships (workspace_id)
    WHERE role = 'owner';

CREATE INDEX workspaces_owner_active_idx
    ON workspaces (owner_user_id)
    WHERE status = 'active';

CREATE INDEX workspace_memberships_user_list_idx
    ON workspace_memberships (user_id, workspace_id);

CREATE INDEX workspace_invitations_pending_idx
    ON workspace_invitations (workspace_id, expires_at)
    WHERE status = 'pending';

CREATE INDEX workspace_idempotency_expiry_idx
    ON workspace_idempotency_records (expires_at);

CREATE FUNCTION reject_workspace_owner_user_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
        RAISE EXCEPTION 'workspace owner_user_id is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspaces_owner_user_immutable_trigger
    BEFORE UPDATE ON workspaces
    FOR EACH ROW EXECUTE FUNCTION reject_workspace_owner_user_mutation();

CREATE FUNCTION assert_workspace_owner_membership(target_workspace_id UUID)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    expected_owner_user_id UUID;
    owner_membership_count BIGINT;
    matching_owner_count BIGINT;
BEGIN
    SELECT owner_user_id
    INTO expected_owner_user_id
    FROM workspaces
    WHERE id = target_workspace_id;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT
        count(*),
        count(*) FILTER (WHERE user_id = expected_owner_user_id)
    INTO owner_membership_count, matching_owner_count
    FROM workspace_memberships
    WHERE workspace_id = target_workspace_id
      AND role = 'owner';

    IF owner_membership_count <> 1 OR matching_owner_count <> 1 THEN
        RAISE EXCEPTION 'workspace must have exactly one matching Owner membership'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION enforce_workspace_owner_membership()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'workspaces' THEN
        IF TG_OP = 'DELETE' THEN
            PERFORM assert_workspace_owner_membership(OLD.id);
            RETURN OLD;
        END IF;

        PERFORM assert_workspace_owner_membership(NEW.id);
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        PERFORM assert_workspace_owner_membership(OLD.workspace_id);
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
        PERFORM assert_workspace_owner_membership(OLD.workspace_id);
    END IF;
    PERFORM assert_workspace_owner_membership(NEW.workspace_id);
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER workspaces_owner_membership_constraint_trigger
    AFTER INSERT OR UPDATE OR DELETE ON workspaces
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_workspace_owner_membership();

CREATE CONSTRAINT TRIGGER workspace_memberships_owner_constraint_trigger
    AFTER INSERT OR UPDATE OR DELETE ON workspace_memberships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_workspace_owner_membership();

CREATE FUNCTION enforce_workspace_invitation_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF OLD.status <> 'pending' OR NEW.status NOT IN ('accepted', 'revoked', 'expired') THEN
            RAISE EXCEPTION 'invalid workspace invitation status transition'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_invitations_lifecycle_trigger
    BEFORE UPDATE ON workspace_invitations
    FOR EACH ROW EXECUTE FUNCTION enforce_workspace_invitation_lifecycle();
