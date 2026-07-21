ALTER TABLE agent_definitions
    ADD COLUMN organization_id UUID,
    DROP CONSTRAINT agent_definitions_owner_variant_check,
    ADD CONSTRAINT agent_definitions_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_definitions_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL
            AND workspace_id IS NULL AND organization_id IS NULL)
        OR (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NOT NULL AND organization_id IS NULL)
        OR (owner_scope = 'ORGANIZATION' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NOT NULL)
    );

ALTER TABLE agent_versions
    ADD COLUMN organization_id UUID,
    ADD COLUMN organization_submission_id UUID,
    ADD COLUMN organization_policy_snapshot_id UUID,
    DROP CONSTRAINT agent_versions_owner_variant_check,
    ADD CONSTRAINT agent_versions_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_versions_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL
            AND workspace_id IS NULL AND organization_id IS NULL
            AND organization_submission_id IS NULL AND organization_policy_snapshot_id IS NULL)
        OR (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NOT NULL AND organization_id IS NULL
            AND organization_submission_id IS NULL AND organization_policy_snapshot_id IS NULL)
        OR (owner_scope = 'ORGANIZATION' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NOT NULL
            AND organization_submission_id IS NOT NULL AND organization_policy_snapshot_id IS NOT NULL)
    ),
    ADD CONSTRAINT agent_versions_organization_policy_fk
        FOREIGN KEY (organization_id, organization_policy_snapshot_id)
        REFERENCES organization_policy_snapshots(organization_id, id) ON DELETE RESTRICT;

ALTER TABLE agent_control_idempotency_keys
    ADD COLUMN organization_id UUID,
    DROP CONSTRAINT agent_control_idempotency_owner_variant_check,
    ADD CONSTRAINT agent_control_idempotency_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    ADD CONSTRAINT agent_control_idempotency_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL
            AND workspace_id IS NULL AND organization_id IS NULL)
        OR (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NOT NULL AND organization_id IS NULL)
        OR (owner_scope = 'ORGANIZATION' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NOT NULL)
    );

CREATE TABLE organization_agent_submissions (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    kind TEXT NOT NULL,
    definition_id UUID NOT NULL,
    base_version_id UUID,
    display_name TEXT,
    icon_media_type TEXT,
    icon_data BYTEA,
    canonical_manifest JSONB NOT NULL,
    bundle JSONB NOT NULL,
    manifest_digest BYTEA NOT NULL,
    bundle_digest BYTEA NOT NULL,
    content_digest BYTEA NOT NULL,
    submitted_by_user_id UUID NOT NULL,
    status TEXT NOT NULL,
    revision BIGINT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT organization_agent_submissions_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    CONSTRAINT organization_agent_submissions_base_version_fk
        FOREIGN KEY (base_version_id) REFERENCES agent_versions(id) ON DELETE RESTRICT,
    CONSTRAINT organization_agent_submissions_submitted_by_user_fk
        FOREIGN KEY (submitted_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT organization_agent_submissions_kind_value_check CHECK (kind IN ('initial', 'next')),
    CONSTRAINT organization_agent_submissions_display_name_check CHECK (
        display_name IS NULL OR (
            display_name = btrim(display_name)
            AND char_length(display_name) BETWEEN 1 AND 100
            AND display_name !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT organization_agent_submissions_icon_media_type_check CHECK (
        icon_media_type IS NULL OR icon_media_type IN ('image/png', 'image/webp')
    ),
    CONSTRAINT organization_agent_submissions_icon_pair_check CHECK (
        (icon_media_type IS NULL) = (icon_data IS NULL)
    ),
    CONSTRAINT organization_agent_submissions_icon_size_check CHECK (
        icon_data IS NULL OR octet_length(icon_data) <= 524288
    ),
    CONSTRAINT organization_agent_submissions_manifest_object_check CHECK (
        jsonb_typeof(canonical_manifest) = 'object'
    ),
    CONSTRAINT organization_agent_submissions_bundle_object_check CHECK (
        jsonb_typeof(bundle) = 'object'
    ),
    CONSTRAINT organization_agent_submissions_manifest_digest_length_check CHECK (
        octet_length(manifest_digest) = 32
    ),
    CONSTRAINT organization_agent_submissions_bundle_digest_length_check CHECK (
        octet_length(bundle_digest) = 32
    ),
    CONSTRAINT organization_agent_submissions_content_digest_length_check CHECK (
        octet_length(content_digest) = 32
    ),
    CONSTRAINT organization_agent_submissions_status_check CHECK (
        status IN ('pending', 'approved', 'rejected', 'withdrawn', 'superseded')
    ),
    CONSTRAINT organization_agent_submissions_revision_check CHECK (revision > 0),
    CONSTRAINT organization_agent_submissions_kind_check CHECK (
        (kind = 'initial' AND base_version_id IS NULL AND display_name IS NOT NULL)
        OR (kind = 'next' AND base_version_id IS NOT NULL AND display_name IS NULL
            AND icon_media_type IS NULL AND icon_data IS NULL)
    ),
    CONSTRAINT organization_agent_submissions_terminal_check CHECK (
        (status = 'pending' AND terminal_at IS NULL)
        OR (status <> 'pending' AND terminal_at IS NOT NULL)
    ),
    CONSTRAINT organization_agent_submissions_time_check CHECK (
        updated_at >= submitted_at AND (terminal_at IS NULL OR terminal_at >= submitted_at)
    ),
    CONSTRAINT organization_agent_submissions_org_id_key
        UNIQUE (organization_id, id)
);

CREATE TABLE organization_agent_reviews (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    submission_id UUID NOT NULL,
    reviewer_user_id UUID NOT NULL,
    decision TEXT NOT NULL,
    reason_code TEXT,
    safe_note TEXT,
    organization_policy_snapshot_id UUID NOT NULL,
    organization_policy_version BIGINT NOT NULL,
    reviewed_content_digest BYTEA NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT organization_agent_reviews_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    CONSTRAINT organization_agent_reviews_reviewer_user_fk
        FOREIGN KEY (reviewer_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT organization_agent_reviews_submission_key UNIQUE (submission_id),
    CONSTRAINT organization_agent_reviews_submission_fk
        FOREIGN KEY (organization_id, submission_id)
        REFERENCES organization_agent_submissions(organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT organization_agent_reviews_policy_fk
        FOREIGN KEY (organization_id, organization_policy_snapshot_id)
        REFERENCES organization_policy_snapshots(organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT organization_agent_reviews_decision_check CHECK (decision IN ('approve', 'reject')),
    CONSTRAINT organization_agent_reviews_policy_version_check CHECK (organization_policy_version > 0),
    CONSTRAINT organization_agent_reviews_content_digest_length_check CHECK (
        octet_length(reviewed_content_digest) = 32
    ),
    CONSTRAINT organization_agent_reviews_reason_check CHECK (
        (decision = 'approve' AND reason_code IS NULL AND safe_note IS NULL)
        OR (decision = 'reject'
            AND reason_code = btrim(reason_code)
            AND char_length(reason_code) BETWEEN 1 AND 64
            AND reason_code !~ '[[:cntrl:]]'
            AND (safe_note IS NULL OR (
                safe_note = btrim(safe_note)
                AND char_length(safe_note) BETWEEN 1 AND 500
                AND safe_note !~ '[[:cntrl:]]'
            )))
    )
);

ALTER TABLE agent_versions
    ADD CONSTRAINT agent_versions_organization_submission_fk
    FOREIGN KEY (organization_id, organization_submission_id)
    REFERENCES organization_agent_submissions(organization_id, id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX agent_control_idempotency_organization_operation_key
    ON agent_control_idempotency_keys (organization_id, operation, key_hash)
    WHERE owner_scope = 'ORGANIZATION';

CREATE INDEX agent_definitions_organization_list_idx
    ON agent_definitions (organization_id, updated_at DESC)
    WHERE owner_scope = 'ORGANIZATION';

CREATE INDEX agent_versions_organization_time_idx
    ON agent_versions (organization_id, published_at DESC)
    WHERE owner_scope = 'ORGANIZATION';

CREATE INDEX organization_agent_submissions_queue_idx
    ON organization_agent_submissions (organization_id, status, submitted_at DESC, id DESC);

CREATE FUNCTION enforce_organization_agent_submission_variant()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.kind = 'initial' THEN
        IF EXISTS (
            SELECT 1 FROM agent_definitions WHERE id = NEW.definition_id
        ) THEN
            RAISE EXCEPTION 'reserved Organization Agent Definition already exists'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NOT EXISTS (
            SELECT 1
            FROM agent_definitions definition
            JOIN agent_versions version ON version.id = NEW.base_version_id
            WHERE definition.id = NEW.definition_id
              AND definition.owner_scope = 'ORGANIZATION'
              AND definition.organization_id = NEW.organization_id
              AND definition.latest_version_id = NEW.base_version_id
              AND version.definition_id = definition.id
              AND version.owner_scope = 'ORGANIZATION'
              AND version.organization_id = NEW.organization_id
        ) THEN
            RAISE EXCEPTION 'next Organization Agent submission base is invalid'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER organization_agent_submission_variant_trigger
    AFTER INSERT ON organization_agent_submissions
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_agent_submission_variant();

CREATE FUNCTION guard_organization_agent_submission_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Organization Agent submission cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.status <> 'pending'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.definition_id IS DISTINCT FROM OLD.definition_id
       OR NEW.base_version_id IS DISTINCT FROM OLD.base_version_id
       OR NEW.display_name IS DISTINCT FROM OLD.display_name
       OR NEW.icon_media_type IS DISTINCT FROM OLD.icon_media_type
       OR NEW.icon_data IS DISTINCT FROM OLD.icon_data
       OR NEW.canonical_manifest IS DISTINCT FROM OLD.canonical_manifest
       OR NEW.bundle IS DISTINCT FROM OLD.bundle
       OR NEW.manifest_digest IS DISTINCT FROM OLD.manifest_digest
       OR NEW.bundle_digest IS DISTINCT FROM OLD.bundle_digest
       OR NEW.content_digest IS DISTINCT FROM OLD.content_digest
       OR NEW.submitted_by_user_id IS DISTINCT FROM OLD.submitted_by_user_id
       OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
       OR NEW.status NOT IN ('approved', 'rejected', 'withdrawn', 'superseded')
       OR NEW.revision <> OLD.revision + 1
       OR NEW.terminal_at IS NULL
       OR NEW.updated_at <> NEW.terminal_at THEN
        RAISE EXCEPTION 'Organization Agent submission mutation is invalid'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_agent_submission_immutable_trigger
    BEFORE UPDATE OR DELETE ON organization_agent_submissions
    FOR EACH ROW EXECUTE FUNCTION guard_organization_agent_submission_mutation();

CREATE FUNCTION guard_organization_agent_review_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Organization Agent review is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER organization_agent_review_immutable_trigger
    BEFORE UPDATE OR DELETE ON organization_agent_reviews
    FOR EACH ROW EXECUTE FUNCTION guard_organization_agent_review_mutation();

CREATE FUNCTION enforce_organization_agent_review_separation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    submitter UUID;
BEGIN
    SELECT submitted_by_user_id INTO submitter
    FROM organization_agent_submissions
    WHERE id = NEW.submission_id AND organization_id = NEW.organization_id;

    IF submitter IS NULL OR submitter = NEW.reviewer_user_id THEN
        RAISE EXCEPTION 'Organization Agent review requires another actor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER organization_agent_review_separation_trigger
    AFTER INSERT ON organization_agent_reviews
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION enforce_organization_agent_review_separation();
