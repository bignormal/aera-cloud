CREATE TABLE platforms (
    id UUID PRIMARY KEY,
    platform_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT platforms_platform_key_key UNIQUE (platform_key),
    CONSTRAINT platforms_platform_key_check CHECK (
        platform_key ~ '^[a-z][a-z0-9_-]{2,63}$'
    ),
    CONSTRAINT platforms_display_name_check CHECK (
        display_name = btrim(display_name)
        AND char_length(display_name) BETWEEN 1 AND 100
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT platforms_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT platforms_time_check CHECK (updated_at >= created_at)
);

ALTER TABLE agent_definitions
    ADD COLUMN platform_id UUID,
    ADD COLUMN created_by_admin_id UUID,
    ALTER COLUMN created_by DROP NOT NULL,
    DROP CONSTRAINT agent_definitions_owner_variant_check,
    ADD CONSTRAINT agent_definitions_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_definitions_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL
            AND workspace_id IS NULL AND organization_id IS NULL AND platform_id IS NULL)
        OR (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NOT NULL AND organization_id IS NULL AND platform_id IS NULL)
        OR (owner_scope = 'ORGANIZATION' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NOT NULL AND platform_id IS NULL)
        OR (owner_scope = 'PLATFORM' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NULL AND platform_id IS NOT NULL)
    ),
    ADD CONSTRAINT agent_definitions_creator_variant_check CHECK (
        (owner_scope = 'PLATFORM' AND created_by IS NULL AND created_by_admin_id IS NOT NULL)
        OR (owner_scope <> 'PLATFORM' AND created_by IS NOT NULL AND created_by_admin_id IS NULL)
    ),
    ADD CONSTRAINT agent_definitions_platform_id_id_key UNIQUE (platform_id, id);

CREATE TABLE platform_agent_drafts (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    definition_id UUID NOT NULL,
    base_version_id UUID REFERENCES agent_versions(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    icon_media_type TEXT,
    icon_data BYTEA,
    canonical_manifest JSONB NOT NULL,
    bundle JSONB NOT NULL,
    manifest_digest BYTEA NOT NULL,
    bundle_digest BYTEA NOT NULL,
    content_digest BYTEA NOT NULL,
    revision BIGINT NOT NULL,
    status TEXT NOT NULL,
    last_editor_admin_id UUID NOT NULL,
    last_editor_role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT platform_agent_drafts_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_drafts_definition_fk
        FOREIGN KEY (platform_id, definition_id)
        REFERENCES agent_definitions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_drafts_kind_check CHECK (kind IN ('initial', 'next')),
    CONSTRAINT platform_agent_drafts_variant_check CHECK (
        (kind = 'initial' AND base_version_id IS NULL)
        OR (kind = 'next' AND base_version_id IS NOT NULL)
    ),
    CONSTRAINT platform_agent_drafts_display_name_check CHECK (
        display_name = btrim(display_name)
        AND char_length(display_name) BETWEEN 1 AND 100
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT platform_agent_drafts_icon_media_type_check CHECK (
        icon_media_type IS NULL OR icon_media_type IN ('image/png', 'image/webp')
    ),
    CONSTRAINT platform_agent_drafts_icon_pair_check CHECK (
        (icon_media_type IS NULL) = (icon_data IS NULL)
    ),
    CONSTRAINT platform_agent_drafts_icon_size_check CHECK (
        icon_data IS NULL OR octet_length(icon_data) <= 524288
    ),
    CONSTRAINT platform_agent_drafts_manifest_object_check CHECK (
        jsonb_typeof(canonical_manifest) = 'object'
    ),
    CONSTRAINT platform_agent_drafts_bundle_object_check CHECK (
        jsonb_typeof(bundle) = 'object'
    ),
    CONSTRAINT platform_agent_drafts_manifest_digest_length_check CHECK (
        octet_length(manifest_digest) = 32
    ),
    CONSTRAINT platform_agent_drafts_bundle_digest_length_check CHECK (
        octet_length(bundle_digest) = 32
    ),
    CONSTRAINT platform_agent_drafts_content_digest_length_check CHECK (
        octet_length(content_digest) = 32
    ),
    CONSTRAINT platform_agent_drafts_revision_check CHECK (revision > 0),
    CONSTRAINT platform_agent_drafts_status_check CHECK (status IN ('active', 'archived')),
    CONSTRAINT platform_agent_drafts_editor_role_check CHECK (last_editor_role = 'developer'),
    CONSTRAINT platform_agent_drafts_time_check CHECK (updated_at >= created_at),
    CONSTRAINT platform_agent_drafts_platform_id_id_key UNIQUE (platform_id, id),
    CONSTRAINT platform_agent_drafts_platform_definition_key UNIQUE (platform_id, definition_id)
);

CREATE TABLE platform_agent_policy_snapshots (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    version BIGINT NOT NULL,
    canonical_policy JSONB NOT NULL,
    policy_digest BYTEA NOT NULL,
    signature_key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT platform_agent_policy_snapshots_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_policy_snapshots_version_check CHECK (version > 0),
    CONSTRAINT platform_agent_policy_snapshots_document_check CHECK (
        jsonb_typeof(canonical_policy) = 'object'
    ),
    CONSTRAINT platform_agent_policy_snapshots_digest_length_check CHECK (
        octet_length(policy_digest) = 32
    ),
    CONSTRAINT platform_agent_policy_snapshots_key_id_check CHECK (
        char_length(signature_key_id) BETWEEN 1 AND 128
    ),
    CONSTRAINT platform_agent_policy_snapshots_signature_length_check CHECK (
        octet_length(signature) = 64
    ),
    CONSTRAINT platform_agent_policy_snapshots_platform_version_key UNIQUE (platform_id, version),
    CONSTRAINT platform_agent_policy_snapshots_platform_id_id_key UNIQUE (platform_id, id),
    CONSTRAINT platform_agent_policy_snapshots_platform_id_id_version_key UNIQUE (platform_id, id, version)
);

CREATE TABLE platform_agent_submissions (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    draft_id UUID NOT NULL,
    draft_revision BIGINT NOT NULL,
    definition_id UUID NOT NULL,
    base_version_id UUID REFERENCES agent_versions(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    icon_media_type TEXT,
    icon_data BYTEA,
    canonical_manifest JSONB NOT NULL,
    bundle JSONB NOT NULL,
    manifest_digest BYTEA NOT NULL,
    bundle_digest BYTEA NOT NULL,
    content_digest BYTEA NOT NULL,
    submitted_by_admin_id UUID NOT NULL,
    submitted_by_role TEXT NOT NULL,
    status TEXT NOT NULL,
    revision BIGINT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT platform_agent_submissions_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_submissions_draft_fk
        FOREIGN KEY (platform_id, draft_id)
        REFERENCES platform_agent_drafts(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_submissions_definition_fk
        FOREIGN KEY (platform_id, definition_id)
        REFERENCES agent_definitions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_submissions_kind_check CHECK (kind IN ('initial', 'next')),
    CONSTRAINT platform_agent_submissions_variant_check CHECK (
        (kind = 'initial' AND base_version_id IS NULL)
        OR (kind = 'next' AND base_version_id IS NOT NULL)
    ),
    CONSTRAINT platform_agent_submissions_display_name_check CHECK (
        display_name = btrim(display_name)
        AND char_length(display_name) BETWEEN 1 AND 100
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT platform_agent_submissions_icon_media_type_check CHECK (
        icon_media_type IS NULL OR icon_media_type IN ('image/png', 'image/webp')
    ),
    CONSTRAINT platform_agent_submissions_icon_pair_check CHECK (
        (icon_media_type IS NULL) = (icon_data IS NULL)
    ),
    CONSTRAINT platform_agent_submissions_icon_size_check CHECK (
        icon_data IS NULL OR octet_length(icon_data) <= 524288
    ),
    CONSTRAINT platform_agent_submissions_manifest_object_check CHECK (
        jsonb_typeof(canonical_manifest) = 'object'
    ),
    CONSTRAINT platform_agent_submissions_bundle_object_check CHECK (
        jsonb_typeof(bundle) = 'object'
    ),
    CONSTRAINT platform_agent_submissions_manifest_digest_length_check CHECK (
        octet_length(manifest_digest) = 32
    ),
    CONSTRAINT platform_agent_submissions_bundle_digest_length_check CHECK (
        octet_length(bundle_digest) = 32
    ),
    CONSTRAINT platform_agent_submissions_content_digest_length_check CHECK (
        octet_length(content_digest) = 32
    ),
    CONSTRAINT platform_agent_submissions_draft_revision_check CHECK (draft_revision > 0),
    CONSTRAINT platform_agent_submissions_submitter_role_check CHECK (submitted_by_role = 'developer'),
    CONSTRAINT platform_agent_submissions_status_check CHECK (
        status IN ('pending', 'approved', 'rejected', 'withdrawn', 'superseded')
    ),
    CONSTRAINT platform_agent_submissions_revision_check CHECK (revision > 0),
    CONSTRAINT platform_agent_submissions_terminal_check CHECK (
        (status = 'pending' AND terminal_at IS NULL)
        OR (status <> 'pending' AND terminal_at IS NOT NULL)
    ),
    CONSTRAINT platform_agent_submissions_time_check CHECK (
        updated_at >= submitted_at AND (terminal_at IS NULL OR terminal_at >= submitted_at)
    ),
    CONSTRAINT platform_agent_submissions_platform_id_id_key UNIQUE (platform_id, id)
);

CREATE TABLE platform_agent_reviews (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    submission_id UUID NOT NULL,
    reviewer_admin_id UUID NOT NULL,
    reviewer_role TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    safe_note TEXT,
    reviewed_content_digest BYTEA NOT NULL,
    platform_policy_snapshot_id UUID NOT NULL,
    platform_policy_version BIGINT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT platform_agent_reviews_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_reviews_submission_key UNIQUE (submission_id),
    CONSTRAINT platform_agent_reviews_submission_fk
        FOREIGN KEY (platform_id, submission_id)
        REFERENCES platform_agent_submissions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_reviews_policy_fk
        FOREIGN KEY (platform_id, platform_policy_snapshot_id, platform_policy_version)
        REFERENCES platform_agent_policy_snapshots(platform_id, id, version) ON DELETE RESTRICT,
    CONSTRAINT platform_agent_reviews_reviewer_role_check CHECK (reviewer_role = 'super_admin'),
    CONSTRAINT platform_agent_reviews_decision_check CHECK (decision IN ('approve', 'reject')),
    CONSTRAINT platform_agent_reviews_reason_code_check CHECK (
        reason_code ~ '^[a-z][a-z0-9_]{2,63}$'
    ),
    CONSTRAINT platform_agent_reviews_safe_note_check CHECK (
        safe_note IS NULL OR (
            safe_note = btrim(safe_note)
            AND char_length(safe_note) BETWEEN 1 AND 500
            AND safe_note !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT platform_agent_reviews_content_digest_length_check CHECK (
        octet_length(reviewed_content_digest) = 32
    ),
    CONSTRAINT platform_agent_reviews_policy_version_check CHECK (platform_policy_version > 0)
);

ALTER TABLE agent_versions
    ADD COLUMN platform_id UUID,
    ADD COLUMN platform_submission_id UUID,
    ADD COLUMN platform_policy_snapshot_id UUID,
    ADD COLUMN published_by_admin_id UUID,
    ALTER COLUMN published_by DROP NOT NULL,
    DROP CONSTRAINT agent_versions_owner_variant_check,
    ADD CONSTRAINT agent_versions_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_versions_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL
            AND workspace_id IS NULL AND organization_id IS NULL AND platform_id IS NULL
            AND organization_submission_id IS NULL AND organization_policy_snapshot_id IS NULL
            AND platform_submission_id IS NULL AND platform_policy_snapshot_id IS NULL)
        OR (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NOT NULL AND organization_id IS NULL AND platform_id IS NULL
            AND organization_submission_id IS NULL AND organization_policy_snapshot_id IS NULL
            AND platform_submission_id IS NULL AND platform_policy_snapshot_id IS NULL)
        OR (owner_scope = 'ORGANIZATION' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NOT NULL AND platform_id IS NULL
            AND organization_submission_id IS NOT NULL AND organization_policy_snapshot_id IS NOT NULL
            AND platform_submission_id IS NULL AND platform_policy_snapshot_id IS NULL)
        OR (owner_scope = 'PLATFORM' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NULL AND platform_id IS NOT NULL
            AND organization_submission_id IS NULL AND organization_policy_snapshot_id IS NULL
            AND platform_submission_id IS NOT NULL AND platform_policy_snapshot_id IS NOT NULL)
    ),
    ADD CONSTRAINT agent_versions_publisher_variant_check CHECK (
        (owner_scope = 'PLATFORM' AND published_by IS NULL AND published_by_admin_id IS NOT NULL)
        OR (owner_scope <> 'PLATFORM' AND published_by IS NOT NULL AND published_by_admin_id IS NULL)
    ),
    ADD CONSTRAINT agent_versions_platform_definition_fk
        FOREIGN KEY (platform_id, definition_id)
        REFERENCES agent_definitions(platform_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_versions_platform_submission_fk
        FOREIGN KEY (platform_id, platform_submission_id)
        REFERENCES platform_agent_submissions(platform_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_versions_platform_policy_fk
        FOREIGN KEY (platform_id, platform_policy_snapshot_id)
        REFERENCES platform_agent_policy_snapshots(platform_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_versions_platform_id_id_key UNIQUE (platform_id, id);

ALTER TABLE agent_control_idempotency_keys
    ADD COLUMN platform_id UUID,
    DROP CONSTRAINT agent_control_idempotency_owner_variant_check,
    ADD CONSTRAINT agent_control_idempotency_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    ADD CONSTRAINT agent_control_idempotency_owner_variant_check CHECK (
        (owner_scope = 'USER' AND tenant_id IS NOT NULL AND owner_id IS NOT NULL
            AND workspace_id IS NULL AND organization_id IS NULL AND platform_id IS NULL)
        OR (owner_scope = 'WORKSPACE' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NOT NULL AND organization_id IS NULL AND platform_id IS NULL)
        OR (owner_scope = 'ORGANIZATION' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NOT NULL AND platform_id IS NULL)
        OR (owner_scope = 'PLATFORM' AND tenant_id IS NULL AND owner_id IS NULL
            AND workspace_id IS NULL AND organization_id IS NULL AND platform_id IS NOT NULL)
    );

CREATE UNIQUE INDEX agent_control_idempotency_platform_operation_key
    ON agent_control_idempotency_keys (platform_id, operation, key_hash)
    WHERE owner_scope = 'PLATFORM';

CREATE INDEX agent_definitions_platform_list_idx
    ON agent_definitions (platform_id, updated_at DESC)
    WHERE owner_scope = 'PLATFORM';

CREATE INDEX agent_versions_platform_time_idx
    ON agent_versions (platform_id, published_at DESC)
    WHERE owner_scope = 'PLATFORM';

CREATE TABLE official_releases (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    definition_id UUID NOT NULL,
    channel TEXT NOT NULL,
    current_release_revision_id UUID NOT NULL,
    head_revision BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_releases_platform_fk
        FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE RESTRICT,
    CONSTRAINT official_releases_definition_fk
        FOREIGN KEY (platform_id, definition_id)
        REFERENCES agent_definitions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_releases_channel_check CHECK (channel IN ('internal', 'stable')),
    CONSTRAINT official_releases_head_revision_check CHECK (head_revision > 0),
    CONSTRAINT official_releases_time_check CHECK (updated_at >= created_at),
    CONSTRAINT official_releases_platform_definition_channel_key
        UNIQUE (platform_id, definition_id, channel)
);

CREATE TABLE official_release_revisions (
    id UUID PRIMARY KEY,
    release_id UUID NOT NULL,
    revision_number BIGINT NOT NULL,
    agent_version_id UUID NOT NULL,
    state TEXT NOT NULL,
    rollout_basis_points INTEGER NOT NULL,
    minimum_desktop_version TEXT NOT NULL,
    bucket_algorithm_version TEXT NOT NULL,
    rollout_key_id TEXT NOT NULL,
    action TEXT NOT NULL,
    previous_revision_id UUID,
    rollback_target_revision_id UUID,
    actor_admin_id UUID NOT NULL,
    actor_admin_role TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    ticket_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_release_revisions_release_fk
        FOREIGN KEY (release_id) REFERENCES official_releases(id) ON DELETE RESTRICT,
    CONSTRAINT official_release_revisions_version_fk
        FOREIGN KEY (agent_version_id) REFERENCES agent_versions(id) ON DELETE RESTRICT,
    CONSTRAINT official_release_revisions_revision_check CHECK (revision_number > 0),
    CONSTRAINT official_release_revisions_state_check CHECK (state IN ('active', 'paused')),
    CONSTRAINT official_release_revisions_rollout_check CHECK (
        rollout_basis_points BETWEEN 0 AND 10000
    ),
    CONSTRAINT official_release_revisions_minimum_version_check CHECK (
        char_length(minimum_desktop_version) BETWEEN 1 AND 128
    ),
    CONSTRAINT official_release_revisions_algorithm_check CHECK (bucket_algorithm_version = '1'),
    CONSTRAINT official_release_revisions_key_id_check CHECK (
        char_length(rollout_key_id) BETWEEN 1 AND 64
    ),
    CONSTRAINT official_release_revisions_action_check CHECK (
        action IN ('initial', 'activate', 'rollout_update', 'pause', 'resume', 'rollback')
    ),
    CONSTRAINT official_release_revisions_actor_role_check CHECK (
        actor_admin_role IN ('super_admin', 'developer', 'operator', 'support', 'finance', 'auditor')
    ),
    CONSTRAINT official_release_revisions_reason_code_check CHECK (
        reason_code ~ '^[a-z][a-z0-9_]{2,63}$'
    ),
    CONSTRAINT official_release_revisions_ticket_check CHECK (
        ticket_reference IS NULL OR char_length(ticket_reference) BETWEEN 1 AND 128
    ),
    CONSTRAINT official_release_revisions_transition_check CHECK (
        (action = 'initial' AND revision_number = 1 AND state = 'paused'
            AND rollout_basis_points = 0 AND previous_revision_id IS NULL
            AND rollback_target_revision_id IS NULL)
        OR (action <> 'initial' AND revision_number > 1 AND previous_revision_id IS NOT NULL)
    ),
    CONSTRAINT official_release_revisions_rollback_check CHECK (
        (action = 'rollback') = (rollback_target_revision_id IS NOT NULL)
    ),
    CONSTRAINT official_release_revisions_pause_state_check CHECK (
        action <> 'pause' OR state = 'paused'
    ),
    CONSTRAINT official_release_revisions_resume_state_check CHECK (
        action <> 'resume' OR state = 'active'
    ),
    CONSTRAINT official_release_revisions_release_revision_key UNIQUE (release_id, revision_number),
    CONSTRAINT official_release_revisions_release_id_id_key UNIQUE (release_id, id),
    CONSTRAINT official_release_revisions_release_id_id_revision_key
        UNIQUE (release_id, id, revision_number),
    CONSTRAINT official_release_revisions_release_id_id_version_key
        UNIQUE (release_id, id, agent_version_id),
    CONSTRAINT official_release_revisions_previous_fk
        FOREIGN KEY (release_id, previous_revision_id)
        REFERENCES official_release_revisions(release_id, id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT official_release_revisions_rollback_target_fk
        FOREIGN KEY (release_id, rollback_target_revision_id)
        REFERENCES official_release_revisions(release_id, id)
        DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE official_releases
    ADD CONSTRAINT official_releases_current_revision_fk
    FOREIGN KEY (id, current_release_revision_id, head_revision)
    REFERENCES official_release_revisions(release_id, id, revision_number)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE official_release_audience_accounts (
    release_revision_id UUID NOT NULL,
    user_id UUID NOT NULL,
    CONSTRAINT official_release_audience_accounts_pkey
        PRIMARY KEY (release_revision_id, user_id),
    CONSTRAINT official_release_audience_revision_fk
        FOREIGN KEY (release_revision_id)
        REFERENCES official_release_revisions(id) ON DELETE RESTRICT,
    CONSTRAINT official_release_audience_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX official_release_revisions_release_created_idx
    ON official_release_revisions (release_id, revision_number DESC, created_at DESC);

CREATE INDEX official_release_audience_user_idx
    ON official_release_audience_accounts (user_id, release_revision_id);

ALTER TABLE installations
    ADD COLUMN official_release_id UUID,
    ADD COLUMN selected_release_revision_id UUID,
    DROP CONSTRAINT installations_update_policy_check,
    ADD CONSTRAINT installations_official_release_fk
        FOREIGN KEY (official_release_id) REFERENCES official_releases(id) ON DELETE RESTRICT,
    ADD CONSTRAINT installations_update_policy_check CHECK (
        update_policy IN ('manual', 'managed')
    ),
    ADD CONSTRAINT installations_official_source_check CHECK (
        (update_policy = 'manual'
            AND official_release_id IS NULL
            AND selected_release_revision_id IS NULL)
        OR (update_policy = 'managed'
            AND official_release_id IS NOT NULL
            AND selected_release_revision_id IS NOT NULL)
    ),
    ADD CONSTRAINT installations_official_selection_fk
        FOREIGN KEY (official_release_id, selected_release_revision_id, selected_version_id)
        REFERENCES official_release_revisions(release_id, id, agent_version_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE runtime_binding_records
    ADD COLUMN official_release_revision_id UUID,
    ADD CONSTRAINT runtime_binding_records_official_revision_fk
        FOREIGN KEY (official_release_revision_id)
        REFERENCES official_release_revisions(id) ON DELETE RESTRICT;

ALTER TABLE admin_operations
    ADD COLUMN actor_admin_role TEXT,
    DROP CONSTRAINT admin_operations_action_check,
    DROP CONSTRAINT admin_operations_target_type_check,
    DROP CONSTRAINT admin_operations_action_target_check,
    DROP CONSTRAINT admin_operations_approval_check,
    ADD CONSTRAINT admin_operations_action_check CHECK (action IN (
        'revoke_device', 'revoke_session', 'disable_user', 'enable_user',
        'official_definition_reserve', 'official_draft_create', 'official_draft_update',
        'official_draft_submit', 'official_submission_withdraw', 'official_submission_review',
        'official_release_activate', 'official_release_rollout', 'official_release_pause',
        'official_release_resume', 'official_release_rollback'
    )),
    ADD CONSTRAINT admin_operations_target_type_check CHECK (target_type IN (
        'device', 'session', 'user', 'platform_definition', 'platform_draft',
        'platform_submission', 'official_release'
    )),
    ADD CONSTRAINT admin_operations_actor_role_check CHECK (
        actor_admin_role IS NULL OR actor_admin_role IN (
            'super_admin', 'developer', 'operator', 'support', 'finance', 'auditor'
        )
    ),
    ADD CONSTRAINT admin_operations_official_actor_check CHECK (
        action NOT LIKE 'official_%' OR actor_admin_role IS NOT NULL
    ),
    ADD CONSTRAINT admin_operations_action_target_check CHECK (
        (action = 'revoke_device' AND target_type = 'device')
        OR (action = 'revoke_session' AND target_type = 'session')
        OR (action IN ('disable_user', 'enable_user') AND target_type = 'user')
        OR (action = 'official_definition_reserve' AND target_type = 'platform_definition')
        OR (action IN ('official_draft_create', 'official_draft_update')
            AND target_type = 'platform_draft')
        OR (action IN (
                'official_draft_submit', 'official_submission_withdraw',
                'official_submission_review'
            ) AND target_type = 'platform_submission')
        OR (action IN (
                'official_release_activate', 'official_release_rollout',
                'official_release_pause', 'official_release_resume',
                'official_release_rollback'
            ) AND target_type = 'official_release')
    ),
    ADD CONSTRAINT admin_operations_approval_check CHECK (
        (action IN ('disable_user', 'enable_user', 'official_release_rollback')
            AND approval_id IS NOT NULL)
        OR action NOT IN ('disable_user', 'enable_user', 'official_release_rollback')
    );

CREATE FUNCTION guard_platform_agent_submission_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Platform Agent submission cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.status <> 'pending'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.platform_id IS DISTINCT FROM OLD.platform_id
       OR NEW.draft_id IS DISTINCT FROM OLD.draft_id
       OR NEW.draft_revision IS DISTINCT FROM OLD.draft_revision
       OR NEW.definition_id IS DISTINCT FROM OLD.definition_id
       OR NEW.base_version_id IS DISTINCT FROM OLD.base_version_id
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.display_name IS DISTINCT FROM OLD.display_name
       OR NEW.icon_media_type IS DISTINCT FROM OLD.icon_media_type
       OR NEW.icon_data IS DISTINCT FROM OLD.icon_data
       OR NEW.canonical_manifest IS DISTINCT FROM OLD.canonical_manifest
       OR NEW.bundle IS DISTINCT FROM OLD.bundle
       OR NEW.manifest_digest IS DISTINCT FROM OLD.manifest_digest
       OR NEW.bundle_digest IS DISTINCT FROM OLD.bundle_digest
       OR NEW.content_digest IS DISTINCT FROM OLD.content_digest
       OR NEW.submitted_by_admin_id IS DISTINCT FROM OLD.submitted_by_admin_id
       OR NEW.submitted_by_role IS DISTINCT FROM OLD.submitted_by_role
       OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
       OR NEW.status NOT IN ('approved', 'rejected', 'withdrawn', 'superseded')
       OR NEW.revision <> OLD.revision + 1
       OR NEW.terminal_at IS NULL
       OR NEW.updated_at <> NEW.terminal_at THEN
        RAISE EXCEPTION 'Platform Agent submission mutation is invalid'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_agent_submission_immutable_trigger
    BEFORE UPDATE OR DELETE ON platform_agent_submissions
    FOR EACH ROW EXECUTE FUNCTION guard_platform_agent_submission_mutation();

CREATE FUNCTION reject_platform_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Platform Agent control-plane row is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER platform_agent_policy_snapshot_immutable_trigger
    BEFORE UPDATE OR DELETE ON platform_agent_policy_snapshots
    FOR EACH ROW EXECUTE FUNCTION reject_platform_immutable_mutation();

CREATE TRIGGER platform_agent_review_immutable_trigger
    BEFORE UPDATE OR DELETE ON platform_agent_reviews
    FOR EACH ROW EXECUTE FUNCTION reject_platform_immutable_mutation();

CREATE TRIGGER official_release_revision_immutable_trigger
    BEFORE UPDATE OR DELETE ON official_release_revisions
    FOR EACH ROW EXECUTE FUNCTION reject_platform_immutable_mutation();

CREATE TRIGGER official_release_audience_immutable_trigger
    BEFORE UPDATE OR DELETE ON official_release_audience_accounts
    FOR EACH ROW EXECUTE FUNCTION reject_platform_immutable_mutation();

CREATE FUNCTION enforce_platform_agent_review_separation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    submitter UUID;
BEGIN
    SELECT submitted_by_admin_id INTO submitter
    FROM platform_agent_submissions
    WHERE id = NEW.submission_id AND platform_id = NEW.platform_id;

    IF submitter IS NULL OR submitter = NEW.reviewer_admin_id THEN
        RAISE EXCEPTION 'Platform Agent review requires another actor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER platform_agent_review_separation_trigger
    AFTER INSERT ON platform_agent_reviews
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION enforce_platform_agent_review_separation();

CREATE FUNCTION enforce_official_release_revision_source()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    release_platform_id UUID;
    release_definition_id UUID;
    version_platform_id UUID;
    version_definition_id UUID;
    version_owner_scope TEXT;
BEGIN
    SELECT release.platform_id, release.definition_id,
           version.platform_id, version.definition_id, version.owner_scope
    INTO release_platform_id, release_definition_id,
         version_platform_id, version_definition_id, version_owner_scope
    FROM official_releases release
    JOIN agent_versions version ON version.id = NEW.agent_version_id
    WHERE release.id = NEW.release_id;

    IF NOT FOUND
       OR version_owner_scope <> 'PLATFORM'
       OR version_platform_id IS DISTINCT FROM release_platform_id
       OR version_definition_id IS DISTINCT FROM release_definition_id THEN
        RAISE EXCEPTION 'Official release revision source is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER official_release_revision_source_constraint_trigger
    AFTER INSERT ON official_release_revisions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_official_release_revision_source();

CREATE FUNCTION enforce_installation_official_source()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    definition_owner_scope TEXT;
    version_owner_scope TEXT;
    release_definition_id UUID;
    revision_version_id UUID;
BEGIN
    IF NEW.update_policy <> 'managed' THEN
        RETURN NEW;
    END IF;

    SELECT definition.owner_scope, version.owner_scope,
           release.definition_id, revision.agent_version_id
    INTO definition_owner_scope, version_owner_scope,
         release_definition_id, revision_version_id
    FROM agent_definitions definition
    JOIN agent_versions version ON version.id = NEW.selected_version_id
    JOIN official_releases release ON release.id = NEW.official_release_id
    JOIN official_release_revisions revision
      ON revision.id = NEW.selected_release_revision_id
     AND revision.release_id = release.id
    WHERE definition.id = NEW.definition_id;

    IF NOT FOUND
       OR definition_owner_scope <> 'PLATFORM'
       OR version_owner_scope <> 'PLATFORM'
       OR release_definition_id IS DISTINCT FROM NEW.definition_id
       OR revision_version_id IS DISTINCT FROM NEW.selected_version_id THEN
        RAISE EXCEPTION 'Official Installation source is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER installations_official_source_constraint_trigger
    AFTER INSERT OR UPDATE ON installations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_installation_official_source();

CREATE FUNCTION enforce_runtime_binding_official_source()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    installation_policy TEXT;
    installation_version_id UUID;
    installation_release_revision_id UUID;
BEGIN
    SELECT update_policy, selected_version_id, selected_release_revision_id
    INTO installation_policy, installation_version_id, installation_release_revision_id
    FROM installations
    WHERE id = NEW.agent_installation_id;

    IF NOT FOUND
       OR installation_version_id IS DISTINCT FROM NEW.agent_version_id
       OR (installation_policy = 'managed'
           AND NEW.official_release_revision_id IS DISTINCT FROM installation_release_revision_id)
       OR (installation_policy <> 'managed' AND NEW.official_release_revision_id IS NOT NULL) THEN
        RAISE EXCEPTION 'RuntimeBinding official source is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER runtime_binding_official_source_constraint_trigger
    AFTER INSERT OR UPDATE ON runtime_binding_records
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_runtime_binding_official_source();
