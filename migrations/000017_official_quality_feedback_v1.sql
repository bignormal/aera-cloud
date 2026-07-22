ALTER TABLE official_releases
    ADD CONSTRAINT official_releases_id_platform_definition_key
    UNIQUE (id, platform_id, definition_id);

CREATE TABLE official_quality_consent_receipts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    purpose TEXT NOT NULL,
    consent_version BIGINT NOT NULL,
    state TEXT NOT NULL,
    revision BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_quality_consent_receipts_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_consent_receipts_purpose_check CHECK (
        purpose IN ('official_quality_metrics', 'official_explicit_feedback')
    ),
    CONSTRAINT official_quality_consent_receipts_version_check CHECK (
        consent_version > 0
    ),
    CONSTRAINT official_quality_consent_receipts_state_check CHECK (
        state IN ('granted', 'revoked')
    ),
    CONSTRAINT official_quality_consent_receipts_revision_check CHECK (
        revision > 0
    ),
    CONSTRAINT official_quality_consent_receipts_user_purpose_revision_key
        UNIQUE (user_id, purpose, revision)
);

CREATE INDEX official_quality_consent_current_idx
    ON official_quality_consent_receipts (user_id, purpose, revision DESC);

CREATE TABLE official_quality_purge_requests (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    purpose TEXT NOT NULL,
    state TEXT NOT NULL,
    window_start_day DATE NOT NULL,
    window_end_day DATE NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT official_quality_purge_requests_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_purge_requests_purpose_check CHECK (
        purpose IN ('official_quality_metrics', 'official_explicit_feedback')
    ),
    CONSTRAINT official_quality_purge_requests_state_check CHECK (
        state IN ('pending', 'running', 'completed')
    ),
    CONSTRAINT official_quality_purge_requests_window_check CHECK (
        window_end_day >= window_start_day
        AND window_end_day - window_start_day <= 31
    ),
    CONSTRAINT official_quality_purge_requests_attempt_check CHECK (
        attempt_count >= 0
    ),
    CONSTRAINT official_quality_purge_requests_time_check CHECK (
        updated_at >= created_at
        AND (completed_at IS NULL OR completed_at >= created_at)
    ),
    CONSTRAINT official_quality_purge_requests_terminal_check CHECK (
        (state = 'completed' AND completed_at IS NOT NULL)
        OR (state <> 'completed' AND completed_at IS NULL)
    )
);

CREATE UNIQUE INDEX official_quality_purge_active_key
    ON official_quality_purge_requests (user_id, purpose)
    WHERE state IN ('pending', 'running');

CREATE INDEX official_quality_purge_due_idx
    ON official_quality_purge_requests (state, next_attempt_at, created_at);

CREATE TABLE official_quality_events (
    event_id UUID PRIMARY KEY,
    protocol_version SMALLINT NOT NULL,
    consent_version BIGINT NOT NULL,
    platform_id UUID NOT NULL,
    definition_id UUID NOT NULL,
    version_id UUID NOT NULL,
    release_id UUID NOT NULL,
    release_revision_id UUID NOT NULL,
    desktop_version TEXT NOT NULL,
    runtime_version TEXT NOT NULL,
    event_day DATE NOT NULL,
    subject_pseudonym BYTEA NOT NULL,
    binding_proof_digest BYTEA NOT NULL,
    event_kind TEXT NOT NULL,
    result_code TEXT NOT NULL,
    latency_bucket TEXT NOT NULL,
    total_token_bucket TEXT NOT NULL,
    crash_code TEXT,
    feedback_rating TEXT,
    feedback_reason_codes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    device_signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_quality_events_uuid_v7_check CHECK (
        (get_byte(uuid_send(event_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(event_id), 8) >> 6) = 2
    ),
    CONSTRAINT official_quality_events_protocol_check CHECK (
        protocol_version = 1
    ),
    CONSTRAINT official_quality_events_consent_version_check CHECK (
        consent_version > 0
    ),
    CONSTRAINT official_quality_events_definition_fk
        FOREIGN KEY (platform_id, definition_id)
        REFERENCES agent_definitions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_events_version_fk
        FOREIGN KEY (platform_id, version_id)
        REFERENCES agent_versions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_events_release_fk
        FOREIGN KEY (release_id, platform_id, definition_id)
        REFERENCES official_releases(id, platform_id, definition_id)
        ON DELETE RESTRICT,
    CONSTRAINT official_quality_events_release_revision_fk
        FOREIGN KEY (release_id, release_revision_id, version_id)
        REFERENCES official_release_revisions(release_id, id, agent_version_id)
        ON DELETE RESTRICT,
    CONSTRAINT official_quality_events_desktop_version_check CHECK (
        desktop_version = btrim(desktop_version)
        AND char_length(desktop_version) BETWEEN 1 AND 128
        AND desktop_version !~ '[[:cntrl:]]'
    ),
    CONSTRAINT official_quality_events_runtime_version_check CHECK (
        runtime_version = btrim(runtime_version)
        AND char_length(runtime_version) BETWEEN 1 AND 128
        AND runtime_version !~ '[[:cntrl:]]'
    ),
    CONSTRAINT official_quality_events_subject_length_check CHECK (
        octet_length(subject_pseudonym) = 32
    ),
    CONSTRAINT official_quality_events_binding_proof_length_check CHECK (
        octet_length(binding_proof_digest) = 32
    ),
    CONSTRAINT official_quality_events_kind_check CHECK (
        event_kind IN ('metric', 'explicit_feedback')
    ),
    CONSTRAINT official_quality_events_result_check CHECK (
        result_code IN (
            'success', 'user_cancelled', 'model_error',
            'tool_error', 'runtime_crash', 'timeout'
        )
    ),
    CONSTRAINT official_quality_events_latency_check CHECK (
        latency_bucket IN (
            'lt_1s', '1s_5s', '5s_15s',
            '15s_60s', '60s_180s', 'gte_180s'
        )
    ),
    CONSTRAINT official_quality_events_token_check CHECK (
        total_token_bucket IN (
            '0', '1_1k', '1k_4k',
            '4k_16k', '16k_64k', 'gte_64k'
        )
    ),
    CONSTRAINT official_quality_events_crash_code_check CHECK (
        crash_code IS NULL OR crash_code IN (
            'gateway_unavailable', 'runtime_process_exit',
            'runtime_protocol_failure', 'unclassified_runtime_failure'
        )
    ),
    CONSTRAINT official_quality_events_crash_variant_check CHECK (
        (result_code = 'runtime_crash' AND crash_code IS NOT NULL)
        OR (result_code <> 'runtime_crash' AND crash_code IS NULL)
    ),
    CONSTRAINT official_quality_events_rating_check CHECK (
        feedback_rating IS NULL
        OR feedback_rating IN ('helpful', 'not_helpful')
    ),
    CONSTRAINT official_quality_events_reason_catalog_check CHECK (
        feedback_reason_codes <@ ARRAY[
            'incorrect', 'incomplete', 'tool_failed', 'too_slow',
            'unsafe_or_inappropriate', 'other_without_text'
        ]::TEXT[]
        AND cardinality(feedback_reason_codes) <= 6
    ),
    CONSTRAINT official_quality_events_feedback_variant_check CHECK (
        (event_kind = 'metric'
            AND feedback_rating IS NULL
            AND cardinality(feedback_reason_codes) = 0)
        OR (event_kind = 'explicit_feedback'
            AND feedback_rating IS NOT NULL)
    ),
    CONSTRAINT official_quality_events_signature_length_check CHECK (
        octet_length(device_signature) = 64
    )
);

CREATE UNIQUE INDEX official_quality_event_binding_dedupe_key
    ON official_quality_events (event_day, binding_proof_digest, event_kind);

CREATE INDEX official_quality_events_retention_idx
    ON official_quality_events (event_day, created_at);

CREATE INDEX official_quality_events_aggregate_idx
    ON official_quality_events (
        platform_id, definition_id, version_id,
        release_id, release_revision_id, event_day
    );

CREATE TABLE official_quality_daily_aggregates (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    definition_id UUID NOT NULL,
    version_id UUID NOT NULL,
    release_id UUID NOT NULL,
    release_revision_id UUID NOT NULL,
    aggregate_day DATE NOT NULL,
    event_kind TEXT NOT NULL,
    result_code TEXT NOT NULL,
    latency_bucket TEXT NOT NULL,
    total_token_bucket TEXT NOT NULL,
    crash_code TEXT,
    feedback_rating TEXT,
    feedback_reason_code TEXT,
    event_count BIGINT NOT NULL,
    distinct_subject_count BIGINT NOT NULL,
    suppression_threshold SMALLINT NOT NULL,
    is_suppressed BOOLEAN NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_quality_daily_aggregates_definition_fk
        FOREIGN KEY (platform_id, definition_id)
        REFERENCES agent_definitions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_daily_aggregates_version_fk
        FOREIGN KEY (platform_id, version_id)
        REFERENCES agent_versions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_daily_aggregates_release_fk
        FOREIGN KEY (release_id, platform_id, definition_id)
        REFERENCES official_releases(id, platform_id, definition_id)
        ON DELETE RESTRICT,
    CONSTRAINT official_quality_daily_aggregates_release_revision_fk
        FOREIGN KEY (release_id, release_revision_id, version_id)
        REFERENCES official_release_revisions(release_id, id, agent_version_id)
        ON DELETE RESTRICT,
    CONSTRAINT official_quality_daily_aggregates_kind_check CHECK (
        event_kind IN ('metric', 'explicit_feedback')
    ),
    CONSTRAINT official_quality_daily_aggregates_result_check CHECK (
        result_code IN (
            'success', 'user_cancelled', 'model_error',
            'tool_error', 'runtime_crash', 'timeout'
        )
    ),
    CONSTRAINT official_quality_daily_aggregates_latency_check CHECK (
        latency_bucket IN (
            'lt_1s', '1s_5s', '5s_15s',
            '15s_60s', '60s_180s', 'gte_180s'
        )
    ),
    CONSTRAINT official_quality_daily_aggregates_token_check CHECK (
        total_token_bucket IN (
            '0', '1_1k', '1k_4k',
            '4k_16k', '16k_64k', 'gte_64k'
        )
    ),
    CONSTRAINT official_quality_daily_aggregates_crash_check CHECK (
        crash_code IS NULL OR crash_code IN (
            'gateway_unavailable', 'runtime_process_exit',
            'runtime_protocol_failure', 'unclassified_runtime_failure'
        )
    ),
    CONSTRAINT official_quality_daily_aggregates_rating_check CHECK (
        feedback_rating IS NULL
        OR feedback_rating IN ('helpful', 'not_helpful')
    ),
    CONSTRAINT official_quality_daily_aggregates_reason_check CHECK (
        feedback_reason_code IS NULL OR feedback_reason_code IN (
            'incorrect', 'incomplete', 'tool_failed', 'too_slow',
            'unsafe_or_inappropriate', 'other_without_text'
        )
    ),
    CONSTRAINT official_quality_daily_aggregates_feedback_variant_check CHECK (
        (event_kind = 'metric'
            AND feedback_rating IS NULL
            AND feedback_reason_code IS NULL)
        OR (event_kind = 'explicit_feedback'
            AND feedback_rating IS NOT NULL)
    ),
    CONSTRAINT official_quality_daily_aggregates_count_check CHECK (
        event_count > 0
        AND distinct_subject_count > 0
        AND distinct_subject_count <= event_count
    ),
    CONSTRAINT official_quality_daily_aggregates_suppression_check CHECK (
        suppression_threshold BETWEEN 10 AND 1000
        AND is_suppressed = (distinct_subject_count < suppression_threshold)
    ),
    CONSTRAINT official_quality_daily_aggregates_time_check CHECK (
        updated_at >= computed_at
    ),
    CONSTRAINT official_quality_daily_aggregates_bucket_key
        UNIQUE NULLS NOT DISTINCT (
            platform_id, definition_id, version_id,
            release_id, release_revision_id, aggregate_day,
            event_kind, result_code, latency_bucket, total_token_bucket,
            crash_code, feedback_rating, feedback_reason_code
        )
);

CREATE INDEX official_quality_daily_aggregates_retention_idx
    ON official_quality_daily_aggregates (aggregate_day, updated_at);

CREATE INDEX official_quality_daily_aggregates_admin_idx
    ON official_quality_daily_aggregates (
        platform_id, definition_id, version_id,
        release_id, release_revision_id, aggregate_day DESC
    );

CREATE TABLE official_quality_proposals (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    definition_id UUID NOT NULL,
    version_id UUID NOT NULL,
    release_id UUID NOT NULL,
    release_revision_id UUID NOT NULL,
    problem_categories TEXT[] NOT NULL,
    improvement_objective TEXT NOT NULL,
    created_by_admin_id UUID NOT NULL,
    created_by_role TEXT NOT NULL,
    status TEXT NOT NULL,
    revision BIGINT NOT NULL,
    reason_code TEXT NOT NULL,
    ticket_reference TEXT,
    linked_draft_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT official_quality_proposals_definition_fk
        FOREIGN KEY (platform_id, definition_id)
        REFERENCES agent_definitions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_proposals_version_fk
        FOREIGN KEY (platform_id, version_id)
        REFERENCES agent_versions(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_proposals_release_fk
        FOREIGN KEY (release_id, platform_id, definition_id)
        REFERENCES official_releases(id, platform_id, definition_id)
        ON DELETE RESTRICT,
    CONSTRAINT official_quality_proposals_release_revision_fk
        FOREIGN KEY (release_id, release_revision_id, version_id)
        REFERENCES official_release_revisions(release_id, id, agent_version_id)
        ON DELETE RESTRICT,
    CONSTRAINT official_quality_proposals_draft_fk
        FOREIGN KEY (platform_id, linked_draft_id)
        REFERENCES platform_agent_drafts(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_proposals_categories_check CHECK (
        cardinality(problem_categories) BETWEEN 1 AND 6
        AND problem_categories <@ ARRAY[
            'reliability', 'latency', 'tool_quality',
            'correctness', 'safety', 'usability'
        ]::TEXT[]
    ),
    CONSTRAINT official_quality_proposals_objective_check CHECK (
        improvement_objective = btrim(improvement_objective)
        AND char_length(improvement_objective) BETWEEN 20 AND 2000
        AND improvement_objective !~ '[[:cntrl:]]'
    ),
    CONSTRAINT official_quality_proposals_creator_role_check CHECK (
        created_by_role = 'developer'
    ),
    CONSTRAINT official_quality_proposals_status_check CHECK (
        status IN (
            'open', 'submitted', 'approved',
            'rejected', 'draft_linked', 'closed'
        )
    ),
    CONSTRAINT official_quality_proposals_revision_check CHECK (revision > 0),
    CONSTRAINT official_quality_proposals_reason_code_check CHECK (
        reason_code ~ '^[a-z][a-z0-9_]{2,63}$'
    ),
    CONSTRAINT official_quality_proposals_ticket_check CHECK (
        ticket_reference IS NULL
        OR char_length(ticket_reference) BETWEEN 1 AND 128
    ),
    CONSTRAINT official_quality_proposals_draft_variant_check CHECK (
        (status IN ('draft_linked', 'closed') AND linked_draft_id IS NOT NULL)
        OR (status NOT IN ('draft_linked', 'closed') AND linked_draft_id IS NULL)
    ),
    CONSTRAINT official_quality_proposals_time_check CHECK (
        updated_at >= created_at
        AND (terminal_at IS NULL OR terminal_at >= created_at)
    ),
    CONSTRAINT official_quality_proposals_platform_id_id_key
        UNIQUE (platform_id, id)
);

CREATE INDEX official_quality_proposals_list_idx
    ON official_quality_proposals (platform_id, status, updated_at DESC);

CREATE TABLE official_quality_proposal_aggregates (
    proposal_id UUID NOT NULL,
    aggregate_id UUID NOT NULL,
    position SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_quality_proposal_aggregates_pkey
        PRIMARY KEY (proposal_id, aggregate_id),
    CONSTRAINT official_quality_proposal_aggregates_proposal_fk
        FOREIGN KEY (proposal_id)
        REFERENCES official_quality_proposals(id) ON DELETE RESTRICT,
    -- aggregate_id is validated against the live aggregate by the constraint
    -- trigger below, but intentionally has no permanent FK: aggregate rows have
    -- a hard 180-day retention bound while this immutable source ID remains as
    -- proposal provenance after the aggregate expires.
    CONSTRAINT official_quality_proposal_aggregates_position_check CHECK (
        position BETWEEN 1 AND 100
    ),
    CONSTRAINT official_quality_proposal_aggregates_position_key
        UNIQUE (proposal_id, position)
);

CREATE TABLE official_quality_proposal_reviews (
    id UUID PRIMARY KEY,
    platform_id UUID NOT NULL,
    proposal_id UUID NOT NULL,
    reviewer_admin_id UUID NOT NULL,
    reviewer_role TEXT NOT NULL,
    decision TEXT NOT NULL,
    reviewed_revision BIGINT NOT NULL,
    reason_code TEXT NOT NULL,
    ticket_reference TEXT,
    reviewed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT official_quality_proposal_reviews_proposal_key
        UNIQUE (proposal_id),
    CONSTRAINT official_quality_proposal_reviews_proposal_fk
        FOREIGN KEY (platform_id, proposal_id)
        REFERENCES official_quality_proposals(platform_id, id) ON DELETE RESTRICT,
    CONSTRAINT official_quality_proposal_reviews_reviewer_role_check CHECK (
        reviewer_role = 'super_admin'
    ),
    CONSTRAINT official_quality_proposal_reviews_decision_check CHECK (
        decision IN ('approve', 'reject')
    ),
    CONSTRAINT official_quality_proposal_reviews_revision_check CHECK (
        reviewed_revision > 0
    ),
    CONSTRAINT official_quality_proposal_reviews_reason_code_check CHECK (
        reason_code ~ '^[a-z][a-z0-9_]{2,63}$'
    ),
    CONSTRAINT official_quality_proposal_reviews_ticket_check CHECK (
        ticket_reference IS NULL
        OR char_length(ticket_reference) BETWEEN 1 AND 128
    )
);

CREATE FUNCTION reject_official_quality_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Official quality row is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION guard_official_quality_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('agentera.official_quality_retention', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'Official quality event is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER official_quality_consent_receipt_immutable_trigger
    BEFORE UPDATE OR DELETE ON official_quality_consent_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_official_quality_immutable_mutation();

CREATE TRIGGER official_quality_event_immutable_trigger
    BEFORE UPDATE OR DELETE ON official_quality_events
    FOR EACH ROW EXECUTE FUNCTION guard_official_quality_event_mutation();

CREATE TRIGGER official_quality_proposal_review_immutable_trigger
    BEFORE UPDATE OR DELETE ON official_quality_proposal_reviews
    FOR EACH ROW EXECUTE FUNCTION reject_official_quality_immutable_mutation();

CREATE TRIGGER official_quality_proposal_aggregate_immutable_trigger
    BEFORE UPDATE OR DELETE ON official_quality_proposal_aggregates
    FOR EACH ROW EXECUTE FUNCTION reject_official_quality_immutable_mutation();

CREATE FUNCTION enforce_official_quality_proposal_aggregate_source()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    source_matches BOOLEAN;
BEGIN
    SELECT (
        proposal.platform_id = aggregate.platform_id
        AND proposal.definition_id = aggregate.definition_id
        AND proposal.version_id = aggregate.version_id
        AND proposal.release_id = aggregate.release_id
        AND proposal.release_revision_id = aggregate.release_revision_id
    ) INTO source_matches
    FROM official_quality_proposals proposal
    JOIN official_quality_daily_aggregates aggregate
      ON aggregate.id = NEW.aggregate_id
    WHERE proposal.id = NEW.proposal_id;

    IF source_matches IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Official quality proposal aggregate source is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER official_quality_proposal_aggregate_source_trigger
    AFTER INSERT ON official_quality_proposal_aggregates
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION enforce_official_quality_proposal_aggregate_source();

CREATE FUNCTION enforce_official_quality_proposal_review_separation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    creator UUID;
    proposal_revision BIGINT;
    proposal_status TEXT;
BEGIN
    SELECT created_by_admin_id, revision, status
    INTO creator, proposal_revision, proposal_status
    FROM official_quality_proposals
    WHERE id = NEW.proposal_id AND platform_id = NEW.platform_id;

    IF creator IS NULL
       OR creator = NEW.reviewer_admin_id
       OR proposal_status <> 'submitted'
       OR proposal_revision <> NEW.reviewed_revision THEN
        RAISE EXCEPTION 'Official quality proposal review is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER official_quality_proposal_review_separation_trigger
    AFTER INSERT ON official_quality_proposal_reviews
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION enforce_official_quality_proposal_review_separation();

CREATE FUNCTION delete_official_quality_events_before(cutoff_day DATE)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_count BIGINT;
BEGIN
    IF cutoff_day IS NULL THEN
        RAISE EXCEPTION 'Official quality retention cutoff is required'
            USING ERRCODE = '22004';
    END IF;
    PERFORM set_config('agentera.official_quality_retention', 'on', true);
    DELETE FROM official_quality_events WHERE event_day < cutoff_day;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

ALTER TABLE admin_operations
    DROP CONSTRAINT admin_operations_action_check,
    DROP CONSTRAINT admin_operations_target_type_check,
    DROP CONSTRAINT admin_operations_action_target_check,
    ADD CONSTRAINT admin_operations_action_check CHECK (action IN (
        'revoke_device', 'revoke_session', 'disable_user', 'enable_user',
        'official_definition_reserve', 'official_draft_create', 'official_draft_update',
        'official_draft_submit', 'official_submission_withdraw', 'official_submission_review',
        'official_release_activate', 'official_release_rollout', 'official_release_pause',
        'official_release_resume', 'official_release_rollback',
        'official_quality_proposal_create', 'official_quality_proposal_submit',
        'official_quality_proposal_review', 'official_quality_draft_clone'
    )),
    ADD CONSTRAINT admin_operations_target_type_check CHECK (target_type IN (
        'device', 'session', 'user', 'platform_definition', 'platform_draft',
        'platform_submission', 'official_release', 'official_quality_proposal'
    )),
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
        OR (action IN (
                'official_quality_proposal_create',
                'official_quality_proposal_submit',
                'official_quality_proposal_review',
                'official_quality_draft_clone'
            ) AND target_type = 'official_quality_proposal')
    );
