CREATE TABLE experience_candidates (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL,
    agent_definition_id UUID NOT NULL,
    source_agent_version_id UUID NOT NULL,
    submitted_by_user_id UUID,
    submitted_from_device_id UUID,
    kind TEXT NOT NULL,
    skill_name TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    dlp_contract_version TEXT NOT NULL,
    content_digest BYTEA NOT NULL,
    bundle_document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT experience_candidates_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE RESTRICT,
    CONSTRAINT experience_candidates_definition_fk
        FOREIGN KEY (agent_definition_id) REFERENCES agent_definitions(id) ON DELETE RESTRICT,
    CONSTRAINT experience_candidates_source_version_fk
        FOREIGN KEY (source_agent_version_id) REFERENCES agent_versions(id) ON DELETE RESTRICT,
    CONSTRAINT experience_candidates_submitted_by_user_fk
        FOREIGN KEY (submitted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT experience_candidates_submitted_from_device_fk
        FOREIGN KEY (submitted_from_device_id) REFERENCES devices(id) ON DELETE SET NULL,
    CONSTRAINT experience_candidates_id_workspace_key UNIQUE (id, workspace_id),
    CONSTRAINT experience_candidates_kind_check CHECK (kind = 'SKILL'),
    CONSTRAINT experience_candidates_skill_name_check CHECK (
        skill_name = btrim(skill_name)
        AND char_length(skill_name) BETWEEN 1 AND 100
        AND skill_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT experience_candidates_schema_version_check CHECK (schema_version = 1),
    CONSTRAINT experience_candidates_dlp_contract_version_check CHECK (
        dlp_contract_version = 'experience-candidate-dlp-v1'
    ),
    CONSTRAINT experience_candidates_content_digest_length_check CHECK (
        octet_length(content_digest) = 32
    ),
    CONSTRAINT experience_candidates_bundle_document_check CHECK (
        jsonb_typeof(bundle_document) = 'object'
    )
);

CREATE TABLE experience_candidate_reviews (
    id UUID PRIMARY KEY,
    candidate_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    decision TEXT NOT NULL,
    reviewed_by_user_id UUID,
    reason_code TEXT,
    safe_note TEXT,
    reviewed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT experience_candidate_reviews_candidate_id_key UNIQUE (candidate_id),
    CONSTRAINT experience_candidate_reviews_workspace_fk
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE RESTRICT,
    CONSTRAINT experience_candidate_reviews_candidate_workspace_fk
        FOREIGN KEY (candidate_id, workspace_id)
        REFERENCES experience_candidates(id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT experience_candidate_reviews_reviewed_by_user_fk
        FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT experience_candidate_reviews_decision_check CHECK (
        decision IN ('APPROVED', 'REJECTED')
    ),
    CONSTRAINT experience_candidate_reviews_rejection_check CHECK (
        (decision = 'APPROVED' AND reason_code IS NULL AND safe_note IS NULL)
        OR
        (
            decision = 'REJECTED'
            AND reason_code = btrim(reason_code)
            AND char_length(reason_code) BETWEEN 1 AND 64
            AND reason_code ~ '^[a-z0-9_]+$'
            AND (
                safe_note IS NULL
                OR (
                    safe_note = btrim(safe_note)
                    AND char_length(safe_note) BETWEEN 1 AND 240
                    AND safe_note !~ '[[:cntrl:]]'
                )
            )
        )
    )
);

CREATE INDEX experience_candidates_workspace_created_idx
    ON experience_candidates (workspace_id, created_at DESC, id);

CREATE INDEX experience_candidates_submitter_created_idx
    ON experience_candidates (submitted_by_user_id, created_at DESC)
    WHERE submitted_by_user_id IS NOT NULL;

CREATE INDEX experience_candidates_definition_created_idx
    ON experience_candidates (agent_definition_id, created_at DESC);

CREATE INDEX experience_candidate_reviews_workspace_reviewed_idx
    ON experience_candidate_reviews (workspace_id, reviewed_at DESC, candidate_id);

CREATE FUNCTION enforce_experience_candidate_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'immutable ExperienceCandidate cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
        OR NEW.agent_definition_id IS DISTINCT FROM OLD.agent_definition_id
        OR NEW.source_agent_version_id IS DISTINCT FROM OLD.source_agent_version_id
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.skill_name IS DISTINCT FROM OLD.skill_name
        OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
        OR NEW.dlp_contract_version IS DISTINCT FROM OLD.dlp_contract_version
        OR NEW.content_digest IS DISTINCT FROM OLD.content_digest
        OR NEW.bundle_document IS DISTINCT FROM OLD.bundle_document
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'immutable ExperienceCandidate core cannot be updated'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.submitted_by_user_id IS DISTINCT FROM OLD.submitted_by_user_id THEN
        IF NEW.submitted_by_user_id IS NOT NULL
            OR OLD.submitted_by_user_id IS NULL
            OR EXISTS (
                SELECT 1
                FROM users
                WHERE id = OLD.submitted_by_user_id
                  AND (status <> 'disabled' OR deletion_finalized_at IS NULL)
            ) THEN
            RAISE EXCEPTION 'ExperienceCandidate submitter can detach only after account deletion'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    IF NEW.submitted_from_device_id IS DISTINCT FROM OLD.submitted_from_device_id THEN
        IF NEW.submitted_from_device_id IS NOT NULL
            OR OLD.submitted_from_device_id IS NULL
            OR EXISTS (SELECT 1 FROM devices WHERE id = OLD.submitted_from_device_id) THEN
            RAISE EXCEPTION 'ExperienceCandidate device can detach only after device deletion'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER experience_candidates_immutable_trigger
    BEFORE UPDATE OR DELETE ON experience_candidates
    FOR EACH ROW EXECUTE FUNCTION enforce_experience_candidate_immutability();

CREATE FUNCTION enforce_experience_candidate_review_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'terminal ExperienceCandidate review cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id
        OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
        OR NEW.decision IS DISTINCT FROM OLD.decision
        OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
        OR NEW.safe_note IS DISTINCT FROM OLD.safe_note
        OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at THEN
        RAISE EXCEPTION 'terminal ExperienceCandidate review cannot be updated'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.reviewed_by_user_id IS DISTINCT FROM OLD.reviewed_by_user_id THEN
        IF NEW.reviewed_by_user_id IS NOT NULL
            OR OLD.reviewed_by_user_id IS NULL
            OR EXISTS (
                SELECT 1
                FROM users
                WHERE id = OLD.reviewed_by_user_id
                  AND (status <> 'disabled' OR deletion_finalized_at IS NULL)
            ) THEN
            RAISE EXCEPTION 'ExperienceCandidate reviewer can detach only after account deletion'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER experience_candidate_reviews_immutable_trigger
    BEFORE UPDATE OR DELETE ON experience_candidate_reviews
    FOR EACH ROW EXECUTE FUNCTION enforce_experience_candidate_review_immutability();
