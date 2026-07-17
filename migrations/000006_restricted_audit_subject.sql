ALTER TABLE audit_events
    ADD COLUMN operator_identity TEXT,
    ADD COLUMN subject_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT audit_events_operator_identity_length_check CHECK (
        operator_identity IS NULL OR char_length(operator_identity) BETWEEN 1 AND 128
    );

CREATE INDEX audit_events_subject_time_idx
    ON audit_events (subject_user_id, created_at DESC);
