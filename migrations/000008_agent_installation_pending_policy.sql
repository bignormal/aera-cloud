ALTER TABLE installations
    DROP CONSTRAINT installations_lifecycle_check;

ALTER TABLE installations
    ADD CONSTRAINT installations_lifecycle_check CHECK (
        (status = 'pending' AND runtime_profile_id IS NULL AND activated_at IS NULL AND archived_at IS NULL)
        OR
        (status = 'active' AND runtime_profile_id IS NOT NULL AND policy_snapshot_id IS NOT NULL AND activated_at IS NOT NULL AND archived_at IS NULL)
        OR
        (status = 'archived' AND archived_at IS NOT NULL)
    );
