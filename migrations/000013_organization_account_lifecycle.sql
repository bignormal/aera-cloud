ALTER TABLE organization_invitations
    DROP CONSTRAINT organization_invitations_lifecycle_check,
    ADD CONSTRAINT organization_invitations_lifecycle_check CHECK (
        (status = 'pending' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL)
        OR (status = 'accepted' AND accepted_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'revoked' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NOT NULL)
        OR (status = 'expired' AND accepted_by_user_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL)
    );
