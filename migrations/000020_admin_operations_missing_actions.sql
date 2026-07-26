-- The admin control service dispatches force_password_reset and
-- revoke_all_sessions (internal/admin/control_model.go), but the
-- admin_operations checks from 000015_internal_admin_api.sql never allowed
-- them, so every such command failed with SERVICE_UNAVAILABLE. Align the
-- action allowlist and the action/target pairing with the code.
ALTER TABLE admin_operations
    DROP CONSTRAINT admin_operations_action_check;
ALTER TABLE admin_operations
    ADD CONSTRAINT admin_operations_action_check CHECK (action IN (
        'revoke_device', 'revoke_session', 'revoke_all_sessions',
        'disable_user', 'enable_user', 'force_password_reset',
        'official_definition_reserve', 'official_draft_create',
        'official_draft_update', 'official_draft_submit',
        'official_submission_withdraw', 'official_submission_review',
        'official_release_activate', 'official_release_rollout',
        'official_release_pause', 'official_release_resume',
        'official_release_rollback',
        'official_quality_proposal_create', 'official_quality_proposal_submit',
        'official_quality_proposal_review', 'official_quality_draft_clone'
    ));

ALTER TABLE admin_operations
    DROP CONSTRAINT admin_operations_action_target_check;
ALTER TABLE admin_operations
    ADD CONSTRAINT admin_operations_action_target_check CHECK (
        (action = 'revoke_device' AND target_type = 'device')
        OR (action = 'revoke_session' AND target_type = 'session')
        OR (action IN ('revoke_all_sessions', 'disable_user', 'enable_user', 'force_password_reset')
            AND target_type = 'user')
        OR (action = 'official_definition_reserve' AND target_type = 'platform_definition')
        OR (action IN ('official_draft_create', 'official_draft_update')
            AND target_type = 'platform_draft')
        OR (action IN ('official_draft_submit', 'official_submission_withdraw', 'official_submission_review')
            AND target_type = 'platform_submission')
        OR (action IN ('official_release_activate', 'official_release_rollout', 'official_release_pause',
                       'official_release_resume', 'official_release_rollback')
            AND target_type = 'official_release')
        OR (action IN ('official_quality_proposal_create', 'official_quality_proposal_submit',
                       'official_quality_proposal_review', 'official_quality_draft_clone')
            AND target_type = 'official_quality_proposal')
    );
