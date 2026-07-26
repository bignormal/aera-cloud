package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/bignormal/aera-cloud/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEmbeddedMigrationsIncludeInternalBetaDirectRegistration(t *testing.T) {
	loaded, err := loadMigrations(migrations.FS)
	if err != nil {
		t.Fatalf("loadMigrations() error = %v", err)
	}
	if len(loaded) != 20 {
		t.Fatalf("embedded migration count = %d, want 20", len(loaded))
	}
	directRegistration := loaded[18]
	if directRegistration.version != 19 || directRegistration.name != "000019_internal_beta_direct_registration.sql" {
		t.Fatalf("migration 19 = %d/%s", directRegistration.version, directRegistration.name)
	}
	const expected = "ALTER TABLE identities\n    ALTER COLUMN verified_at DROP NOT NULL;"
	if strings.TrimSpace(string(directRegistration.contents)) != expected {
		t.Fatalf("migration 19 contents = %q, want only verified_at nullability change", directRegistration.contents)
	}

	adminActions := loaded[19]
	if adminActions.version != 20 || adminActions.name != "000020_admin_operations_missing_actions.sql" {
		t.Fatalf("migration 20 = %d/%s", adminActions.version, adminActions.name)
	}
	for _, required := range []string{"'revoke_all_sessions'", "'force_password_reset'", "target_type = 'user'"} {
		if !strings.Contains(string(adminActions.contents), required) {
			t.Fatalf("migration 20 is missing %q", required)
		}
	}
}

func TestApplyMigrationsCreatesAuthSchemaAndIsIdempotent(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()

	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("second ApplyMigrations() error = %v", err)
	}

	tables := []string{
		"users",
		"identities",
		"password_credentials",
		"personal_spaces",
		"devices",
		"sessions",
		"verification_challenges",
		"oauth_requests",
		"authorization_codes",
		"offline_entitlement_issuances",
		"audit_events",
		"legal_acceptances",
		"device_self_revocation_nonces",
		"agent_definitions",
		"agent_versions",
		"agent_version_revocations",
		"installations",
		"policy_snapshots",
		"runtime_binding_records",
		"agent_control_idempotency_keys",
		"workspaces",
		"workspace_memberships",
		"workspace_invitations",
		"workspace_idempotency_records",
		"experience_candidates",
		"experience_candidate_reviews",
		"organizations",
		"organization_memberships",
		"organization_departments",
		"organization_invitations",
		"organization_policy_snapshots",
		"organization_idempotency_records",
		"organization_agent_submissions",
		"organization_agent_reviews",
		"admin_operations",
		"platforms",
		"platform_agent_drafts",
		"platform_agent_policy_snapshots",
		"platform_agent_submissions",
		"platform_agent_reviews",
		"official_releases",
		"official_release_revisions",
		"official_release_audience_accounts",
		"official_quality_consent_receipts",
		"official_quality_purge_requests",
		"official_quality_events",
		"official_quality_daily_aggregates",
		"official_quality_proposals",
		"official_quality_proposal_aggregates",
		"official_quality_proposal_reviews",
		"backup_devices",
		"encrypted_profile_backups",
		"encrypted_backup_chunks",
		"encrypted_backup_key_envelopes",
		"encrypted_backup_operations",
	}
	for _, table := range tables {
		var exists bool
		if err := postgres.QueryRow(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s does not exist", table)
		}
	}

	assertUniqueConstraint(t, ctx, postgres, "identities", "identities_kind_lookup_hmac_key", []string{"kind", "lookup_hmac"})
	assertUniqueConstraint(t, ctx, postgres, "devices", "devices_installation_id_key", []string{"installation_id"})
	assertUniqueConstraint(t, ctx, postgres, "identities", "identities_user_id_kind_key", []string{"user_id", "kind"})
	assertUniqueConstraint(t, ctx, postgres, "agent_versions", "agent_versions_definition_version_key", []string{"definition_id", "version_number"})
	assertUniqueConstraint(t, ctx, postgres, "agent_version_revocations", "agent_version_revocations_version_key", []string{"version_id"})
	assertUniqueConstraint(t, ctx, postgres, "policy_snapshots", "policy_snapshots_installation_version_key", []string{"installation_id", "policy_version"})
	assertUniqueConstraint(t, ctx, postgres, "experience_candidates", "experience_candidates_id_workspace_key", []string{"id", "workspace_id"})
	assertUniqueConstraint(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_candidate_id_key", []string{"candidate_id"})
	assertUniqueConstraint(t, ctx, postgres, "organization_invitations", "organization_invitations_token_digest_key", []string{"token_digest"})
	assertUniqueConstraint(t, ctx, postgres, "organization_policy_snapshots", "organization_policy_snapshots_organization_version_key", []string{"organization_id", "policy_version"})
	assertUniqueConstraint(t, ctx, postgres, "organization_policy_snapshots", "organization_policy_snapshots_organization_id_id_key", []string{"organization_id", "id"})
	assertUniqueConstraint(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submissions_org_id_key", []string{"organization_id", "id"})
	assertUniqueConstraint(t, ctx, postgres, "organization_agent_reviews", "organization_agent_reviews_submission_key", []string{"submission_id"})
	assertUniqueConstraint(t, ctx, postgres, "platform_agent_reviews", "platform_agent_reviews_submission_key", []string{"submission_id"})
	assertUniqueConstraint(t, ctx, postgres, "official_releases", "official_releases_platform_definition_channel_key", []string{"platform_id", "definition_id", "channel"})
	assertUniqueConstraint(t, ctx, postgres, "official_releases", "official_releases_id_platform_definition_key", []string{"id", "platform_id", "definition_id"})
	assertUniqueConstraint(t, ctx, postgres, "official_release_revisions", "official_release_revisions_release_revision_key", []string{"release_id", "revision_number"})
	assertUniqueConstraint(t, ctx, postgres, "official_quality_consent_receipts", "official_quality_consent_receipts_user_purpose_revision_key", []string{"user_id", "purpose", "revision"})
	assertUniqueConstraint(t, ctx, postgres, "official_quality_proposals", "official_quality_proposals_platform_id_id_key", []string{"platform_id", "id"})
	assertUniqueConstraint(t, ctx, postgres, "official_quality_proposal_reviews", "official_quality_proposal_reviews_proposal_key", []string{"proposal_id"})
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_content_digest_length_check", "octet_length(content_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_signature_length_check", "octet_length(signature) = 64")
	assertCheckConstraintContains(t, ctx, postgres, "policy_snapshots", "policy_snapshots_content_digest_length_check", "octet_length(content_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "policy_snapshots", "policy_snapshots_signature_length_check", "octet_length(signature) = 64")
	assertCheckConstraintContains(t, ctx, postgres, "runtime_binding_records", "runtime_binding_records_tool_digest_length_check", "octet_length(tool_permission_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_key_hash_length_check", "octet_length(key_hash) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_request_hash_length_check", "octet_length(request_hash) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "installations", "installations_lifecycle_check", "runtime_profile_id")
	assertCheckConstraintContains(t, ctx, postgres, "official_quality_events", "official_quality_events_result_check", "runtime_crash")
	assertCheckConstraintContains(t, ctx, postgres, "official_quality_events", "official_quality_events_latency_check", "gte_180s")
	assertCheckConstraintContains(t, ctx, postgres, "official_quality_events", "official_quality_events_token_check", "gte_64k")
	assertCheckConstraintContains(t, ctx, postgres, "official_quality_events", "official_quality_events_signature_length_check", "octet_length(device_signature) = 64")
	assertCheckConstraintContains(t, ctx, postgres, "official_quality_daily_aggregates", "official_quality_daily_aggregates_suppression_check", "distinct_subject_count < suppression_threshold")
	assertTriggerExists(t, ctx, postgres, "official_quality_consent_receipts", "official_quality_consent_receipt_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "official_quality_events", "official_quality_event_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "official_quality_proposal_aggregates", "official_quality_proposal_aggregate_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "official_quality_proposal_reviews", "official_quality_proposal_review_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "encrypted_profile_backups", "encrypted_profile_backup_guard_trigger")
	assertTriggerExists(t, ctx, postgres, "encrypted_backup_chunks", "encrypted_backup_chunk_immutable_trigger")
	assertCheckConstraintContains(t, ctx, postgres, "encrypted_profile_backups", "encrypted_profile_backups_size_check", "1073741824")
	assertCheckConstraintContains(t, ctx, postgres, "encrypted_profile_backups", "encrypted_profile_backups_state_check", "deleting")
	assertCheckConstraintContains(t, ctx, postgres, "encrypted_profile_backups", "encrypted_profile_backups_cipher_suite_check", "HPKE-X25519-HKDF-SHA256-AES256GCM")
	assertCheckConstraintContains(t, ctx, postgres, "backup_devices", "backup_devices_public_key_length_check", "octet_length(public_key) = 32")
	assertCheckConstraintExcludes(t, ctx, postgres, "installations", "installations_lifecycle_check", "policy_snapshot_id IS NULL")
	assertCheckConstraintContains(t, ctx, postgres, "installations", "installations_status_check", "pending")
	assertCheckConstraintContains(t, ctx, postgres, "installations", "installations_update_policy_check", "manual")
	assertCheckConstraintContains(t, ctx, postgres, "workspaces", "workspaces_display_name_check", "char_length(btrim(display_name))")
	assertCheckConstraintContains(t, ctx, postgres, "workspaces", "workspaces_lifecycle_check", "archived_at")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_memberships", "workspace_memberships_role_check", "owner")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_token_digest_length_check", "octet_length(token_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_expiry_check", "expires_at")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_lifecycle_check", "accepted_by_user_id")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_idempotency_records", "workspace_idempotency_key_digest_length_check", "octet_length(key_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_idempotency_records", "workspace_idempotency_request_digest_length_check", "octet_length(request_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_idempotency_records", "workspace_idempotency_expiry_check", "expires_at")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_owner_variant_check", "WORKSPACE")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_owner_variant_check", "workspace_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_owner_variant_check", "ORGANIZATION")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_owner_variant_check", "organization_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_owner_variant_check", "PLATFORM")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_creator_variant_check", "created_by_admin_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "WORKSPACE")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "ORGANIZATION")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "organization_submission_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "organization_policy_snapshot_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "PLATFORM")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "platform_submission_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "platform_policy_snapshot_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_owner_variant_check", "WORKSPACE")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_owner_variant_check", "ORGANIZATION")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_owner_variant_check", "PLATFORM")
	assertCheckConstraintContains(t, ctx, postgres, "installations", "installations_official_source_check", "selected_release_revision_id")
	assertCheckConstraintContains(t, ctx, postgres, "official_release_revisions", "official_release_revisions_rollout_check", "10000")
	assertCheckConstraintContains(t, ctx, postgres, "official_release_revisions", "official_release_revisions_action_check", "rollback")
	assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_action_check", "official_release_rollback")
	assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_action_check", "revoke_all_sessions")
	assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_action_check", "force_password_reset")
	assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_action_target_check", "revoke_all_sessions")
	assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_action_target_check", "force_password_reset")
	assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_target_type_check", "official_release")
	assertCheckConstraintContains(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submissions_kind_check", "initial")
	assertCheckConstraintContains(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submissions_status_check", "superseded")
	assertCheckConstraintContains(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submissions_terminal_check", "terminal_at")
	assertCheckConstraintContains(t, ctx, postgres, "organization_agent_reviews", "organization_agent_reviews_decision_check", "approve")
	assertCheckConstraintContains(t, ctx, postgres, "organization_agent_reviews", "organization_agent_reviews_reason_check", "reason_code")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_kind_check", "SKILL")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_skill_name_check", "char_length(skill_name)")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_schema_version_check", "schema_version = 1")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_dlp_contract_version_check", "experience-candidate-dlp-v1")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_content_digest_length_check", "octet_length(content_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_bundle_document_check", "jsonb_typeof(bundle_document)")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_decision_check", "APPROVED")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_decision_check", "REJECTED")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_rejection_check", "reason_code")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_rejection_check", "safe_note")
	assertCheckConstraintContains(t, ctx, postgres, "organizations", "organizations_display_name_check", "char_length(display_name)")
	assertCheckConstraintContains(t, ctx, postgres, "organizations", "organizations_status_check", "dissolved")
	assertCheckConstraintContains(t, ctx, postgres, "organizations", "organizations_policy_required_check", "current_policy_snapshot_id")
	assertCheckConstraintContains(t, ctx, postgres, "organizations", "organizations_lifecycle_check", "dissolved_at")
	assertCheckConstraintContains(t, ctx, postgres, "organization_memberships", "organization_memberships_role_check", "auditor")
	assertCheckConstraintContains(t, ctx, postgres, "organization_departments", "organization_departments_display_name_check", "char_length(display_name)")
	assertCheckConstraintContains(t, ctx, postgres, "organization_departments", "organization_departments_lifecycle_check", "archived_at")
	assertCheckConstraintContains(t, ctx, postgres, "organization_invitations", "organization_invitations_token_digest_length_check", "octet_length(token_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "organization_invitations", "organization_invitations_expiry_check", "7 days")
	assertCheckConstraintContains(t, ctx, postgres, "organization_invitations", "organization_invitations_lifecycle_check", "accepted_at IS NOT NULL")
	for _, status := range []string{"executing", "succeeded", "failed", "conflict"} {
		assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_status_check", status)
	}
	assertCheckConstraintExcludes(t, ctx, postgres, "organization_invitations", "organization_invitations_lifecycle_check", "accepted_by_user_id IS NOT NULL")
	assertCheckConstraintContains(t, ctx, postgres, "organization_policy_snapshots", "organization_policy_snapshots_schema_version_check", "schema_version = 1")
	assertCheckConstraintContains(t, ctx, postgres, "organization_policy_snapshots", "organization_policy_snapshots_content_digest_length_check", "octet_length(content_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "organization_policy_snapshots", "organization_policy_snapshots_signature_length_check", "octet_length(signature) = 64")
	assertCheckConstraintContains(t, ctx, postgres, "organization_idempotency_records", "organization_idempotency_key_digest_length_check", "octet_length(key_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "organization_idempotency_records", "organization_idempotency_request_digest_length_check", "octet_length(request_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "organization_idempotency_records", "organization_idempotency_expiry_check", "24:00:00")

	assertForeignKeyConstraintContains(t, ctx, postgres, "workspaces", "workspaces_owner_user_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_memberships", "workspace_memberships_workspace_fk", "ON DELETE CASCADE")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_memberships", "workspace_memberships_user_fk", "ON DELETE CASCADE")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_created_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_accepted_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_workspace_fk", "ON DELETE CASCADE")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_definition_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_source_version_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_submitted_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_submitted_from_device_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_candidate_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_reviewed_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_memberships", "organization_memberships_organization_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_memberships", "organization_memberships_user_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_memberships", "organization_memberships_department_fk", "FOREIGN KEY (organization_id, department_id)")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_invitations", "organization_invitations_created_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_invitations", "organization_invitations_accepted_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_policy_snapshots", "organization_policy_snapshots_issued_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organizations", "organizations_current_policy_fk", "DEFERRABLE INITIALLY DEFERRED")
	assertForeignKeyConstraintContains(t, ctx, postgres, "audit_events", "audit_events_organization_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_organization_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_organization_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_organization_policy_fk", "FOREIGN KEY (organization_id, organization_policy_snapshot_id)")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_organization_submission_fk", "FOREIGN KEY (organization_id, organization_submission_id)")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_organization_fk", "ON DELETE CASCADE")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submissions_organization_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_agent_reviews", "organization_agent_reviews_submission_fk", "FOREIGN KEY (organization_id, submission_id)")
	assertForeignKeyConstraintContains(t, ctx, postgres, "organization_agent_reviews", "organization_agent_reviews_policy_fk", "FOREIGN KEY (organization_id, organization_policy_snapshot_id)")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_platform_submission_fk", "FOREIGN KEY (platform_id, platform_submission_id)")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_platform_policy_fk", "FOREIGN KEY (platform_id, platform_policy_snapshot_id)")
	assertForeignKeyConstraintContains(t, ctx, postgres, "official_releases", "official_releases_current_revision_fk", "DEFERRABLE INITIALLY DEFERRED")
	assertForeignKeyConstraintContains(t, ctx, postgres, "installations", "installations_official_selection_fk", "FOREIGN KEY (official_release_id, selected_release_revision_id, selected_version_id)")

	assertIndexDefinitionContains(t, ctx, postgres, "workspace_memberships_one_owner_idx", "UNIQUE", "workspace_id", "WHERE", "owner")
	assertIndexDefinitionContains(t, ctx, postgres, "workspaces_owner_active_idx", "owner_user_id", "WHERE", "active")
	assertIndexDefinitionContains(t, ctx, postgres, "workspace_memberships_user_list_idx", "user_id", "workspace_id")
	assertIndexDefinitionContains(t, ctx, postgres, "workspace_invitations_pending_idx", "workspace_id", "expires_at", "pending")
	assertIndexDefinitionContains(t, ctx, postgres, "workspace_idempotency_expiry_idx", "expires_at")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_control_idempotency_user_operation_key", "UNIQUE", "tenant_id", "owner_id", "operation", "key_hash", "USER")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_control_idempotency_workspace_operation_key", "UNIQUE", "workspace_id", "operation", "key_hash", "WORKSPACE")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidates_workspace_created_idx", "workspace_id", "created_at", "id")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidates_submitter_created_idx", "submitted_by_user_id", "created_at")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidates_definition_created_idx", "agent_definition_id", "created_at")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidate_reviews_workspace_reviewed_idx", "workspace_id", "reviewed_at", "candidate_id")
	assertIndexDefinitionContains(t, ctx, postgres, "organization_memberships_one_owner_idx", "UNIQUE", "organization_id", "WHERE", "owner")
	assertIndexDefinitionContains(t, ctx, postgres, "organization_memberships_user_list_idx", "user_id", "organization_id")
	assertIndexDefinitionContains(t, ctx, postgres, "organization_departments_active_name_idx", "UNIQUE", "organization_id", "name_key", "WHERE", "active")
	assertIndexDefinitionContains(t, ctx, postgres, "organization_invitations_pending_idx", "organization_id", "expires_at", "pending")
	assertIndexDefinitionContains(t, ctx, postgres, "organization_policy_snapshots_history_idx", "organization_id", "policy_version")
	assertIndexDefinitionContains(t, ctx, postgres, "organization_idempotency_expiry_idx", "expires_at")
	assertIndexDefinitionContains(t, ctx, postgres, "audit_events_organization_created_idx", "organization_id", "created_at", "id")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_control_idempotency_organization_operation_key", "UNIQUE", "organization_id", "operation", "key_hash", "ORGANIZATION")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_definitions_organization_list_idx", "organization_id", "updated_at", "ORGANIZATION")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_versions_organization_time_idx", "organization_id", "published_at", "ORGANIZATION")
	assertIndexDefinitionContains(t, ctx, postgres, "organization_agent_submissions_queue_idx", "organization_id", "status", "submitted_at")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_control_idempotency_platform_operation_key", "UNIQUE", "platform_id", "operation", "key_hash", "PLATFORM")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_definitions_platform_list_idx", "platform_id", "updated_at", "PLATFORM")
	assertIndexDefinitionContains(t, ctx, postgres, "official_release_revisions_release_created_idx", "release_id", "revision_number")

	assertColumns(t, ctx, postgres, "agent_definitions", []string{
		"id", "tenant_id", "owner_scope", "owner_id", "display_name", "icon_media_type", "icon_data",
		"status", "latest_version_id", "created_by", "created_at", "updated_at", "workspace_id", "organization_id",
		"platform_id", "created_by_admin_id",
	})
	assertColumns(t, ctx, postgres, "agent_versions", []string{
		"id", "definition_id", "tenant_id", "owner_scope", "owner_id", "version_number",
		"canonical_manifest", "bundle", "content_digest", "signing_key_id", "signature",
		"runtime_minimum_version", "runtime_maximum_version_exclusive", "published_by", "published_at", "workspace_id",
		"organization_id", "organization_submission_id", "organization_policy_snapshot_id",
		"platform_id", "platform_submission_id", "platform_policy_snapshot_id", "published_by_admin_id",
	})
	assertColumns(t, ctx, postgres, "agent_control_idempotency_keys", []string{"workspace_id", "organization_id", "platform_id"})
	for _, table := range []string{"agent_definitions", "agent_versions", "agent_control_idempotency_keys"} {
		assertColumnNullable(t, ctx, postgres, table, "tenant_id", true)
		assertColumnNullable(t, ctx, postgres, table, "owner_id", true)
		assertColumnNullable(t, ctx, postgres, table, "workspace_id", true)
		assertColumnNullable(t, ctx, postgres, table, "organization_id", true)
		assertColumnNullable(t, ctx, postgres, table, "platform_id", true)
	}
	assertColumnNullable(t, ctx, postgres, "agent_definitions", "created_by", true)
	assertColumnNullable(t, ctx, postgres, "agent_definitions", "created_by_admin_id", true)
	assertColumnNullable(t, ctx, postgres, "agent_versions", "published_by", true)
	assertColumnNullable(t, ctx, postgres, "agent_versions", "published_by_admin_id", true)
	assertColumnNullable(t, ctx, postgres, "agent_versions", "organization_submission_id", true)
	assertColumnNullable(t, ctx, postgres, "agent_versions", "organization_policy_snapshot_id", true)
	assertColumns(t, ctx, postgres, "installations", []string{
		"id", "tenant_id", "owner_scope", "owner_id", "device_id", "device_installation_id",
		"definition_id", "selected_version_id", "runtime_profile_id", "policy_snapshot_id", "update_policy",
		"status", "created_by", "created_at", "updated_at", "activated_at", "archived_at",
		"official_release_id", "selected_release_revision_id",
	})
	assertColumns(t, ctx, postgres, "runtime_binding_records", []string{"official_release_revision_id"})
	assertColumns(t, ctx, postgres, "platform_agent_reviews", []string{
		"platform_id", "submission_id", "reviewer_admin_id", "platform_policy_snapshot_id",
		"platform_policy_version", "reviewed_content_digest",
	})
	assertColumns(t, ctx, postgres, "official_release_revisions", []string{
		"release_id", "revision_number", "agent_version_id", "state", "rollout_basis_points",
		"minimum_desktop_version", "bucket_algorithm_version", "rollout_key_id", "action",
		"previous_revision_id", "rollback_target_revision_id", "actor_admin_id", "actor_admin_role",
	})
	assertColumns(t, ctx, postgres, "encrypted_profile_backups", []string{
		"id", "user_id", "source_device_id", "source_installation_id", "source_definition_id",
		"source_version_id", "profile_lineage_id", "parent_backup_id", "format_version", "cipher_suite",
		"state", "chunk_count", "total_ciphertext_size", "manifest_object_key", "manifest_ciphertext_digest",
		"manifest_ciphertext_size", "public_envelope_digest", "public_signature", "recovery_salt",
		"recovery_memory_kib", "recovery_iterations", "recovery_parallelism", "recovery_root_key_envelope",
		"wrapped_data_key", "created_at", "updated_at", "upload_expires_at", "sealed_at",
		"deletion_started_at", "deleted_at",
	})
	assertNoColumns(t, ctx, postgres, "encrypted_profile_backups", []string{
		"manifest", "filename", "file_path", "profile_path", "recovery_phrase", "root_key", "data_encryption_key",
	})
	assertColumns(t, ctx, postgres, "workspaces", []string{
		"id", "owner_user_id", "display_name", "status", "revision", "created_at", "updated_at", "archived_at",
	})
	assertColumns(t, ctx, postgres, "workspace_memberships", []string{
		"workspace_id", "user_id", "role", "revision", "joined_at", "updated_at",
	})
	assertColumns(t, ctx, postgres, "workspace_invitations", []string{
		"id", "workspace_id", "token_digest", "created_by_user_id", "status", "accepted_by_user_id",
		"created_at", "expires_at", "accepted_at", "revoked_at",
	})
	assertColumns(t, ctx, postgres, "workspace_idempotency_records", []string{
		"actor_user_id", "workspace_id", "operation", "key_digest", "request_digest", "resource_type",
		"resource_id", "created_at", "expires_at",
	})
	assertColumns(t, ctx, postgres, "experience_candidates", []string{
		"id", "workspace_id", "agent_definition_id", "source_agent_version_id", "submitted_by_user_id",
		"submitted_from_device_id", "kind", "skill_name", "schema_version", "dlp_contract_version",
		"content_digest", "bundle_document", "created_at",
	})
	assertColumns(t, ctx, postgres, "experience_candidate_reviews", []string{
		"id", "candidate_id", "workspace_id", "decision", "reviewed_by_user_id", "reason_code",
		"safe_note", "reviewed_at",
	})
	assertColumns(t, ctx, postgres, "organizations", []string{
		"id", "display_name", "status", "revision", "current_policy_snapshot_id", "created_at",
		"updated_at", "archived_at", "dissolved_at",
	})
	assertColumns(t, ctx, postgres, "organization_memberships", []string{
		"organization_id", "user_id", "role", "department_id", "revision", "joined_at", "updated_at",
	})
	assertColumns(t, ctx, postgres, "organization_departments", []string{
		"organization_id", "id", "display_name", "name_key", "status", "revision", "created_at",
		"updated_at", "archived_at",
	})
	assertColumns(t, ctx, postgres, "organization_invitations", []string{
		"id", "organization_id", "token_digest", "created_by_user_id", "status", "accepted_by_user_id",
		"created_at", "expires_at", "accepted_at", "revoked_at",
	})
	assertColumns(t, ctx, postgres, "organization_policy_snapshots", []string{
		"id", "organization_id", "policy_version", "schema_version", "policy_document", "content_digest",
		"issuer", "signing_key_id", "signature", "issued_by_user_id", "created_at",
	})
	assertColumns(t, ctx, postgres, "organization_idempotency_records", []string{
		"actor_user_id", "organization_id", "operation", "key_digest", "request_digest", "resource_type",
		"resource_id", "created_at", "expires_at",
	})
	assertColumns(t, ctx, postgres, "organization_agent_submissions", []string{
		"id", "organization_id", "kind", "definition_id", "base_version_id", "display_name",
		"icon_media_type", "icon_data", "canonical_manifest", "bundle", "manifest_digest",
		"bundle_digest", "content_digest", "submitted_by_user_id", "status", "revision",
		"submitted_at", "terminal_at", "updated_at",
	})
	assertColumns(t, ctx, postgres, "organization_agent_reviews", []string{
		"id", "organization_id", "submission_id", "reviewer_user_id", "decision", "reason_code",
		"safe_note", "organization_policy_snapshot_id", "organization_policy_version",
		"reviewed_content_digest", "reviewed_at",
	})
	assertColumns(t, ctx, postgres, "audit_events", []string{"organization_id"})
	assertColumns(t, ctx, postgres, "users", []string{"administrative_revision"})
	assertColumns(t, ctx, postgres, "admin_operations", []string{
		"operation_id", "idempotency_key_id", "idempotency_key_hmac", "request_fingerprint",
		"service_subject", "actor_admin_id", "approval_id", "request_id", "action", "target_type",
		"target_id", "expected_revision", "result_revision", "status", "error_code", "reason_code",
		"ticket_reference", "created_at", "updated_at", "completed_at",
	})
	assertNoColumns(t, ctx, postgres, "admin_operations", []string{
		"note", "idempotency_key", "email", "phone", "token", "certificate",
	})
	assertColumnNullable(t, ctx, postgres, "experience_candidates", "submitted_by_user_id", true)
	assertColumnNullable(t, ctx, postgres, "experience_candidates", "submitted_from_device_id", true)
	assertColumnNullable(t, ctx, postgres, "experience_candidate_reviews", "reviewed_by_user_id", true)

	for table, trigger := range map[string]string{
		"agent_versions":            "agent_versions_immutable_trigger",
		"policy_snapshots":          "policy_snapshots_immutable_trigger",
		"agent_version_revocations": "agent_version_revocations_immutable_trigger",
		"runtime_binding_records":   "runtime_binding_records_immutable_trigger",
	} {
		assertTriggerExists(t, ctx, postgres, table, trigger)
	}
	assertTriggerExists(t, ctx, postgres, "workspaces", "workspaces_owner_user_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "workspace_invitations", "workspace_invitations_lifecycle_trigger")
	assertTriggerExists(t, ctx, postgres, "experience_candidates", "experience_candidates_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "organizations", "organizations_lifecycle_trigger")
	assertTriggerExists(t, ctx, postgres, "organization_memberships", "organization_memberships_department_active_trigger")
	assertTriggerExists(t, ctx, postgres, "organization_departments", "organization_departments_lifecycle_trigger")
	assertTriggerExists(t, ctx, postgres, "organization_invitations", "organization_invitations_lifecycle_trigger")
	assertTriggerExists(t, ctx, postgres, "organization_policy_snapshots", "organization_policy_snapshots_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submission_variant_trigger")
	assertTriggerDefinitionContains(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submission_variant_trigger", "AFTER INSERT ON")
	assertTriggerExists(t, ctx, postgres, "organization_agent_submissions", "organization_agent_submission_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "organization_agent_reviews", "organization_agent_review_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "organization_agent_reviews", "organization_agent_review_separation_trigger")
	assertTriggerExists(t, ctx, postgres, "platform_agent_policy_snapshots", "platform_agent_policy_snapshot_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "platform_agent_submissions", "platform_agent_submission_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "platform_agent_reviews", "platform_agent_review_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "official_release_revisions", "official_release_revision_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "official_release_audience_accounts", "official_release_audience_immutable_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "official_release_revisions", "official_release_revision_source_constraint_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "installations", "installations_official_source_constraint_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "runtime_binding_records", "runtime_binding_official_source_constraint_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "workspaces", "workspaces_owner_membership_constraint_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "workspace_memberships", "workspace_memberships_owner_constraint_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "organizations", "organizations_owner_membership_constraint_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "organization_memberships", "organization_memberships_owner_constraint_trigger")

	var applied int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if applied != 20 {
		t.Fatalf("applied migration count = %d, want 20", applied)
	}
	var receiptConsumedColumn bool
	if err := postgres.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'verification_challenges'
			  AND column_name = 'receipt_consumed_at'
		)
	`).Scan(&receiptConsumedColumn); err != nil {
		t.Fatalf("check receipt_consumed_at: %v", err)
	}
	if !receiptConsumedColumn {
		t.Fatal("verification_challenges.receipt_consumed_at does not exist")
	}
	var oauthMetadataColumns int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'oauth_requests'
		  AND column_name IN (
			'state_encryption_key_id', 'state_nonce', 'device_display_name', 'device_platform', 'app_version'
		  )
	`).Scan(&oauthMetadataColumns); err != nil {
		t.Fatalf("check OAuth metadata columns: %v", err)
	}
	if oauthMetadataColumns != 5 {
		t.Fatalf("OAuth metadata column count = %d, want 5", oauthMetadataColumns)
	}
	var administrativeDisableColumn bool
	if err := postgres.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'users'
			  AND column_name = 'administratively_disabled'
		)
	`).Scan(&administrativeDisableColumn); err != nil {
		t.Fatalf("check administratively_disabled: %v", err)
	}
	if !administrativeDisableColumn {
		t.Fatal("users.administratively_disabled does not exist")
	}
	var adminAuditColumns int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'audit_events'
		  AND column_name IN ('operator_identity', 'subject_user_id')
	`).Scan(&adminAuditColumns); err != nil {
		t.Fatalf("check restricted audit columns: %v", err)
	}
	if adminAuditColumns != 2 {
		t.Fatalf("restricted audit column count = %d, want 2", adminAuditColumns)
	}
}

func assertColumnNullable(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	column string,
	want bool,
) {
	t.Helper()
	var nullable string
	if err := postgres.QueryRow(ctx, `
		SELECT is_nullable
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
	`, table, column).Scan(&nullable); err != nil {
		t.Fatalf("read nullable state for %s.%s: %v", table, column, err)
	}
	got := nullable == "YES"
	if got != want {
		t.Fatalf("nullable state for %s.%s = %t, want %t", table, column, got, want)
	}
}

func TestWorkspaceOwnerInvariantRejectsMissingOrMismatchedOwnerAtCommit(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}

	ownerID := uuid.New()
	otherID := uuid.New()
	now := time.Date(2026, 7, 20, 8, 30, 0, 0, time.UTC)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, created_at, updated_at)
		VALUES ($1, 'active', $3, $3), ($2, 'active', $3, $3)
	`, ownerID, otherID, now); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	defer func() {
		_, _ = postgres.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1, $2)`, ownerID, otherID)
	}()
	defer func() {
		_, _ = postgres.Exec(context.Background(), `DELETE FROM workspaces WHERE owner_user_id = $1`, ownerID)
	}()

	validWorkspaceID := uuid.New()
	valid, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin valid workspace transaction: %v", err)
	}
	defer func() { _ = valid.Rollback(context.Background()) }()
	if _, err := valid.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Valid workspace', 'active', 1, $3, $3)
	`, validWorkspaceID, ownerID, now); err != nil {
		t.Fatalf("insert valid workspace: %v", err)
	}
	if _, err := valid.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, validWorkspaceID, ownerID, now); err != nil {
		t.Fatalf("insert valid Owner membership: %v", err)
	}
	if err := valid.Commit(ctx); err != nil {
		t.Fatalf("commit valid workspace: %v", err)
	}

	if _, err := postgres.Exec(ctx, `UPDATE workspaces SET owner_user_id = $2 WHERE id = $1`, validWorkspaceID, otherID); err == nil {
		t.Fatal("owner_user_id update succeeded, want immutable Owner rejection")
	}

	missingOwner, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin missing-Owner transaction: %v", err)
	}
	defer func() { _ = missingOwner.Rollback(context.Background()) }()
	if _, err := missingOwner.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Missing Owner', 'active', 1, $3, $3)
	`, uuid.New(), ownerID, now); err != nil {
		t.Fatalf("insert missing-Owner workspace before deferred check: %v", err)
	}
	if err := missingOwner.Commit(ctx); err == nil {
		t.Fatal("workspace without Owner membership committed")
	}

	mismatchedOwner, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin mismatched-Owner transaction: %v", err)
	}
	defer func() { _ = mismatchedOwner.Rollback(context.Background()) }()
	mismatchedWorkspaceID := uuid.New()
	if _, err := mismatchedOwner.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Mismatched Owner', 'active', 1, $3, $3)
	`, mismatchedWorkspaceID, ownerID, now); err != nil {
		t.Fatalf("insert mismatched workspace: %v", err)
	}
	if _, err := mismatchedOwner.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, mismatchedWorkspaceID, otherID, now); err != nil {
		t.Fatalf("insert mismatched Owner membership before deferred check: %v", err)
	}
	if err := mismatchedOwner.Commit(ctx); err == nil {
		t.Fatal("workspace with mismatched Owner membership committed")
	}
}

func TestOrganizationFoundationDatabaseInvariants(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}

	now := time.Date(2026, 7, 21, 2, 0, 0, 0, time.UTC)
	users := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for _, userID := range users {
		if _, err := postgres.Exec(ctx, `
			INSERT INTO users (id, status, created_at, updated_at)
			VALUES ($1, 'active', $2, $2)
		`, userID, now); err != nil {
			t.Fatalf("insert user: %v", err)
		}
	}

	t.Run("active organization requires exactly one Owner at commit", func(t *testing.T) {
		tx, err := postgres.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		insertOrganizationWithoutMembership(t, ctx, tx, uuid.New(), users[0], uuid.New(), "No owner", "active", now)
		if err := tx.Commit(ctx); err == nil {
			t.Fatal("organization without Owner committed")
		}
	})

	t.Run("partial index rejects two Owners", func(t *testing.T) {
		tx, err := postgres.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		organizationID := uuid.New()
		insertOrganizationFixture(t, ctx, tx, organizationID, users[0], uuid.New(), "Two owners", "active", now)
		if _, err := tx.Exec(ctx, `
			INSERT INTO organization_memberships (
				organization_id, user_id, role, revision, joined_at, updated_at
			) VALUES ($1, $2, 'owner', 1, $3, $3)
		`, organizationID, users[1], now); err == nil {
			t.Fatal("second Owner membership was accepted")
		}
	})

	organizationA := uuid.New()
	policyA := uuid.New()
	createOrganizationFixture(t, ctx, postgres, organizationA, users[0], policyA, "Organization A", "active", now)
	organizationB := uuid.New()
	createOrganizationFixture(t, ctx, postgres, organizationB, users[1], uuid.New(), "Organization B", "active", now)

	t.Run("current policy must belong to the same Organization", func(t *testing.T) {
		tx, err := postgres.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		organizationID := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO organizations (
				id, display_name, status, revision, current_policy_snapshot_id,
				created_at, updated_at
			) VALUES ($1, 'Cross policy', 'active', 1, $2, $3, $3)
		`, organizationID, policyA, now); err != nil {
			t.Fatalf("insert Organization with deferred cross-policy pointer: %v", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO organization_memberships (
				organization_id, user_id, role, revision, joined_at, updated_at
			) VALUES ($1, $2, 'owner', 1, $3, $3)
		`, organizationID, users[2], now); err != nil {
			t.Fatalf("insert Owner membership: %v", err)
		}
		if err := tx.Commit(ctx); err == nil {
			t.Fatal("cross-Organization current policy committed")
		}
	})

	t.Run("membership cannot reference another Organization Department", func(t *testing.T) {
		departmentID := uuid.New()
		if _, err := postgres.Exec(ctx, `
			INSERT INTO organization_departments (
				organization_id, id, display_name, name_key, status, revision, created_at, updated_at
			) VALUES ($1, $2, 'Research', 'research', 'active', 1, $3, $3)
		`, organizationA, departmentID, now); err != nil {
			t.Fatalf("insert Department: %v", err)
		}
		if _, err := postgres.Exec(ctx, `
			INSERT INTO organization_memberships (
				organization_id, user_id, role, department_id, revision, joined_at, updated_at
			) VALUES ($1, $2, 'member', $3, 1, $4, $4)
		`, organizationB, users[2], departmentID, now); err == nil {
			t.Fatal("cross-Organization Department assignment was accepted")
		}
	})

	t.Run("dissolved Organization cannot retain memberships", func(t *testing.T) {
		organizationID := uuid.New()
		createOrganizationFixture(t, ctx, postgres, organizationID, users[3], uuid.New(), "Archived", "archived", now)
		tx, err := postgres.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, `
			UPDATE organizations
			SET status = 'dissolved', dissolved_at = $2, revision = revision + 1, updated_at = $2
			WHERE id = $1
		`, organizationID, now.Add(time.Hour)); err != nil {
			t.Fatalf("update Organization to dissolved: %v", err)
		}
		if err := tx.Commit(ctx); err == nil {
			t.Fatal("dissolved Organization with membership committed")
		}
	})

	t.Run("invitation terminal state cannot transition", func(t *testing.T) {
		invitationID := uuid.New()
		tokenDigest := sha256.Sum256(invitationID[:])
		if _, err := postgres.Exec(ctx, `
			INSERT INTO organization_invitations (
				id, organization_id, token_digest, created_by_user_id, status,
				created_at, expires_at
			) VALUES ($1, $2, $3, $4, 'pending', $5::timestamptz, $5::timestamptz + INTERVAL '7 days')
		`, invitationID, organizationA, tokenDigest[:], users[0], now); err != nil {
			t.Fatalf("insert invitation: %v", err)
		}
		if _, err := postgres.Exec(ctx, `
			UPDATE organization_invitations
			SET status = 'revoked', revoked_at = $2
			WHERE id = $1
		`, invitationID, now.Add(time.Minute)); err != nil {
			t.Fatalf("revoke invitation: %v", err)
		}
		if _, err := postgres.Exec(ctx, `
			UPDATE organization_invitations
			SET status = 'pending', revoked_at = NULL
			WHERE id = $1
		`, invitationID); err == nil {
			t.Fatal("terminal invitation returned to pending")
		}
	})

	t.Run("policy snapshots reject update and delete", func(t *testing.T) {
		if _, err := postgres.Exec(ctx, `
			UPDATE organization_policy_snapshots SET policy_version = 2 WHERE id = $1
		`, policyA); err == nil {
			t.Fatal("immutable policy snapshot was updated")
		}
		if _, err := postgres.Exec(ctx, `
			DELETE FROM organization_policy_snapshots WHERE id = $1
		`, policyA); err == nil {
			t.Fatal("immutable policy snapshot was deleted")
		}
	})
}

func createOrganizationFixture(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	organizationID uuid.UUID,
	ownerID uuid.UUID,
	policyID uuid.UUID,
	displayName string,
	status string,
	now time.Time,
) {
	t.Helper()
	tx, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Organization fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	insertOrganizationFixture(t, ctx, tx, organizationID, ownerID, policyID, displayName, status, now)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit Organization fixture: %v", err)
	}
}

func insertOrganizationFixture(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	ownerID uuid.UUID,
	policyID uuid.UUID,
	displayName string,
	status string,
	now time.Time,
) {
	t.Helper()
	insertOrganizationWithoutMembership(t, ctx, tx, organizationID, ownerID, policyID, displayName, status, now)
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_memberships (
			organization_id, user_id, role, revision, joined_at, updated_at
		) VALUES ($1, $2, 'owner', 1, $3, $3)
	`, organizationID, ownerID, now); err != nil {
		t.Fatalf("insert Owner membership: %v", err)
	}
}

func insertOrganizationWithoutMembership(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	ownerID uuid.UUID,
	policyID uuid.UUID,
	displayName string,
	status string,
	now time.Time,
) {
	t.Helper()
	archivedAt := any(nil)
	if status == "archived" {
		archivedAt = now
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (
			id, display_name, status, revision, current_policy_snapshot_id,
			created_at, updated_at, archived_at
		) VALUES ($1, $2, $3, 1, $4, $5, $5, $6)
	`, organizationID, displayName, status, policyID, now, archivedAt); err != nil {
		t.Fatalf("insert Organization: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document,
			content_digest, issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES ($1, $2, 1, 1, '{"schema_version":1}'::jsonb, $3,
			'https://accounts.example.com', 'organization-test-v1', $4, $5, $6)
	`, policyID, organizationID, bytes.Repeat([]byte{22}, 32), bytes.Repeat([]byte{23}, 64), ownerID, now); err != nil {
		t.Fatalf("insert policy snapshot: %v", err)
	}
}

func TestWorkspaceInvitationTerminalStateCannotTransitionAgain(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}

	ownerID := uuid.New()
	workspaceID := uuid.New()
	invitationID := uuid.New()
	now := time.Date(2026, 7, 20, 8, 45, 0, 0, time.UTC)
	if _, err := postgres.Exec(ctx, `INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)`, ownerID, now); err != nil {
		t.Fatalf("insert invitation owner: %v", err)
	}
	defer func() { _, _ = postgres.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, ownerID) }()
	defer func() {
		_, _ = postgres.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, workspaceID)
	}()

	tx, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin invitation fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Invitation workspace', 'active', 1, $3, $3)
	`, workspaceID, ownerID, now); err != nil {
		t.Fatalf("insert invitation workspace: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, workspaceID, ownerID, now); err != nil {
		t.Fatalf("insert invitation Owner membership: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit invitation workspace: %v", err)
	}

	if _, err := postgres.Exec(ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, invitationID, workspaceID, bytes.Repeat([]byte{0x42}, 32), ownerID, now, now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert pending invitation: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		UPDATE workspace_invitations
		SET status = 'accepted', accepted_by_user_id = $2, accepted_at = $3
		WHERE id = $1
	`, invitationID, ownerID, now.Add(time.Hour)); err != nil {
		t.Fatalf("accept pending invitation: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		UPDATE workspace_invitations
		SET status = 'revoked', accepted_by_user_id = NULL, accepted_at = NULL, revoked_at = $2
		WHERE id = $1
	`, invitationID, now.Add(2*time.Hour)); err == nil {
		t.Fatal("accepted invitation transitioned to revoked")
	}
}

func assertColumns(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, table string, expected []string) {
	t.Helper()
	rows, err := postgres.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
	`, table)
	if err != nil {
		t.Fatalf("read columns for %s: %v", table, err)
	}
	defer rows.Close()
	actual := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan column for %s: %v", table, err)
		}
		actual[column] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns for %s: %v", table, err)
	}
	for _, column := range expected {
		if _, ok := actual[column]; !ok {
			t.Errorf("table %s is missing column %s", table, column)
		}
	}
}

func assertNoColumns(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, table string, forbidden []string) {
	t.Helper()
	rows, err := postgres.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
	`, table)
	if err != nil {
		t.Fatalf("read columns for %s: %v", table, err)
	}
	defer rows.Close()

	forbiddenSet := make(map[string]struct{}, len(forbidden))
	for _, column := range forbidden {
		forbiddenSet[column] = struct{}{}
	}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan column for %s: %v", table, err)
		}
		if _, found := forbiddenSet[column]; found {
			t.Errorf("table %s contains forbidden column %s", table, column)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns for %s: %v", table, err)
	}
}

func assertCheckConstraintContains(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
	expected string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname = $1 AND c.conname = $2 AND c.contype = 'c'
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read check constraint %s: %v", name, err)
	}
	if !strings.Contains(definition, expected) {
		t.Fatalf("check constraint %s = %q, want it to contain %q", name, definition, expected)
	}
}

func assertCheckConstraintExcludes(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
	forbidden string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname = $1 AND c.conname = $2 AND c.contype = 'c'
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read check constraint %s: %v", name, err)
	}
	if strings.Contains(definition, forbidden) {
		t.Fatalf("check constraint %s = %q, want it to exclude %q", name, definition, forbidden)
	}
}

func assertTriggerExists(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, table, name string) {
	t.Helper()
	var enabled string
	err := postgres.QueryRow(ctx, `
		SELECT tg.tgenabled::text
		FROM pg_trigger tg
		JOIN pg_class tbl ON tbl.oid = tg.tgrelid
		WHERE tbl.relname = $1 AND tg.tgname = $2 AND NOT tg.tgisinternal
	`, table, name).Scan(&enabled)
	if err != nil {
		t.Fatalf("read trigger %s: %v", name, err)
	}
	if enabled != "O" {
		t.Fatalf("trigger %s enabled state = %q, want O", name, enabled)
	}
}

func assertTriggerDefinitionContains(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
	expected string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_triggerdef(tg.oid)
		FROM pg_trigger tg
		JOIN pg_class tbl ON tbl.oid = tg.tgrelid
		WHERE tbl.relname = $1 AND tg.tgname = $2 AND NOT tg.tgisinternal
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read trigger definition %s: %v", name, err)
	}
	if !strings.Contains(definition, expected) {
		t.Fatalf("trigger definition %s = %q, want it to contain %q", name, definition, expected)
	}
}

func assertForeignKeyConstraintContains(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
	expected string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class tbl ON tbl.oid = c.conrelid
		WHERE tbl.relname = $1 AND c.conname = $2 AND c.contype = 'f'
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read foreign key constraint %s: %v", name, err)
	}
	if !strings.Contains(definition, expected) {
		t.Fatalf("foreign key constraint %s = %q, want it to contain %q", name, definition, expected)
	}
}

func assertIndexDefinitionContains(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	name string,
	expected ...string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_indexdef(i.indexrelid)
		FROM pg_index i
		JOIN pg_class idx ON idx.oid = i.indexrelid
		WHERE idx.relname = $1
	`, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read index %s: %v", name, err)
	}
	for _, fragment := range expected {
		if !strings.Contains(strings.ToLower(definition), strings.ToLower(fragment)) {
			t.Fatalf("index %s = %q, want it to contain %q", name, definition, fragment)
		}
	}
}

func assertDeferredConstraintTrigger(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
) {
	t.Helper()
	var deferrable bool
	var initiallyDeferred bool
	err := postgres.QueryRow(ctx, `
		SELECT tg.tgdeferrable, tg.tginitdeferred
		FROM pg_trigger tg
		JOIN pg_class tbl ON tbl.oid = tg.tgrelid
		WHERE tbl.relname = $1 AND tg.tgname = $2 AND NOT tg.tgisinternal
	`, table, name).Scan(&deferrable, &initiallyDeferred)
	if err != nil {
		t.Fatalf("read deferred constraint trigger %s: %v", name, err)
	}
	if !deferrable || !initiallyDeferred {
		t.Fatalf(
			"constraint trigger %s deferrable/initially deferred = %t/%t, want true/true",
			name,
			deferrable,
			initiallyDeferred,
		)
	}
}

func TestApplyMigrationsSerializesConcurrentRunners(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()

	errorsByRunner := make(chan error, 2)
	var runners sync.WaitGroup
	for range 2 {
		runners.Add(1)
		go func() {
			defer runners.Done()
			errorsByRunner <- ApplyMigrations(ctx, postgres)
		}()
	}
	runners.Wait()
	close(errorsByRunner)
	for err := range errorsByRunner {
		if err != nil {
			t.Errorf("concurrent ApplyMigrations() error = %v", err)
		}
	}
}

func assertUniqueConstraint(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, table, name string, columns []string) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname = $1 AND c.conname = $2
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read constraint %s: %v", name, err)
	}
	if !strings.HasPrefix(definition, "UNIQUE") {
		t.Fatalf("constraint %s = %q, want UNIQUE", name, definition)
	}
	for _, column := range columns {
		if !strings.Contains(definition, column) {
			t.Errorf("constraint %s = %q, missing %s", name, definition, column)
		}
	}
}
