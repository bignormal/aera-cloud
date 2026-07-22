package agentcontrol

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestPlatformOwnerRequiresOnlyPlatformID(t *testing.T) {
	platformID := uuid.New()
	owner := AssetOwner{Scope: OwnerScopePlatform, PlatformID: platformID}
	if err := owner.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if got := owner.Key(); got != platformID {
		t.Fatalf("Key() = %s, want %s", got, platformID)
	}

	invalid := []AssetOwner{
		{Scope: OwnerScopePlatform},
		{Scope: OwnerScopePlatform, PlatformID: platformID, PersonalSpaceID: uuid.New(), UserID: uuid.New()},
		{Scope: OwnerScopePlatform, PlatformID: platformID, WorkspaceID: uuid.New()},
		{Scope: OwnerScopePlatform, PlatformID: platformID, OrganizationID: uuid.New()},
	}
	for index, candidate := range invalid {
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidAgentContent) {
			t.Fatalf("invalid PLATFORM owner %d error = %v", index, err)
		}
	}
}

func TestPlatformModelUsesFixedChannelsAndErrors(t *testing.T) {
	if OfficialChannelInternal != "internal" || OfficialChannelStable != "stable" {
		t.Fatalf("official channels = %q, %q", OfficialChannelInternal, OfficialChannelStable)
	}

	actor := PlatformAdminActor{AdminID: uuid.New(), Role: "developer", RequestID: "request-1"}
	if actor.AdminID == uuid.Nil || actor.Role != "developer" || actor.RequestID != "request-1" {
		t.Fatalf("PlatformAdminActor = %#v", actor)
	}

	errorsByCode := map[string]error{
		"official_agent_not_eligible":          ErrOfficialAgentNotEligible,
		"official_release_paused":              ErrOfficialReleasePaused,
		"official_release_revision_conflict":   ErrOfficialReleaseRevisionConflict,
		"official_client_version_unsupported":  ErrOfficialClientVersionUnsupported,
		"official_installation_policy_blocked": ErrOfficialInstallationPolicyBlocked,
		"official_submission_self_review":      ErrOfficialSubmissionSelfReview,
		"official_submission_conflict":         ErrOfficialSubmissionConflict,
		"official_rollout_invalid":             ErrOfficialRolloutInvalid,
		"official_version_integrity_failed":    ErrOfficialVersionIntegrityFailed,
		"official_managed_update_conflict":     ErrOfficialManagedUpdateConflict,
		"cloud_unavailable":                    ErrCloudUnavailable,
	}
	for code, err := range errorsByCode {
		if err == nil || err.Error() != code {
			t.Fatalf("error for %q = %v", code, err)
		}
	}
}
