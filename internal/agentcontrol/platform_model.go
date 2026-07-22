package agentcontrol

import (
	"errors"

	"github.com/google/uuid"
)

type PlatformAdminActor struct {
	AdminID   uuid.UUID
	Role      string
	RequestID string
}

type OfficialChannel string

const (
	OfficialChannelInternal OfficialChannel = "internal"
	OfficialChannelStable   OfficialChannel = "stable"
)

var (
	ErrOfficialAgentNotEligible          = errors.New("official_agent_not_eligible")
	ErrOfficialReleasePaused             = errors.New("official_release_paused")
	ErrOfficialReleaseRevisionConflict   = errors.New("official_release_revision_conflict")
	ErrOfficialClientVersionUnsupported  = errors.New("official_client_version_unsupported")
	ErrOfficialInstallationPolicyBlocked = errors.New("official_installation_policy_blocked")
	ErrOfficialSubmissionSelfReview      = errors.New("official_submission_self_review")
	ErrOfficialSubmissionConflict        = errors.New("official_submission_conflict")
	ErrOfficialRolloutInvalid            = errors.New("official_rollout_invalid")
	ErrOfficialVersionIntegrityFailed    = errors.New("official_version_integrity_failed")
	ErrOfficialManagedUpdateConflict     = errors.New("official_managed_update_conflict")
	ErrCloudUnavailable                  = errors.New("cloud_unavailable")
)
