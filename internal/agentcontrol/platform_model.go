package agentcontrol

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type PlatformAdminActor struct {
	AdminID   uuid.UUID
	Role      string
	RequestID string
}

type OfficialChannel string

const (
	OfficialChannelInternal   OfficialChannel = "internal"
	OfficialChannelStable     OfficialChannel = "stable"
	officialBucketAlgorithmV1                 = "1"
)

type OfficialReleaseState string

const (
	OfficialReleaseStateActive OfficialReleaseState = "active"
	OfficialReleaseStatePaused OfficialReleaseState = "paused"
)

type OfficialReleaseAction string

const (
	OfficialReleaseActionInitial       OfficialReleaseAction = "initial"
	OfficialReleaseActionActivate      OfficialReleaseAction = "activate"
	OfficialReleaseActionRolloutUpdate OfficialReleaseAction = "rollout_update"
	OfficialReleaseActionPause         OfficialReleaseAction = "pause"
	OfficialReleaseActionResume        OfficialReleaseAction = "resume"
	OfficialReleaseActionRollback      OfficialReleaseAction = "rollback"
)

type OfficialProductSelector struct {
	Scope           OwnerScope
	PersonalSpaceID uuid.UUID
	WorkspaceID     uuid.UUID
	OrganizationID  uuid.UUID
}

type OfficialEligibilityContext struct {
	Channel        OfficialChannel
	DesktopVersion string
	Selector       OfficialProductSelector
}

type OfficialReleaseRevision struct {
	ID                       uuid.UUID
	ReleaseID                uuid.UUID
	RevisionNumber           int64
	AgentVersionID           uuid.UUID
	State                    OfficialReleaseState
	RolloutBasisPoints       int
	MinimumDesktopVersion    string
	BucketAlgorithmVersion   string
	RolloutKeyID             string
	Action                   OfficialReleaseAction
	PreviousRevisionID       uuid.UUID
	RollbackTargetRevisionID uuid.UUID
	ActorAdminID             uuid.UUID
	ActorAdminRole           string
	ReasonCode               string
	TicketReference          string
	AllowlistedUserIDs       []uuid.UUID
	CreatedAt                time.Time
}

type OfficialRelease struct {
	ID                uuid.UUID
	PlatformID        uuid.UUID
	DefinitionID      uuid.UUID
	Channel           OfficialChannel
	CurrentRevisionID uuid.UUID
	HeadRevision      int64
	CurrentRevision   OfficialReleaseRevision
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Replayed          bool
}

type PlatformOperationEvidence struct {
	ReasonCode      string
	TicketReference string
	IdempotencyKey  string
}

type ActivateOfficialReleaseCommand struct {
	ReleaseID             uuid.UUID
	VersionID             uuid.UUID
	ExpectedHeadRevision  int64
	RolloutBasisPoints    int
	MinimumDesktopVersion string
	AllowlistedUserIDs    []uuid.UUID
	Evidence              PlatformOperationEvidence
}

type UpdateOfficialRolloutCommand struct {
	ReleaseID             uuid.UUID
	ExpectedHeadRevision  int64
	RolloutBasisPoints    int
	MinimumDesktopVersion string
	AllowlistedUserIDs    []uuid.UUID
	Evidence              PlatformOperationEvidence
}

type RollbackOfficialReleaseCommand struct {
	ReleaseID               uuid.UUID
	TargetVersionID         uuid.UUID
	TargetReleaseRevisionID uuid.UUID
	ExpectedHeadRevision    int64
	ApprovalID              uuid.UUID
	Evidence                PlatformOperationEvidence
}

type ChangeOfficialReleaseStateCommand struct {
	ReleaseID            uuid.UUID
	ExpectedHeadRevision int64
	Evidence             PlatformOperationEvidence
}

type OfficialManagedTarget struct {
	PlatformID        uuid.UUID
	ReleaseID         uuid.UUID
	ReleaseRevisionID uuid.UUID
	DefinitionID      uuid.UUID
	VersionID         uuid.UUID
	Channel           OfficialChannel
	HeadRevision      int64
}

type OfficialEligibilityRecord struct {
	AccountDeviceActive  bool
	PlatformActive       bool
	ChannelEntitled      bool
	ContextAuthorized    bool
	ContextPolicyAllowed bool
	UserAllowlisted      bool
	Release              OfficialRelease
	Revision             OfficialReleaseRevision
}

type OfficialReleaseMutationRepositoryCommand struct {
	RevisionID              uuid.UUID
	PlatformID              uuid.UUID
	ReleaseID               uuid.UUID
	ExpectedHeadRevision    int64
	Actor                   PlatformAdminActor
	Action                  OfficialReleaseAction
	VersionID               uuid.UUID
	TargetReleaseRevisionID uuid.UUID
	ApprovalID              uuid.UUID
	RolloutBasisPoints      int
	MinimumDesktopVersion   string
	RolloutKeyID            string
	AllowlistedUserIDs      []uuid.UUID
	ReasonCode              string
	TicketReference         string
	Idempotency             IdempotencyEvidence
	Audit                   AuditEvidence
	ChangedAt               time.Time
}

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
	ErrPlatformPublicationDLPBlocked     = errors.New("official platform publication dlp blocked")
)
