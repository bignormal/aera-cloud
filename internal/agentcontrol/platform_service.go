package agentcontrol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	platformDraftPageLimit      = 50
	platformDraftPageLimitMax   = 100
	platformPolicySchemaVersion = 1
)

var (
	ErrPlatformForbidden          = errors.New("official platform operation forbidden")
	platformReasonPattern         = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	platformKeyPattern            = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	platformRolloutKeyPattern     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	platformServiceSubjectPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
)

type platformAction string

const (
	platformActionRead         platformAction = "read"
	platformActionApprovedRead platformAction = "approved_read"
	platformActionDraftWrite   platformAction = "draft_write"
	platformActionReview       platformAction = "review"
	platformActionReleaseWrite platformAction = "release_write"
	platformActionRollback     platformAction = "rollback"
)

func platformRoleAllowed(role string, action platformAction) bool {
	switch action {
	case platformActionRead:
		return role == "developer" || role == "super_admin" || role == "auditor"
	case platformActionApprovedRead:
		return role == "developer" || role == "super_admin" || role == "operator" || role == "auditor"
	case platformActionDraftWrite:
		return role == "developer"
	case platformActionReview:
		return role == "super_admin"
	case platformActionReleaseWrite:
		return role == "operator"
	case platformActionRollback:
		return role == "super_admin"
	default:
		return false
	}
}

type PlatformDraftKind string

const (
	PlatformDraftInitial PlatformDraftKind = "initial"
	PlatformDraftNext    PlatformDraftKind = "next"
)

type PlatformDraftStatus string

const (
	PlatformDraftActive   PlatformDraftStatus = "active"
	PlatformDraftArchived PlatformDraftStatus = "archived"
)

type PlatformSubmissionStatus string

const (
	PlatformSubmissionPending    PlatformSubmissionStatus = "pending"
	PlatformSubmissionApproved   PlatformSubmissionStatus = "approved"
	PlatformSubmissionRejected   PlatformSubmissionStatus = "rejected"
	PlatformSubmissionWithdrawn  PlatformSubmissionStatus = "withdrawn"
	PlatformSubmissionSuperseded PlatformSubmissionStatus = "superseded"
)

type PlatformReviewDecision string

const (
	PlatformReviewApprove PlatformReviewDecision = "approve"
	PlatformReviewReject  PlatformReviewDecision = "reject"
)

type PlatformDraftPackage struct {
	DefinitionID  uuid.UUID
	BaseVersionID uuid.UUID
	Kind          PlatformDraftKind
	DisplayName   string
	IconMediaType string
	IconData      []byte
	Manifest      AgentManifestV1
	Bundle        VersionBundleV1
}

type CanonicalPlatformDraft struct {
	Package        PlatformDraftPackage
	ManifestDigest [sha256.Size]byte
	BundleDigest   [sha256.Size]byte
	ContentDigest  [sha256.Size]byte
}

func CanonicalizePlatformDraft(input PlatformDraftPackage) (CanonicalPlatformDraft, error) {
	displayName := strings.TrimSpace(input.DisplayName)
	if input.DefinitionID == uuid.Nil || !validPlatformDisplayName(displayName) ||
		(input.IconMediaType == "") != (len(input.IconData) == 0) ||
		(input.IconMediaType != "" && ValidateIcon(input.IconMediaType, input.IconData) != nil) {
		return CanonicalPlatformDraft{}, ErrInvalidAgentContent
	}
	switch input.Kind {
	case PlatformDraftInitial:
		if input.BaseVersionID != uuid.Nil {
			return CanonicalPlatformDraft{}, ErrInvalidAgentContent
		}
	case PlatformDraftNext:
		if input.BaseVersionID == uuid.Nil {
			return CanonicalPlatformDraft{}, ErrInvalidAgentContent
		}
	default:
		return CanonicalPlatformDraft{}, ErrInvalidAgentContent
	}

	version, err := CanonicalizeVersion(input.Manifest, input.Bundle)
	if err != nil {
		return CanonicalPlatformDraft{}, err
	}
	var manifest AgentManifestV1
	if err := decodeStrictJSON(version.ManifestJSON, &manifest); err != nil {
		return CanonicalPlatformDraft{}, ErrInvalidAgentContent
	}
	var bundle VersionBundleV1
	if err := decodeStrictJSON(version.BundleJSON, &bundle); err != nil {
		return CanonicalPlatformDraft{}, ErrInvalidAgentContent
	}
	return CanonicalPlatformDraft{
		Package: PlatformDraftPackage{
			DefinitionID: input.DefinitionID, BaseVersionID: input.BaseVersionID, Kind: input.Kind,
			DisplayName: displayName, IconMediaType: input.IconMediaType,
			IconData: bytes.Clone(input.IconData), Manifest: manifest, Bundle: bundle,
		},
		ManifestDigest: version.ManifestDigest,
		BundleDigest:   version.BundleDigest,
		ContentDigest:  version.ContentDigest,
	}, nil
}

type PlatformDefinitionReservation struct {
	ID               uuid.UUID
	PlatformID       uuid.UUID
	DisplayName      string
	IconMediaType    string
	IconData         []byte
	Status           string
	CreatedByAdminID uuid.UUID
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Replayed         bool
}

type PlatformDefinitionDetail struct {
	Definition       Definition
	PlatformID       uuid.UUID
	CreatedByAdminID uuid.UUID
}

type PlatformAgentDraft struct {
	ID                uuid.UUID
	PlatformID        uuid.UUID
	DefinitionID      uuid.UUID
	BaseVersionID     uuid.UUID
	Kind              PlatformDraftKind
	DisplayName       string
	IconMediaType     string
	IconData          []byte
	Manifest          AgentManifestV1
	Bundle            VersionBundleV1
	ManifestDigest    [sha256.Size]byte
	BundleDigest      [sha256.Size]byte
	ContentDigest     [sha256.Size]byte
	Revision          int64
	Status            PlatformDraftStatus
	LastEditorAdminID uuid.UUID
	LastEditorRole    string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Replayed          bool
}

type PlatformDraftValidation struct {
	DraftID       uuid.UUID
	DraftRevision int64
	ContentDigest [sha256.Size]byte
	DLPVersion    string
	Valid         bool
	Findings      []ExperienceCandidateFinding
}

type PlatformAgentReview struct {
	ID                       uuid.UUID
	PlatformID               uuid.UUID
	SubmissionID             uuid.UUID
	ReviewerAdminID          uuid.UUID
	ReviewerRole             string
	Decision                 PlatformReviewDecision
	ReasonCode               string
	SafeNote                 string
	PlatformPolicySnapshotID uuid.UUID
	PlatformPolicyVersion    int64
	ReviewedContentDigest    [sha256.Size]byte
	ReviewedAt               time.Time
}

type PlatformAgentSubmission struct {
	ID                 uuid.UUID
	PlatformID         uuid.UUID
	DraftID            uuid.UUID
	DraftRevision      int64
	DefinitionID       uuid.UUID
	BaseVersionID      uuid.UUID
	Kind               PlatformDraftKind
	DisplayName        string
	IconMediaType      string
	IconData           []byte
	Manifest           AgentManifestV1
	Bundle             VersionBundleV1
	ManifestDigest     [sha256.Size]byte
	BundleDigest       [sha256.Size]byte
	ContentDigest      [sha256.Size]byte
	SubmittedByAdminID uuid.UUID
	SubmittedByRole    string
	Status             PlatformSubmissionStatus
	Revision           int64
	SubmittedAt        time.Time
	TerminalAt         *time.Time
	UpdatedAt          time.Time
	Review             *PlatformAgentReview
	Replayed           bool
}

type PlatformAgentPolicyV1 struct {
	SchemaVersion            int               `json:"schema_version"`
	ManifestSchemaVersion    int               `json:"manifest_schema_version"`
	DLPVersion               string            `json:"dlp_version"`
	ModelConstraintMode      string            `json:"model_constraint_mode"`
	ToolConstraintMode       string            `json:"tool_constraint_mode"`
	RuntimeCompatibilityMode string            `json:"runtime_compatibility_mode"`
	DependencyMode           string            `json:"dependency_mode"`
	PermittedChannels        []OfficialChannel `json:"permitted_channels"`
	MaximumAssetCount        int               `json:"maximum_asset_count"`
	MaximumAssetBytes        int               `json:"maximum_asset_bytes"`
	MaximumBundleBytes       int               `json:"maximum_bundle_bytes"`
	MaximumManifestBytes     int               `json:"maximum_manifest_bytes"`
	MaximumIconBytes         int               `json:"maximum_icon_bytes"`
	MaximumRolloutBasisPts   int               `json:"maximum_rollout_basis_points"`
}

func DefaultPlatformAgentPolicyV1() PlatformAgentPolicyV1 {
	return PlatformAgentPolicyV1{
		SchemaVersion: platformPolicySchemaVersion, ManifestSchemaVersion: 1,
		DLPVersion:               AgentPublicationDLPVersion,
		ModelConstraintMode:      "manifest_allowlist",
		ToolConstraintMode:       "manifest_allowlist",
		RuntimeCompatibilityMode: "strict_semver",
		DependencyMode:           "immutable_versions",
		PermittedChannels:        []OfficialChannel{OfficialChannelInternal, OfficialChannelStable},
		MaximumAssetCount:        MaxAssetCount, MaximumAssetBytes: MaxAssetBytes,
		MaximumBundleBytes: MaxBundleBytes, MaximumManifestBytes: MaxManifestBytes,
		MaximumIconBytes: MaxIconBytes, MaximumRolloutBasisPts: 10000,
	}
}

type PlatformPolicySnapshot struct {
	ID              uuid.UUID
	PlatformID      uuid.UUID
	Version         int64
	CanonicalPolicy []byte
	PolicyDigest    [sha256.Size]byte
	SigningKeyID    string
	Signature       []byte
	CreatedAt       time.Time
}

type PlatformPolicyMaterial struct {
	ID              uuid.UUID
	Version         int64
	CanonicalPolicy []byte
	PolicyDigest    [sha256.Size]byte
	SigningKeyID    string
	Signature       []byte
}

type PageRequest struct {
	Limit int
	After uuid.UUID
}

type PlatformDefinitionPage struct {
	Items []PlatformDefinitionDetail
	Next  uuid.UUID
}

type PlatformDraftPage struct {
	Items []PlatformAgentDraft
	Next  uuid.UUID
}

type PlatformSubmissionFilter struct {
	Status PlatformSubmissionStatus
	Page   PageRequest
}

type PlatformSubmissionPage struct {
	Items []PlatformAgentSubmission
	Next  uuid.UUID
}

type PlatformVersionPage struct {
	Items []Version
	Next  uuid.UUID
}

type OfficialReleasePage struct {
	Items []OfficialRelease
	Next  uuid.UUID
}

// OfficialDeliveryVerificationSummary contains only the operator-safe delivery
// view for the current revision of one official release.
type OfficialDeliveryVerificationSummary struct {
	ReleaseID uuid.UUID
	Stages    []OfficialDeliveryVerificationStage
}

// OfficialDeliveryTarget binds one approved submission to its immutable Version
// and the current Release revisions that still reference that Version.
type OfficialDeliveryTarget struct {
	SubmissionID  uuid.UUID
	DefinitionID  uuid.UUID
	VersionID     uuid.UUID
	ContentDigest [sha256.Size]byte
	Releases      []OfficialDeliveryTargetRelease
}

type OfficialDeliveryTargetRelease struct {
	ID                uuid.UUID
	CurrentRevisionID uuid.UUID
	VersionID         uuid.UUID
	Channel           OfficialChannel
	State             OfficialReleaseState
}

// OfficialDeliveryVerificationStage aggregates one verification stage without
// retaining a Cloud user, device, Installation, or Desktop-local identifier.
type OfficialDeliveryVerificationStage struct {
	Status            OfficialAgentDeliveryVerificationStatus
	ErrorCode         string
	ReleaseRevisionID uuid.UUID
	DefinitionID      uuid.UUID
	VersionID         uuid.UUID
	ContentDigest     [sha256.Size]byte
	DeviceCount       int
	RuntimeVersion    string
	DesktopVersion    string
	OccurredAt        time.Time
	ReceivedAt        time.Time
	RequestID         uuid.UUID
}

type ReservePlatformDefinitionCommand struct {
	DisplayName    string
	IconMediaType  string
	IconData       []byte
	IdempotencyKey string
}

type CreatePlatformDraftCommand struct {
	DefinitionID   uuid.UUID
	BaseVersionID  uuid.UUID
	Kind           PlatformDraftKind
	DisplayName    string
	IconMediaType  string
	IconData       []byte
	Manifest       AgentManifestV1
	Bundle         VersionBundleV1
	IdempotencyKey string
}

type UpdatePlatformDraftCommand struct {
	DraftID          uuid.UUID
	ExpectedRevision int64
	Kind             PlatformDraftKind
	BaseVersionID    uuid.UUID
	DisplayName      string
	IconMediaType    string
	IconData         []byte
	Manifest         AgentManifestV1
	Bundle           VersionBundleV1
	IdempotencyKey   string
}

type SubmitPlatformDraftCommand struct {
	DraftID          uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
}

type TerminalPlatformSubmissionCommand struct {
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
}

type ReviewPlatformSubmissionCommand struct {
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	Decision         PlatformReviewDecision
	ReasonCode       string
	SafeNote         string
	InitialChannels  []OfficialChannel
	IdempotencyKey   string
}

type EnsurePlatformCommand struct {
	PlatformID          uuid.UUID
	PlatformKey         string
	PlatformDisplayName string
	BuildPolicy         func(int64) (PlatformPolicyMaterial, error)
	EnsuredAt           time.Time
}

type ReservePlatformDefinitionRepositoryCommand struct {
	DefinitionID  uuid.UUID
	PlatformID    uuid.UUID
	Actor         PlatformAdminActor
	DisplayName   string
	IconMediaType string
	IconData      []byte
	Idempotency   IdempotencyEvidence
	Audit         AuditEvidence
	CreatedAt     time.Time
}

type CreatePlatformDraftRepositoryCommand struct {
	DraftID     uuid.UUID
	PlatformID  uuid.UUID
	Actor       PlatformAdminActor
	Canonical   CanonicalPlatformDraft
	Idempotency IdempotencyEvidence
	Audit       AuditEvidence
	CreatedAt   time.Time
}

type UpdatePlatformDraftRepositoryCommand struct {
	DraftID          uuid.UUID
	PlatformID       uuid.UUID
	Actor            PlatformAdminActor
	ExpectedRevision int64
	Kind             PlatformDraftKind
	BaseVersionID    uuid.UUID
	DisplayName      string
	IconMediaType    string
	IconData         []byte
	Manifest         AgentManifestV1
	Bundle           VersionBundleV1
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	UpdatedAt        time.Time
}

type SubmitPlatformDraftRepositoryCommand struct {
	SubmissionID     uuid.UUID
	PlatformID       uuid.UUID
	DraftID          uuid.UUID
	ExpectedRevision int64
	Actor            PlatformAdminActor
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	SubmittedAt      time.Time
}

type TerminalPlatformSubmissionRepositoryCommand struct {
	PlatformID       uuid.UUID
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	Actor            PlatformAdminActor
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	TerminalAt       time.Time
}

type InitialOfficialRelease struct {
	ReleaseID  uuid.UUID
	RevisionID uuid.UUID
	Channel    OfficialChannel
}

type ReviewPlatformSubmissionRepositoryCommand struct {
	ReviewID         uuid.UUID
	PlatformID       uuid.UUID
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	Actor            PlatformAdminActor
	Decision         PlatformReviewDecision
	ReasonCode       string
	SafeNote         string
	InitialReleases  []InitialOfficialRelease
	RolloutKeyID     string
	BuildVersion     func(CanonicalPlatformDraft, int64) (VersionMaterial, error)
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	ReviewedAt       time.Time
}

type PlatformRepository interface {
	EnsurePlatform(context.Context, EnsurePlatformCommand) (PlatformPolicySnapshot, error)
	ReservePlatformDefinition(context.Context, ReservePlatformDefinitionRepositoryCommand) (PlatformDefinitionReservation, error)
	CreatePlatformDraft(context.Context, CreatePlatformDraftRepositoryCommand) (PlatformAgentDraft, error)
	UpdatePlatformDraft(context.Context, UpdatePlatformDraftRepositoryCommand) (PlatformAgentDraft, error)
	GetPlatformDraft(context.Context, uuid.UUID, uuid.UUID) (PlatformAgentDraft, bool, error)
	SubmitPlatformDraft(context.Context, SubmitPlatformDraftRepositoryCommand) (PlatformAgentSubmission, error)
	WithdrawPlatformSubmission(context.Context, TerminalPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error)
	ReviewPlatformSubmission(context.Context, ReviewPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error)
	ListPlatformDefinitions(context.Context, uuid.UUID, PageRequest) (PlatformDefinitionPage, error)
	GetPlatformDefinition(context.Context, uuid.UUID, uuid.UUID) (PlatformDefinitionDetail, bool, error)
	ListPlatformDrafts(context.Context, uuid.UUID, PageRequest) (PlatformDraftPage, error)
	ListPlatformSubmissions(context.Context, uuid.UUID, PlatformSubmissionFilter) (PlatformSubmissionPage, error)
	GetPlatformSubmission(context.Context, uuid.UUID, uuid.UUID) (PlatformAgentSubmission, bool, error)
	ListPlatformVersions(context.Context, uuid.UUID, PageRequest) (PlatformVersionPage, error)
	GetPlatformVersion(context.Context, uuid.UUID, uuid.UUID) (Version, bool, error)
	AppendOfficialReleaseRevision(context.Context, OfficialReleaseMutationRepositoryCommand) (OfficialRelease, error)
	GetOfficialRelease(context.Context, uuid.UUID, uuid.UUID) (OfficialRelease, bool, error)
	ListOfficialReleases(context.Context, uuid.UUID, PageRequest) (OfficialReleasePage, error)
	GetOfficialDeliveryTarget(context.Context, uuid.UUID, uuid.UUID) (OfficialDeliveryTarget, bool, error)
	GetOfficialDeliveryVerificationSummary(context.Context, uuid.UUID, uuid.UUID) (OfficialDeliveryVerificationSummary, error)
	ListOfficialReleaseIDs(context.Context, uuid.UUID, OfficialChannel) ([]uuid.UUID, error)
	FindOfficialReleaseID(context.Context, uuid.UUID, uuid.UUID, OfficialChannel) (uuid.UUID, bool, error)
	FindOfficialInstallation(context.Context, Principal, uuid.UUID) (Installation, bool, error)
	GetOfficialEligibility(context.Context, uuid.UUID, uuid.UUID, Principal, OfficialEligibilityContext) (OfficialEligibilityRecord, bool, error)
	GetOfficialEligibilityByRevision(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, Principal, OfficialEligibilityContext) (OfficialEligibilityRecord, bool, error)
}

type PlatformService interface {
	ReserveDefinition(context.Context, PlatformAdminActor, ReservePlatformDefinitionCommand) (PlatformDefinitionReservation, error)
	CreateDraft(context.Context, PlatformAdminActor, CreatePlatformDraftCommand) (PlatformAgentDraft, error)
	UpdateDraft(context.Context, PlatformAdminActor, UpdatePlatformDraftCommand) (PlatformAgentDraft, error)
	ValidateDraft(context.Context, PlatformAdminActor, uuid.UUID) (PlatformDraftValidation, error)
	SubmitDraft(context.Context, PlatformAdminActor, SubmitPlatformDraftCommand) (PlatformAgentSubmission, error)
	WithdrawSubmission(context.Context, PlatformAdminActor, TerminalPlatformSubmissionCommand) (PlatformAgentSubmission, error)
	ReviewSubmission(context.Context, PlatformAdminActor, ReviewPlatformSubmissionCommand) (PlatformAgentSubmission, error)
	ListDefinitions(context.Context, PlatformAdminActor, PageRequest) (PlatformDefinitionPage, error)
	GetDefinition(context.Context, PlatformAdminActor, uuid.UUID) (PlatformDefinitionDetail, error)
	ListDrafts(context.Context, PlatformAdminActor, PageRequest) (PlatformDraftPage, error)
	GetDraft(context.Context, PlatformAdminActor, uuid.UUID) (PlatformAgentDraft, error)
	ListSubmissions(context.Context, PlatformAdminActor, PlatformSubmissionFilter) (PlatformSubmissionPage, error)
	GetSubmission(context.Context, PlatformAdminActor, uuid.UUID) (PlatformAgentSubmission, error)
	ListVersions(context.Context, PlatformAdminActor, PageRequest) (PlatformVersionPage, error)
	GetVersion(context.Context, PlatformAdminActor, uuid.UUID) (Version, error)
	ListReleases(context.Context, PlatformAdminActor, PageRequest) (OfficialReleasePage, error)
	GetRelease(context.Context, PlatformAdminActor, uuid.UUID) (OfficialRelease, error)
	GetDeliveryTarget(context.Context, PlatformAdminActor, uuid.UUID) (OfficialDeliveryTarget, error)
	GetDeliveryVerificationSummary(context.Context, PlatformAdminActor, uuid.UUID) (OfficialDeliveryVerificationSummary, error)
	ActivateOfficialRelease(context.Context, PlatformAdminActor, ActivateOfficialReleaseCommand) (OfficialRelease, error)
	UpdateOfficialRollout(context.Context, PlatformAdminActor, UpdateOfficialRolloutCommand) (OfficialRelease, error)
	PauseOfficialRelease(context.Context, PlatformAdminActor, ChangeOfficialReleaseStateCommand) (OfficialRelease, error)
	ResumeOfficialRelease(context.Context, PlatformAdminActor, ChangeOfficialReleaseStateCommand) (OfficialRelease, error)
	RollbackOfficialRelease(context.Context, PlatformAdminActor, RollbackOfficialReleaseCommand) (OfficialRelease, error)
	ListOfficialAgents(context.Context, Principal, OfficialEligibilityContext) ([]OfficialAgentCatalogEntry, error)
	GetOfficialAgent(context.Context, Principal, uuid.UUID, OfficialEligibilityContext) (OfficialAgentCatalogEntry, error)
	ResolveOfficialRelease(context.Context, Principal, uuid.UUID, OfficialEligibilityContext) (OfficialManagedTarget, error)
	ResolveOfficialReleaseRevision(context.Context, Principal, uuid.UUID, uuid.UUID, OfficialEligibilityContext) (OfficialManagedTarget, error)
	EvaluateOfficialEligibilityRecord(Principal, OfficialEligibilityContext, OfficialEligibilityRecord, bool) (OfficialManagedTarget, error)
}

type PlatformInitializer interface {
	PlatformService
	Initialize(context.Context) (PlatformPolicySnapshot, error)
}

type PlatformServiceConfig struct {
	Repository          PlatformRepository
	Signer              *Signer
	PlatformID          uuid.UUID
	PlatformKey         string
	PlatformDisplayName string
	RolloutKeyID        string
	RolloutKeys         map[string][]byte
	Clock               func() time.Time
	NewID               func() uuid.UUID
}

type platformService struct {
	repository          PlatformRepository
	signer              *Signer
	platformID          uuid.UUID
	platformKey         string
	platformDisplayName string
	rolloutKeyID        string
	rolloutKeys         map[string][]byte
	clock               func() time.Time
	newID               func() uuid.UUID
}

func NewPlatformService(config PlatformServiceConfig) (PlatformInitializer, error) {
	if config.Repository == nil || config.Signer == nil || config.PlatformID == uuid.Nil ||
		!platformKeyPattern.MatchString(config.PlatformKey) ||
		!validPlatformDisplayName(config.PlatformDisplayName) ||
		!platformRolloutKeyPattern.MatchString(config.RolloutKeyID) {
		return nil, ErrInvalidRequest
	}
	rolloutKeys := cloneRolloutKeys(config.RolloutKeys)
	if len(rolloutKeys) > 0 {
		active, exists := rolloutKeys[config.RolloutKeyID]
		if !exists || len(active) != sha256.Size {
			return nil, ErrInvalidRequest
		}
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	newID := config.NewID
	if newID == nil {
		newID = uuid.New
	}
	return &platformService{
		repository: config.Repository, signer: config.Signer,
		platformID: config.PlatformID, platformKey: config.PlatformKey,
		platformDisplayName: config.PlatformDisplayName, rolloutKeyID: config.RolloutKeyID,
		rolloutKeys: rolloutKeys,
		clock:       clock, newID: newID,
	}, nil
}

var _ PlatformInitializer = (*platformService)(nil)

func (s *platformService) Initialize(ctx context.Context) (PlatformPolicySnapshot, error) {
	if s == nil {
		return PlatformPolicySnapshot{}, ErrInvalidRequest
	}
	policyID := s.newID()
	if policyID == uuid.Nil {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	return s.repository.EnsurePlatform(ctx, EnsurePlatformCommand{
		PlatformID: s.platformID, PlatformKey: s.platformKey,
		PlatformDisplayName: s.platformDisplayName, EnsuredAt: s.clock().UTC(),
		BuildPolicy: func(version int64) (PlatformPolicyMaterial, error) {
			if version <= 0 {
				return PlatformPolicyMaterial{}, ErrInvalidRepositoryCommand
			}
			canonical, err := json.Marshal(DefaultPlatformAgentPolicyV1())
			if err != nil {
				return PlatformPolicyMaterial{}, ErrServiceUnavailable
			}
			digest := sha256.Sum256(canonical)
			attestation, err := s.signer.SignPolicy(PolicySignatureInput{
				PolicyID: policyID, PolicyVersion: version, DocumentDigest: digest,
			})
			if err != nil {
				return PlatformPolicyMaterial{}, ErrServiceUnavailable
			}
			return PlatformPolicyMaterial{
				ID: policyID, Version: version, CanonicalPolicy: canonical, PolicyDigest: digest,
				SigningKeyID: attestation.KeyID, Signature: bytes.Clone(attestation.Signature),
			}, nil
		},
	})
}

func (s *platformService) ReserveDefinition(
	ctx context.Context,
	actor PlatformAdminActor,
	request ReservePlatformDefinitionCommand,
) (PlatformDefinitionReservation, error) {
	displayName := strings.TrimSpace(request.DisplayName)
	if !s.authorized(actor, platformActionDraftWrite) || !validPlatformDisplayName(displayName) ||
		!validIdempotencyKey(request.IdempotencyKey) ||
		(request.IconMediaType == "") != (len(request.IconData) == 0) ||
		(request.IconMediaType != "" && ValidateIcon(request.IconMediaType, request.IconData) != nil) {
		return PlatformDefinitionReservation{}, platformRequestError(actor, platformActionDraftWrite)
	}
	requestHash, err := hashRequest(struct {
		Operation     string `json:"operation"`
		DisplayName   string `json:"display_name"`
		IconMediaType string `json:"icon_media_type,omitempty"`
		IconDigest    string `json:"icon_digest,omitempty"`
	}{"official_definition_reserve", displayName, request.IconMediaType, digestHex(request.IconData)})
	if err != nil {
		return PlatformDefinitionReservation{}, ErrInvalidRequest
	}
	ids, ok := s.ids(3)
	if !ok {
		return PlatformDefinitionReservation{}, ErrServiceUnavailable
	}
	actor, ok = bindGeneratedPlatformOperationTarget(
		actor, "official_definition_reserve", "platform_definition", ids[0],
	)
	if !ok {
		return PlatformDefinitionReservation{}, ErrInvalidRequest
	}
	now := s.clock().UTC()
	result, err := s.repository.ReservePlatformDefinition(ctx, ReservePlatformDefinitionRepositoryCommand{
		DefinitionID: ids[0], PlatformID: s.platformID, Actor: actor,
		DisplayName: displayName, IconMediaType: request.IconMediaType,
		IconData:    bytes.Clone(request.IconData),
		Idempotency: newPlatformIdempotency(ids[1], request.IdempotencyKey, requestHash, now),
		Audit:       AuditEvidence{EventID: ids[2], RequestID: actor.RequestID}, CreatedAt: now,
	})
	if err != nil {
		return PlatformDefinitionReservation{}, err
	}
	return clonePlatformReservation(result), nil
}

func (s *platformService) CreateDraft(
	ctx context.Context,
	actor PlatformAdminActor,
	request CreatePlatformDraftCommand,
) (PlatformAgentDraft, error) {
	if !s.authorized(actor, platformActionDraftWrite) || !validIdempotencyKey(request.IdempotencyKey) {
		return PlatformAgentDraft{}, platformRequestError(actor, platformActionDraftWrite)
	}
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: request.DefinitionID, BaseVersionID: request.BaseVersionID, Kind: request.Kind,
		DisplayName: request.DisplayName, IconMediaType: request.IconMediaType, IconData: request.IconData,
		Manifest: request.Manifest, Bundle: request.Bundle,
	})
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	if findings := ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle)); len(findings) != 0 {
		return PlatformAgentDraft{}, &PlatformPublicationDLPError{Findings: cloneExperienceCandidateFindings(findings)}
	}
	requestHash, err := platformDraftRequestHash("official_draft_create", actor, canonical, 0)
	if err != nil {
		return PlatformAgentDraft{}, ErrInvalidRequest
	}
	ids, ok := s.ids(3)
	if !ok {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	actor, ok = bindGeneratedPlatformOperationTarget(
		actor, "official_draft_create", "platform_draft", ids[0],
	)
	if !ok {
		return PlatformAgentDraft{}, ErrInvalidRequest
	}
	now := s.clock().UTC()
	result, err := s.repository.CreatePlatformDraft(ctx, CreatePlatformDraftRepositoryCommand{
		DraftID: ids[0], PlatformID: s.platformID, Actor: actor, Canonical: canonical,
		Idempotency: newPlatformIdempotency(ids[1], request.IdempotencyKey, requestHash, now),
		Audit:       AuditEvidence{EventID: ids[2], RequestID: actor.RequestID}, CreatedAt: now,
	})
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	return clonePlatformDraft(result), nil
}

func (s *platformService) UpdateDraft(
	ctx context.Context,
	actor PlatformAdminActor,
	request UpdatePlatformDraftCommand,
) (PlatformAgentDraft, error) {
	if !s.authorized(actor, platformActionDraftWrite) || request.DraftID == uuid.Nil || request.ExpectedRevision <= 0 ||
		!validIdempotencyKey(request.IdempotencyKey) {
		return PlatformAgentDraft{}, platformRequestError(actor, platformActionDraftWrite)
	}
	current, found, err := s.repository.GetPlatformDraft(ctx, s.platformID, request.DraftID)
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	if !found {
		return PlatformAgentDraft{}, ErrNotFound
	}
	kind := request.Kind
	baseVersionID := request.BaseVersionID
	if kind == "" {
		kind = current.Kind
		baseVersionID = current.BaseVersionID
	}
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: current.DefinitionID, BaseVersionID: baseVersionID, Kind: kind,
		DisplayName: request.DisplayName, IconMediaType: request.IconMediaType, IconData: request.IconData,
		Manifest: request.Manifest, Bundle: request.Bundle,
	})
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	if findings := ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle)); len(findings) != 0 {
		return PlatformAgentDraft{}, &PlatformPublicationDLPError{Findings: cloneExperienceCandidateFindings(findings)}
	}
	requestHash, err := platformDraftRequestHash("official_draft_update", actor, canonical, request.ExpectedRevision)
	if err != nil {
		return PlatformAgentDraft{}, ErrInvalidRequest
	}
	ids, ok := s.ids(2)
	if !ok {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	result, err := s.repository.UpdatePlatformDraft(ctx, UpdatePlatformDraftRepositoryCommand{
		DraftID: request.DraftID, PlatformID: s.platformID, Actor: actor,
		ExpectedRevision: request.ExpectedRevision, Kind: canonical.Package.Kind,
		BaseVersionID: canonical.Package.BaseVersionID, DisplayName: canonical.Package.DisplayName,
		IconMediaType: canonical.Package.IconMediaType, IconData: bytes.Clone(canonical.Package.IconData),
		Manifest: canonical.Package.Manifest, Bundle: canonical.Package.Bundle,
		Idempotency: newPlatformIdempotency(ids[0], request.IdempotencyKey, requestHash, now),
		Audit:       AuditEvidence{EventID: ids[1], RequestID: actor.RequestID}, UpdatedAt: now,
	})
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	return clonePlatformDraft(result), nil
}

func (s *platformService) ValidateDraft(
	ctx context.Context,
	actor PlatformAdminActor,
	draftID uuid.UUID,
) (PlatformDraftValidation, error) {
	if !s.authorized(actor, platformActionDraftWrite) || draftID == uuid.Nil {
		return PlatformDraftValidation{}, platformRequestError(actor, platformActionDraftWrite)
	}
	draft, found, err := s.repository.GetPlatformDraft(ctx, s.platformID, draftID)
	if err != nil {
		return PlatformDraftValidation{}, err
	}
	if !found {
		return PlatformDraftValidation{}, ErrNotFound
	}
	canonical, err := canonicalFromPlatformDraft(draft)
	if err != nil {
		return PlatformDraftValidation{}, ErrOfficialVersionIntegrityFailed
	}
	findings := ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle))
	return PlatformDraftValidation{
		DraftID: draft.ID, DraftRevision: draft.Revision, ContentDigest: canonical.ContentDigest,
		DLPVersion: AgentPublicationDLPVersion, Valid: len(findings) == 0,
		Findings: cloneExperienceCandidateFindings(findings),
	}, nil
}

func (s *platformService) SubmitDraft(
	ctx context.Context,
	actor PlatformAdminActor,
	request SubmitPlatformDraftCommand,
) (PlatformAgentSubmission, error) {
	if !s.authorized(actor, platformActionDraftWrite) || request.DraftID == uuid.Nil ||
		request.ExpectedRevision <= 0 || !validIdempotencyKey(request.IdempotencyKey) {
		return PlatformAgentSubmission{}, platformRequestError(actor, platformActionDraftWrite)
	}
	hash, err := hashRequest(struct {
		Operation        string `json:"operation"`
		PlatformID       string `json:"platform_id"`
		DraftID          string `json:"draft_id"`
		ExpectedRevision int64  `json:"expected_revision"`
		AdminID          string `json:"admin_id"`
	}{"official_draft_submit", s.platformID.String(), request.DraftID.String(), request.ExpectedRevision, actor.AdminID.String()})
	if err != nil {
		return PlatformAgentSubmission{}, ErrInvalidRequest
	}
	ids, ok := s.ids(3)
	if !ok {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	actor, ok = bindGeneratedPlatformOperationTarget(
		actor, "official_draft_submit", "platform_submission", ids[0],
	)
	if !ok {
		return PlatformAgentSubmission{}, ErrInvalidRequest
	}
	now := s.clock().UTC()
	result, err := s.repository.SubmitPlatformDraft(ctx, SubmitPlatformDraftRepositoryCommand{
		SubmissionID: ids[0], PlatformID: s.platformID, DraftID: request.DraftID,
		ExpectedRevision: request.ExpectedRevision, Actor: actor,
		Idempotency: newPlatformIdempotency(ids[1], request.IdempotencyKey, hash, now),
		Audit:       AuditEvidence{EventID: ids[2], RequestID: actor.RequestID}, SubmittedAt: now,
	})
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	return clonePlatformSubmission(result), nil
}

func (s *platformService) WithdrawSubmission(
	ctx context.Context,
	actor PlatformAdminActor,
	request TerminalPlatformSubmissionCommand,
) (PlatformAgentSubmission, error) {
	if !s.authorized(actor, platformActionDraftWrite) || request.SubmissionID == uuid.Nil ||
		request.ExpectedRevision <= 0 || !validIdempotencyKey(request.IdempotencyKey) {
		return PlatformAgentSubmission{}, platformRequestError(actor, platformActionDraftWrite)
	}
	hash, err := platformTerminalRequestHash("official_submission_withdraw", s.platformID, actor, request)
	if err != nil {
		return PlatformAgentSubmission{}, ErrInvalidRequest
	}
	ids, ok := s.ids(2)
	if !ok {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	result, err := s.repository.WithdrawPlatformSubmission(ctx, TerminalPlatformSubmissionRepositoryCommand{
		PlatformID: s.platformID, SubmissionID: request.SubmissionID,
		ExpectedRevision: request.ExpectedRevision, Actor: actor,
		Idempotency: newPlatformIdempotency(ids[0], request.IdempotencyKey, hash, now),
		Audit:       AuditEvidence{EventID: ids[1], RequestID: actor.RequestID}, TerminalAt: now,
	})
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	return clonePlatformSubmission(result), nil
}

func (s *platformService) ReviewSubmission(
	ctx context.Context,
	actor PlatformAdminActor,
	request ReviewPlatformSubmissionCommand,
) (PlatformAgentSubmission, error) {
	if !s.authorized(actor, platformActionReview) || request.SubmissionID == uuid.Nil ||
		request.ExpectedRevision <= 0 || !validIdempotencyKey(request.IdempotencyKey) {
		return PlatformAgentSubmission{}, platformRequestError(actor, platformActionReview)
	}
	channels, ok := canonicalInitialChannels(request.Decision, request.InitialChannels)
	if !ok || !validPlatformReviewText(request) {
		return PlatformAgentSubmission{}, ErrInvalidRequest
	}
	hash, err := hashRequest(struct {
		Operation        string                 `json:"operation"`
		PlatformID       string                 `json:"platform_id"`
		SubmissionID     string                 `json:"submission_id"`
		ExpectedRevision int64                  `json:"expected_revision"`
		AdminID          string                 `json:"admin_id"`
		Decision         PlatformReviewDecision `json:"decision"`
		ReasonCode       string                 `json:"reason_code,omitempty"`
		SafeNote         string                 `json:"safe_note,omitempty"`
		Channels         []OfficialChannel      `json:"initial_channels,omitempty"`
	}{"official_submission_review", s.platformID.String(), request.SubmissionID.String(),
		request.ExpectedRevision, actor.AdminID.String(), request.Decision, request.ReasonCode, request.SafeNote, channels})
	if err != nil {
		return PlatformAgentSubmission{}, ErrInvalidRequest
	}
	idCount := 3
	if request.Decision == PlatformReviewApprove {
		idCount += 1 + (2 * len(channels))
	}
	ids, ok := s.ids(idCount)
	if !ok {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	index := 1
	var buildVersion func(CanonicalPlatformDraft, int64) (VersionMaterial, error)
	var initialReleases []InitialOfficialRelease
	rolloutKeyID := ""
	if request.Decision == PlatformReviewApprove {
		rolloutKeyID = s.rolloutKeyID
		versionID := ids[index]
		index++
		initialReleases = make([]InitialOfficialRelease, len(channels))
		for channelIndex, channel := range channels {
			initialReleases[channelIndex] = InitialOfficialRelease{
				ReleaseID: ids[index], RevisionID: ids[index+1], Channel: channel,
			}
			index += 2
		}
		buildVersion = func(canonical CanonicalPlatformDraft, versionNumber int64) (VersionMaterial, error) {
			verified, err := CanonicalizePlatformDraft(canonical.Package)
			if err != nil || verified.ManifestDigest != canonical.ManifestDigest ||
				verified.BundleDigest != canonical.BundleDigest || verified.ContentDigest != canonical.ContentDigest {
				return VersionMaterial{}, ErrOfficialVersionIntegrityFailed
			}
			if findings := ScanAgentPublication(publicationTextAssets(verified.Package.Bundle)); len(findings) != 0 {
				return VersionMaterial{}, &PlatformPublicationDLPError{Findings: cloneExperienceCandidateFindings(findings)}
			}
			version, minimum, maximum, err := canonicalizePublication(verified.Package.Manifest, verified.Package.Bundle)
			if err != nil || version.ContentDigest != verified.ContentDigest {
				return VersionMaterial{}, ErrOfficialVersionIntegrityFailed
			}
			attestation, err := s.signer.SignVersion(VersionSignatureInput{
				DefinitionID: verified.Package.DefinitionID, VersionID: versionID, VersionNumber: versionNumber,
				ManifestDigest: verified.ManifestDigest, BundleDigest: verified.BundleDigest,
			})
			if err != nil {
				return VersionMaterial{}, ErrServiceUnavailable
			}
			return VersionMaterial{
				ID: versionID, VersionNumber: versionNumber,
				CanonicalManifest: bytes.Clone(version.ManifestJSON), Bundle: bytes.Clone(version.BundleJSON),
				ContentDigest: version.ContentDigest, SigningKeyID: attestation.KeyID,
				Signature: bytes.Clone(attestation.Signature), RuntimeMinimumVersion: minimum,
				RuntimeMaximumVersionExclusive: maximum,
			}, nil
		}
	}
	now := s.clock().UTC()
	result, err := s.repository.ReviewPlatformSubmission(ctx, ReviewPlatformSubmissionRepositoryCommand{
		ReviewID: ids[0], PlatformID: s.platformID, SubmissionID: request.SubmissionID,
		ExpectedRevision: request.ExpectedRevision, Actor: actor, Decision: request.Decision,
		ReasonCode: request.ReasonCode, SafeNote: request.SafeNote,
		InitialReleases: initialReleases, RolloutKeyID: rolloutKeyID, BuildVersion: buildVersion,
		Idempotency: newPlatformIdempotency(ids[index], request.IdempotencyKey, hash, now),
		Audit:       AuditEvidence{EventID: ids[index+1], RequestID: actor.RequestID}, ReviewedAt: now,
	})
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	return clonePlatformSubmission(result), nil
}

func (s *platformService) ListDefinitions(ctx context.Context, actor PlatformAdminActor, page PageRequest) (PlatformDefinitionPage, error) {
	if !s.authorized(actor, platformActionRead) || !validPageRequest(page) {
		return PlatformDefinitionPage{}, platformRequestError(actor, platformActionRead)
	}
	value, err := s.repository.ListPlatformDefinitions(ctx, s.platformID, normalizePageRequest(page))
	return clonePlatformDefinitionPage(value), err
}

func (s *platformService) GetDefinition(ctx context.Context, actor PlatformAdminActor, id uuid.UUID) (PlatformDefinitionDetail, error) {
	if !s.authorized(actor, platformActionRead) || id == uuid.Nil {
		return PlatformDefinitionDetail{}, platformRequestError(actor, platformActionRead)
	}
	value, found, err := s.repository.GetPlatformDefinition(ctx, s.platformID, id)
	if err != nil {
		return PlatformDefinitionDetail{}, err
	}
	if !found {
		return PlatformDefinitionDetail{}, ErrNotFound
	}
	return clonePlatformDefinitionDetail(value), nil
}

func (s *platformService) ListDrafts(ctx context.Context, actor PlatformAdminActor, page PageRequest) (PlatformDraftPage, error) {
	if !s.authorized(actor, platformActionRead) || !validPageRequest(page) {
		return PlatformDraftPage{}, platformRequestError(actor, platformActionRead)
	}
	value, err := s.repository.ListPlatformDrafts(ctx, s.platformID, normalizePageRequest(page))
	return clonePlatformDraftPage(value), err
}

func (s *platformService) GetDraft(ctx context.Context, actor PlatformAdminActor, id uuid.UUID) (PlatformAgentDraft, error) {
	if !s.authorized(actor, platformActionRead) || id == uuid.Nil {
		return PlatformAgentDraft{}, platformRequestError(actor, platformActionRead)
	}
	value, found, err := s.repository.GetPlatformDraft(ctx, s.platformID, id)
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	if !found {
		return PlatformAgentDraft{}, ErrNotFound
	}
	return clonePlatformDraft(value), nil
}

func (s *platformService) ListSubmissions(ctx context.Context, actor PlatformAdminActor, filter PlatformSubmissionFilter) (PlatformSubmissionPage, error) {
	if !s.authorized(actor, platformActionRead) || !validPlatformSubmissionFilter(filter) {
		return PlatformSubmissionPage{}, platformRequestError(actor, platformActionRead)
	}
	value, err := s.repository.ListPlatformSubmissions(ctx, s.platformID, filter)
	return clonePlatformSubmissionPage(value), err
}

func (s *platformService) GetSubmission(ctx context.Context, actor PlatformAdminActor, id uuid.UUID) (PlatformAgentSubmission, error) {
	if !s.authorized(actor, platformActionRead) || id == uuid.Nil {
		return PlatformAgentSubmission{}, platformRequestError(actor, platformActionRead)
	}
	value, found, err := s.repository.GetPlatformSubmission(ctx, s.platformID, id)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	if !found {
		return PlatformAgentSubmission{}, ErrNotFound
	}
	return clonePlatformSubmission(value), nil
}

func (s *platformService) ListVersions(ctx context.Context, actor PlatformAdminActor, page PageRequest) (PlatformVersionPage, error) {
	if !s.authorized(actor, platformActionApprovedRead) || !validPageRequest(page) {
		return PlatformVersionPage{}, platformRequestError(actor, platformActionApprovedRead)
	}
	value, err := s.repository.ListPlatformVersions(ctx, s.platformID, normalizePageRequest(page))
	return clonePlatformVersionPage(value), err
}

func (s *platformService) GetVersion(ctx context.Context, actor PlatformAdminActor, id uuid.UUID) (Version, error) {
	if !s.authorized(actor, platformActionApprovedRead) || id == uuid.Nil {
		return Version{}, platformRequestError(actor, platformActionApprovedRead)
	}
	value, found, err := s.repository.GetPlatformVersion(ctx, s.platformID, id)
	if err != nil {
		return Version{}, err
	}
	if !found {
		return Version{}, ErrNotFound
	}
	return cloneVersion(value), nil
}

func (s *platformService) ListReleases(
	ctx context.Context,
	actor PlatformAdminActor,
	page PageRequest,
) (OfficialReleasePage, error) {
	if !s.authorized(actor, platformActionApprovedRead) || !validPageRequest(page) {
		return OfficialReleasePage{}, platformRequestError(actor, platformActionApprovedRead)
	}
	value, err := s.repository.ListOfficialReleases(ctx, s.platformID, normalizePageRequest(page))
	return cloneOfficialReleasePage(value), err
}

func (s *platformService) GetRelease(
	ctx context.Context,
	actor PlatformAdminActor,
	id uuid.UUID,
) (OfficialRelease, error) {
	if !s.authorized(actor, platformActionApprovedRead) || id == uuid.Nil {
		return OfficialRelease{}, platformRequestError(actor, platformActionApprovedRead)
	}
	value, found, err := s.repository.GetOfficialRelease(ctx, s.platformID, id)
	if err != nil {
		return OfficialRelease{}, err
	}
	if !found {
		return OfficialRelease{}, ErrNotFound
	}
	return cloneOfficialRelease(value), nil
}

func (s *platformService) GetDeliveryVerificationSummary(
	ctx context.Context,
	actor PlatformAdminActor,
	releaseID uuid.UUID,
) (OfficialDeliveryVerificationSummary, error) {
	if !s.authorized(actor, platformActionApprovedRead) || releaseID == uuid.Nil {
		return OfficialDeliveryVerificationSummary{}, platformRequestError(actor, platformActionApprovedRead)
	}
	if _, found, err := s.repository.GetOfficialRelease(ctx, s.platformID, releaseID); err != nil {
		return OfficialDeliveryVerificationSummary{}, err
	} else if !found {
		return OfficialDeliveryVerificationSummary{}, ErrNotFound
	}
	value, err := s.repository.GetOfficialDeliveryVerificationSummary(ctx, s.platformID, releaseID)
	if err != nil {
		return OfficialDeliveryVerificationSummary{}, err
	}
	return cloneOfficialDeliveryVerificationSummary(value), nil
}

func (s *platformService) GetDeliveryTarget(
	ctx context.Context,
	actor PlatformAdminActor,
	submissionID uuid.UUID,
) (OfficialDeliveryTarget, error) {
	if !s.authorized(actor, platformActionApprovedRead) || submissionID == uuid.Nil {
		return OfficialDeliveryTarget{}, platformRequestError(actor, platformActionApprovedRead)
	}
	value, found, err := s.repository.GetOfficialDeliveryTarget(ctx, s.platformID, submissionID)
	if err != nil {
		return OfficialDeliveryTarget{}, err
	}
	if !found {
		return OfficialDeliveryTarget{}, ErrNotFound
	}
	return cloneOfficialDeliveryTarget(value), nil
}

func (s *platformService) ActivateOfficialRelease(
	ctx context.Context,
	actor PlatformAdminActor,
	request ActivateOfficialReleaseCommand,
) (OfficialRelease, error) {
	if !s.authorized(actor, platformActionReleaseWrite) {
		return OfficialRelease{}, platformRequestError(actor, platformActionReleaseWrite)
	}
	minimum, _, err := parseSemanticVersion(request.MinimumDesktopVersion)
	if err != nil || request.ReleaseID == uuid.Nil || request.VersionID == uuid.Nil || request.ExpectedHeadRevision <= 0 ||
		request.RolloutBasisPoints < 0 || request.RolloutBasisPoints > DefaultPlatformAgentPolicyV1().MaximumRolloutBasisPts ||
		!validPlatformOperationEvidence(request.Evidence) {
		return OfficialRelease{}, ErrOfficialRolloutInvalid
	}
	audience, ok := canonicalOfficialAudience(request.AllowlistedUserIDs)
	if !ok {
		return OfficialRelease{}, ErrOfficialRolloutInvalid
	}
	return s.appendOfficialRelease(ctx, actor, OfficialReleaseMutationRepositoryCommand{
		PlatformID: s.platformID, ReleaseID: request.ReleaseID,
		ExpectedHeadRevision: request.ExpectedHeadRevision, Action: OfficialReleaseActionActivate,
		VersionID: request.VersionID, RolloutBasisPoints: request.RolloutBasisPoints,
		MinimumDesktopVersion: minimum, RolloutKeyID: s.rolloutKeyID,
		AllowlistedUserIDs: audience, ReasonCode: request.Evidence.ReasonCode,
		TicketReference: request.Evidence.TicketReference,
	}, request.Evidence)
}

func (s *platformService) UpdateOfficialRollout(
	ctx context.Context,
	actor PlatformAdminActor,
	request UpdateOfficialRolloutCommand,
) (OfficialRelease, error) {
	if !s.authorized(actor, platformActionReleaseWrite) {
		return OfficialRelease{}, platformRequestError(actor, platformActionReleaseWrite)
	}
	minimum, _, err := parseSemanticVersion(request.MinimumDesktopVersion)
	if err != nil || request.ReleaseID == uuid.Nil || request.ExpectedHeadRevision <= 0 ||
		request.RolloutBasisPoints < 0 || request.RolloutBasisPoints > DefaultPlatformAgentPolicyV1().MaximumRolloutBasisPts ||
		!validPlatformOperationEvidence(request.Evidence) {
		return OfficialRelease{}, ErrOfficialRolloutInvalid
	}
	audience, ok := canonicalOfficialAudience(request.AllowlistedUserIDs)
	if !ok {
		return OfficialRelease{}, ErrOfficialRolloutInvalid
	}
	return s.appendOfficialRelease(ctx, actor, OfficialReleaseMutationRepositoryCommand{
		PlatformID: s.platformID, ReleaseID: request.ReleaseID,
		ExpectedHeadRevision: request.ExpectedHeadRevision, Action: OfficialReleaseActionRolloutUpdate,
		RolloutBasisPoints: request.RolloutBasisPoints, MinimumDesktopVersion: minimum,
		RolloutKeyID: s.rolloutKeyID, AllowlistedUserIDs: audience,
		ReasonCode: request.Evidence.ReasonCode, TicketReference: request.Evidence.TicketReference,
	}, request.Evidence)
}

func (s *platformService) PauseOfficialRelease(
	ctx context.Context,
	actor PlatformAdminActor,
	request ChangeOfficialReleaseStateCommand,
) (OfficialRelease, error) {
	return s.changeOfficialReleaseState(ctx, actor, request, OfficialReleaseActionPause)
}

func (s *platformService) ResumeOfficialRelease(
	ctx context.Context,
	actor PlatformAdminActor,
	request ChangeOfficialReleaseStateCommand,
) (OfficialRelease, error) {
	return s.changeOfficialReleaseState(ctx, actor, request, OfficialReleaseActionResume)
}

func (s *platformService) changeOfficialReleaseState(
	ctx context.Context,
	actor PlatformAdminActor,
	request ChangeOfficialReleaseStateCommand,
	action OfficialReleaseAction,
) (OfficialRelease, error) {
	if !s.authorized(actor, platformActionReleaseWrite) {
		return OfficialRelease{}, platformRequestError(actor, platformActionReleaseWrite)
	}
	if request.ReleaseID == uuid.Nil || request.ExpectedHeadRevision <= 0 || !validPlatformOperationEvidence(request.Evidence) ||
		(action != OfficialReleaseActionPause && action != OfficialReleaseActionResume) {
		return OfficialRelease{}, ErrOfficialRolloutInvalid
	}
	return s.appendOfficialRelease(ctx, actor, OfficialReleaseMutationRepositoryCommand{
		PlatformID: s.platformID, ReleaseID: request.ReleaseID,
		ExpectedHeadRevision: request.ExpectedHeadRevision, Action: action,
		ReasonCode: request.Evidence.ReasonCode, TicketReference: request.Evidence.TicketReference,
	}, request.Evidence)
}

func (s *platformService) RollbackOfficialRelease(
	ctx context.Context,
	actor PlatformAdminActor,
	request RollbackOfficialReleaseCommand,
) (OfficialRelease, error) {
	if !s.authorized(actor, platformActionRollback) {
		return OfficialRelease{}, platformRequestError(actor, platformActionRollback)
	}
	if request.ReleaseID == uuid.Nil || request.TargetVersionID == uuid.Nil || request.TargetReleaseRevisionID == uuid.Nil ||
		request.ApprovalID == uuid.Nil || request.ExpectedHeadRevision <= 0 || !validPlatformOperationEvidence(request.Evidence) {
		return OfficialRelease{}, ErrOfficialRolloutInvalid
	}
	return s.appendOfficialRelease(ctx, actor, OfficialReleaseMutationRepositoryCommand{
		PlatformID: s.platformID, ReleaseID: request.ReleaseID,
		ExpectedHeadRevision: request.ExpectedHeadRevision, Action: OfficialReleaseActionRollback,
		VersionID: request.TargetVersionID, TargetReleaseRevisionID: request.TargetReleaseRevisionID,
		ApprovalID: request.ApprovalID, ReasonCode: request.Evidence.ReasonCode,
		TicketReference: request.Evidence.TicketReference,
	}, request.Evidence)
}

func (s *platformService) appendOfficialRelease(
	ctx context.Context,
	actor PlatformAdminActor,
	command OfficialReleaseMutationRepositoryCommand,
	evidence PlatformOperationEvidence,
) (OfficialRelease, error) {
	if s == nil || len(s.rolloutKeys) == 0 {
		return OfficialRelease{}, ErrCloudUnavailable
	}
	ids, ok := s.ids(3)
	if !ok {
		return OfficialRelease{}, ErrServiceUnavailable
	}
	command.RevisionID = ids[0]
	command.Actor = actor
	command.ChangedAt = s.clock().UTC()
	requestHash, err := officialReleaseRequestHash(command)
	if err != nil {
		return OfficialRelease{}, ErrServiceUnavailable
	}
	command.Idempotency = newPlatformIdempotency(ids[1], evidence.IdempotencyKey, requestHash, command.ChangedAt)
	command.Audit = AuditEvidence{EventID: ids[2], RequestID: actor.RequestID}
	value, err := s.repository.AppendOfficialReleaseRevision(ctx, command)
	return cloneOfficialRelease(value), err
}

func (s *platformService) ResolveOfficialRelease(
	ctx context.Context,
	principal Principal,
	releaseID uuid.UUID,
	eligibilityContext OfficialEligibilityContext,
) (OfficialManagedTarget, error) {
	if s == nil || !validPrincipal(principal) || releaseID == uuid.Nil ||
		!validOfficialEligibilityContext(principal, eligibilityContext) {
		return OfficialManagedTarget{}, ErrInvalidRequest
	}
	record, found, err := s.repository.GetOfficialEligibility(
		ctx, s.platformID, releaseID, principal, eligibilityContext,
	)
	if err != nil {
		return OfficialManagedTarget{}, err
	}
	if !found {
		return OfficialManagedTarget{}, ErrOfficialAgentNotEligible
	}
	return s.EvaluateOfficialEligibilityRecord(principal, eligibilityContext, record, false)
}

func (s *platformService) ListOfficialAgents(
	ctx context.Context,
	principal Principal,
	eligibilityContext OfficialEligibilityContext,
) ([]OfficialAgentCatalogEntry, error) {
	if s == nil || !validPrincipal(principal) || !validOfficialEligibilityContext(principal, eligibilityContext) {
		return nil, ErrInvalidRequest
	}
	releaseIDs, err := s.repository.ListOfficialReleaseIDs(ctx, s.platformID, eligibilityContext.Channel)
	if err != nil {
		return nil, err
	}
	items := make([]OfficialAgentCatalogEntry, 0, len(releaseIDs))
	for _, releaseID := range releaseIDs {
		item, err := s.officialAgentForRelease(ctx, principal, releaseID, eligibilityContext)
		if isOfficialCatalogDenial(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return cloneOfficialAgentCatalog(items), nil
}

func (s *platformService) GetOfficialAgent(
	ctx context.Context,
	principal Principal,
	definitionID uuid.UUID,
	eligibilityContext OfficialEligibilityContext,
) (OfficialAgentCatalogEntry, error) {
	if s == nil || !validPrincipal(principal) || definitionID == uuid.Nil ||
		!validOfficialEligibilityContext(principal, eligibilityContext) {
		return OfficialAgentCatalogEntry{}, ErrInvalidRequest
	}
	releaseID, found, err := s.repository.FindOfficialReleaseID(
		ctx, s.platformID, definitionID, eligibilityContext.Channel,
	)
	if err != nil {
		return OfficialAgentCatalogEntry{}, err
	}
	if !found {
		return OfficialAgentCatalogEntry{}, ErrOfficialAgentNotEligible
	}
	item, err := s.officialAgentForRelease(ctx, principal, releaseID, eligibilityContext)
	return cloneOfficialAgentCatalogEntry(item), err
}

func (s *platformService) officialAgentForRelease(
	ctx context.Context,
	principal Principal,
	releaseID uuid.UUID,
	eligibilityContext OfficialEligibilityContext,
) (OfficialAgentCatalogEntry, error) {
	record, found, err := s.repository.GetOfficialEligibility(
		ctx, s.platformID, releaseID, principal, eligibilityContext,
	)
	if err != nil {
		return OfficialAgentCatalogEntry{}, err
	}
	if !found {
		return OfficialAgentCatalogEntry{}, ErrOfficialAgentNotEligible
	}
	target, err := s.EvaluateOfficialEligibilityRecord(principal, eligibilityContext, record, false)
	if err != nil {
		return OfficialAgentCatalogEntry{}, err
	}
	detail, found, err := s.repository.GetPlatformDefinition(ctx, s.platformID, target.DefinitionID)
	if err != nil {
		return OfficialAgentCatalogEntry{}, err
	}
	if !found || detail.PlatformID != s.platformID || detail.Definition.ID != target.DefinitionID ||
		detail.Definition.Status != definitionStatusActive {
		return OfficialAgentCatalogEntry{}, ErrCloudUnavailable
	}
	version, found, err := s.repository.GetPlatformVersion(ctx, s.platformID, target.VersionID)
	if err != nil {
		return OfficialAgentCatalogEntry{}, err
	}
	if !found || version.ID != target.VersionID || version.DefinitionID != target.DefinitionID {
		return OfficialAgentCatalogEntry{}, ErrCloudUnavailable
	}
	installationState, updateState := OfficialInstallationNotInstalled, OfficialUpdateCurrent
	installation, found, err := s.repository.FindOfficialInstallation(ctx, principal, target.ReleaseID)
	if err != nil {
		return OfficialAgentCatalogEntry{}, err
	}
	if found {
		if installation.DeviceID != principal.DeviceID || installation.DefinitionID != target.DefinitionID ||
			installation.UpdatePolicy != installationUpdatePolicyManaged || installation.OfficialReleaseID == nil ||
			*installation.OfficialReleaseID != target.ReleaseID || installation.SelectedReleaseRevisionID == nil ||
			(installation.Status != InstallationStatusPending && installation.Status != InstallationStatusActive) {
			return OfficialAgentCatalogEntry{}, ErrCloudUnavailable
		}
		installationState = OfficialInstallationInstalled
		if installation.Status == InstallationStatusActive &&
			*installation.SelectedReleaseRevisionID != target.ReleaseRevisionID {
			updateState = OfficialUpdateAvailable
		}
	}
	return OfficialAgentCatalogEntry{
		DefinitionID: target.DefinitionID, DisplayName: detail.Definition.DisplayName,
		IconMediaType: detail.Definition.IconMediaType, IconData: append([]byte(nil), detail.Definition.IconData...),
		Version: cloneVersion(version), Target: target,
		InstallationState: installationState, UpdateState: updateState,
	}, nil
}

func isOfficialCatalogDenial(err error) bool {
	return errors.Is(err, ErrOfficialAgentNotEligible) || errors.Is(err, ErrOfficialReleasePaused) ||
		errors.Is(err, ErrOfficialClientVersionUnsupported) || errors.Is(err, ErrOfficialInstallationPolicyBlocked)
}

func (s *platformService) ResolveOfficialReleaseRevision(
	ctx context.Context,
	principal Principal,
	definitionID uuid.UUID,
	releaseRevisionID uuid.UUID,
	eligibilityContext OfficialEligibilityContext,
) (OfficialManagedTarget, error) {
	if s == nil || !validPrincipal(principal) || definitionID == uuid.Nil || releaseRevisionID == uuid.Nil ||
		!validOfficialEligibilityContext(principal, eligibilityContext) {
		return OfficialManagedTarget{}, ErrInvalidRequest
	}
	record, found, err := s.repository.GetOfficialEligibilityByRevision(
		ctx, s.platformID, definitionID, releaseRevisionID, principal, eligibilityContext,
	)
	if err != nil {
		return OfficialManagedTarget{}, err
	}
	if !found || record.Release.DefinitionID != definitionID || record.Revision.ID != releaseRevisionID {
		return OfficialManagedTarget{}, ErrOfficialAgentNotEligible
	}
	return s.EvaluateOfficialEligibilityRecord(principal, eligibilityContext, record, false)
}

func (s *platformService) EvaluateOfficialEligibilityRecord(
	principal Principal,
	eligibilityContext OfficialEligibilityContext,
	record OfficialEligibilityRecord,
	allowPaused bool,
) (OfficialManagedTarget, error) {
	if s == nil || !validPrincipal(principal) || !validOfficialEligibilityContext(principal, eligibilityContext) {
		return OfficialManagedTarget{}, ErrInvalidRequest
	}
	if !record.AccountDeviceActive {
		return OfficialManagedTarget{}, ErrOfficialAgentNotEligible
	}
	if !record.PlatformActive || !record.ChannelEntitled {
		return OfficialManagedTarget{}, ErrOfficialAgentNotEligible
	}
	releaseID := record.Release.ID
	if releaseID == uuid.Nil || record.Release.PlatformID != s.platformID || record.Release.DefinitionID == uuid.Nil ||
		record.Release.Channel != eligibilityContext.Channel || record.Release.CurrentRevisionID != record.Revision.ID ||
		record.Release.HeadRevision != record.Revision.RevisionNumber || record.Revision.ReleaseID != releaseID ||
		record.Revision.AgentVersionID == uuid.Nil || record.Revision.BucketAlgorithmVersion != officialBucketAlgorithmV1 ||
		record.Revision.RolloutBasisPoints < 0 || record.Revision.RolloutBasisPoints > 10000 {
		return OfficialManagedTarget{}, ErrCloudUnavailable
	}
	if record.Revision.State != OfficialReleaseStateActive {
		if record.Revision.State == OfficialReleaseStatePaused && !allowPaused {
			return OfficialManagedTarget{}, ErrOfficialReleasePaused
		}
		if record.Revision.State != OfficialReleaseStatePaused {
			return OfficialManagedTarget{}, ErrCloudUnavailable
		}
	}
	_, desktopVersion, desktopErr := parseSemanticVersion(eligibilityContext.DesktopVersion)
	_, minimumVersion, minimumErr := parseSemanticVersion(record.Revision.MinimumDesktopVersion)
	if desktopErr != nil {
		return OfficialManagedTarget{}, ErrInvalidRequest
	}
	if minimumErr != nil {
		return OfficialManagedTarget{}, ErrCloudUnavailable
	}
	if compareSemanticVersion(desktopVersion, minimumVersion) < 0 {
		return OfficialManagedTarget{}, ErrOfficialClientVersionUnsupported
	}
	if !record.ContextAuthorized {
		return OfficialManagedTarget{}, ErrOfficialAgentNotEligible
	}
	if !record.ContextPolicyAllowed {
		return OfficialManagedTarget{}, ErrOfficialInstallationPolicyBlocked
	}
	key, exists := s.rolloutKeys[record.Revision.RolloutKeyID]
	if !exists || len(key) != sha256.Size {
		return OfficialManagedTarget{}, ErrCloudUnavailable
	}
	if !record.UserAllowlisted && officialBucket(
		key, record.Revision.BucketAlgorithmVersion, releaseID, principal.UserID,
	) >= record.Revision.RolloutBasisPoints {
		return OfficialManagedTarget{}, ErrOfficialAgentNotEligible
	}
	return OfficialManagedTarget{
		PlatformID: s.platformID, ReleaseID: releaseID, ReleaseRevisionID: record.Revision.ID,
		DefinitionID: record.Release.DefinitionID, VersionID: record.Revision.AgentVersionID,
		Channel: record.Release.Channel, HeadRevision: record.Release.HeadRevision,
	}, nil
}

func (s *platformService) authorized(actor PlatformAdminActor, action platformAction) bool {
	return s != nil && actor.AdminID != uuid.Nil && validRequestID(actor.RequestID) && platformRoleAllowed(actor.Role, action)
}

func bindGeneratedPlatformOperationTarget(
	actor PlatformAdminActor,
	action string,
	targetType string,
	targetID uuid.UUID,
) (PlatformAdminActor, bool) {
	if actor.Operation == nil {
		return actor, true
	}
	if actor.Operation.Action != action || actor.Operation.TargetType != targetType || targetID == uuid.Nil {
		return PlatformAdminActor{}, false
	}
	proof := *actor.Operation
	proof.TargetID = targetID
	proof.IdempotencyKeyHMAC = bytes.Clone(proof.IdempotencyKeyHMAC)
	proof.RequestFingerprint = bytes.Clone(proof.RequestFingerprint)
	actor.Operation = &proof
	return actor, true
}

func platformRequestError(actor PlatformAdminActor, action platformAction) error {
	if actor.AdminID != uuid.Nil && validRequestID(actor.RequestID) && !platformRoleAllowed(actor.Role, action) {
		return ErrPlatformForbidden
	}
	return ErrInvalidRequest
}

func (s *platformService) ids(count int) ([]uuid.UUID, bool) {
	if s == nil || count <= 0 {
		return nil, false
	}
	values := make([]uuid.UUID, count)
	seen := make(map[uuid.UUID]struct{}, count)
	for index := range values {
		values[index] = s.newID()
		if values[index] == uuid.Nil {
			return nil, false
		}
		if _, exists := seen[values[index]]; exists {
			return nil, false
		}
		seen[values[index]] = struct{}{}
	}
	return values, true
}

func newPlatformIdempotency(id uuid.UUID, key string, requestHash [sha256.Size]byte, now time.Time) IdempotencyEvidence {
	return IdempotencyEvidence{
		ID: id, KeyHash: sha256.Sum256([]byte(key)), RequestHash: requestHash,
		ExpiresAt: now.Add(idempotencyLifetime),
	}
}

func platformDraftRequestHash(operation string, actor PlatformAdminActor, canonical CanonicalPlatformDraft, revision int64) ([sha256.Size]byte, error) {
	return hashRequest(struct {
		Operation        string            `json:"operation"`
		AdminID          string            `json:"admin_id"`
		DefinitionID     string            `json:"definition_id"`
		BaseVersionID    string            `json:"base_version_id,omitempty"`
		Kind             PlatformDraftKind `json:"kind"`
		DisplayName      string            `json:"display_name"`
		IconMediaType    string            `json:"icon_media_type,omitempty"`
		IconDigest       string            `json:"icon_digest,omitempty"`
		ContentDigest    string            `json:"content_digest"`
		ExpectedRevision int64             `json:"expected_revision,omitempty"`
	}{operation, actor.AdminID.String(), canonical.Package.DefinitionID.String(),
		canonical.Package.BaseVersionID.String(), canonical.Package.Kind,
		canonical.Package.DisplayName, canonical.Package.IconMediaType,
		digestHex(canonical.Package.IconData), digestArrayHex(canonical.ContentDigest), revision})
}

func platformTerminalRequestHash(operation string, platformID uuid.UUID, actor PlatformAdminActor, request TerminalPlatformSubmissionCommand) ([sha256.Size]byte, error) {
	return hashRequest(struct {
		Operation        string `json:"operation"`
		PlatformID       string `json:"platform_id"`
		SubmissionID     string `json:"submission_id"`
		ExpectedRevision int64  `json:"expected_revision"`
		AdminID          string `json:"admin_id"`
	}{operation, platformID.String(), request.SubmissionID.String(), request.ExpectedRevision, actor.AdminID.String()})
}

func officialReleaseRequestHash(command OfficialReleaseMutationRepositoryCommand) ([sha256.Size]byte, error) {
	return hashRequest(struct {
		Operation               OfficialReleaseAction `json:"operation"`
		PlatformID              string                `json:"platform_id"`
		ReleaseID               string                `json:"release_id"`
		ExpectedHeadRevision    int64                 `json:"expected_head_revision"`
		AdminID                 string                `json:"admin_id"`
		VersionID               string                `json:"version_id,omitempty"`
		TargetReleaseRevisionID string                `json:"target_release_revision_id,omitempty"`
		ApprovalID              string                `json:"approval_id,omitempty"`
		RolloutBasisPoints      int                   `json:"rollout_basis_points,omitempty"`
		MinimumDesktopVersion   string                `json:"minimum_desktop_version,omitempty"`
		RolloutKeyID            string                `json:"rollout_key_id,omitempty"`
		AudienceDigest          string                `json:"audience_digest"`
		ReasonCode              string                `json:"reason_code"`
		TicketReference         string                `json:"ticket_reference,omitempty"`
	}{
		Operation: command.Action, PlatformID: command.PlatformID.String(), ReleaseID: command.ReleaseID.String(),
		ExpectedHeadRevision: command.ExpectedHeadRevision, AdminID: command.Actor.AdminID.String(),
		VersionID: command.VersionID.String(), TargetReleaseRevisionID: command.TargetReleaseRevisionID.String(),
		ApprovalID: command.ApprovalID.String(), RolloutBasisPoints: command.RolloutBasisPoints,
		MinimumDesktopVersion: command.MinimumDesktopVersion, RolloutKeyID: command.RolloutKeyID,
		AudienceDigest: digestArrayHex(officialAudienceDigest(command.AllowlistedUserIDs)),
		ReasonCode:     command.ReasonCode, TicketReference: command.TicketReference,
	})
}

func officialBucket(key []byte, algorithmVersion string, releaseID uuid.UUID, userID uuid.UUID) int {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(algorithmVersion))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(releaseID.String()))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(userID.String()))
	digest := mac.Sum(nil)
	return int(binary.BigEndian.Uint64(digest[:8]) % 10000)
}

func canonicalOfficialAudience(input []uuid.UUID) ([]uuid.UUID, bool) {
	if len(input) > 10000 {
		return nil, false
	}
	result := append([]uuid.UUID(nil), input...)
	for _, userID := range result {
		if userID == uuid.Nil {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right uuid.UUID) int {
		return bytes.Compare(left[:], right[:])
	})
	result = slices.Compact(result)
	return result, true
}

func officialAudienceDigest(input []uuid.UUID) [sha256.Size]byte {
	hash := sha256.New()
	for _, userID := range input {
		_, _ = hash.Write([]byte(userID.String()))
		_, _ = hash.Write([]byte{0})
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validPlatformOperationEvidence(value PlatformOperationEvidence) bool {
	return platformReasonPattern.MatchString(value.ReasonCode) && validIdempotencyKey(value.IdempotencyKey) &&
		(value.TicketReference == "" || validPlatformTicketReference(value.TicketReference))
}

func validPlatformTicketReference(value string) bool {
	return value == strings.TrimSpace(value) && utf8.ValidString(value) && len([]rune(value)) <= 128 &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func validOfficialEligibilityContext(principal Principal, value OfficialEligibilityContext) bool {
	if value.Channel != OfficialChannelInternal && value.Channel != OfficialChannelStable {
		return false
	}
	if _, _, err := parseSemanticVersion(value.DesktopVersion); err != nil {
		return false
	}
	switch value.Selector.Scope {
	case OwnerScopeUser:
		return value.Selector.PersonalSpaceID == principal.PersonalSpaceID &&
			value.Selector.WorkspaceID == uuid.Nil && value.Selector.OrganizationID == uuid.Nil
	case OwnerScopeWorkspace:
		return value.Selector.PersonalSpaceID == uuid.Nil && value.Selector.WorkspaceID != uuid.Nil &&
			value.Selector.OrganizationID == uuid.Nil
	case OwnerScopeOrganization:
		return value.Selector.PersonalSpaceID == uuid.Nil && value.Selector.WorkspaceID == uuid.Nil &&
			value.Selector.OrganizationID != uuid.Nil
	default:
		return false
	}
}

func cloneRolloutKeys(input map[string][]byte) map[string][]byte {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string][]byte, len(input))
	for keyID, material := range input {
		result[keyID] = bytes.Clone(material)
	}
	return result
}

func cloneOfficialRelease(value OfficialRelease) OfficialRelease {
	value.CurrentRevision.AllowlistedUserIDs = append([]uuid.UUID(nil), value.CurrentRevision.AllowlistedUserIDs...)
	return value
}

func canonicalInitialChannels(decision PlatformReviewDecision, input []OfficialChannel) ([]OfficialChannel, bool) {
	if decision == PlatformReviewReject {
		return nil, len(input) == 0
	}
	if decision != PlatformReviewApprove || len(input) == 0 || len(input) > 8 {
		return nil, false
	}
	seen := make(map[OfficialChannel]struct{}, len(input))
	for _, channel := range input {
		if channel != OfficialChannelInternal && channel != OfficialChannelStable {
			return nil, false
		}
		seen[channel] = struct{}{}
	}
	result := make([]OfficialChannel, 0, len(seen))
	for _, channel := range []OfficialChannel{OfficialChannelInternal, OfficialChannelStable} {
		if _, exists := seen[channel]; exists {
			result = append(result, channel)
		}
	}
	return result, len(result) > 0 && len(result) <= 2
}

func validPlatformReviewText(request ReviewPlatformSubmissionCommand) bool {
	switch request.Decision {
	case PlatformReviewApprove:
		return request.ReasonCode == "" && request.SafeNote == ""
	case PlatformReviewReject:
		return platformReasonPattern.MatchString(request.ReasonCode) &&
			(request.SafeNote == "" || validOrganizationReviewNote(request.SafeNote))
	default:
		return false
	}
}

type PlatformPublicationDLPError struct {
	Findings []ExperienceCandidateFinding
}

func (err *PlatformPublicationDLPError) Error() string {
	return ErrPlatformPublicationDLPBlocked.Error()
}

func (err *PlatformPublicationDLPError) Unwrap() error { return ErrPlatformPublicationDLPBlocked }

func canonicalFromPlatformDraft(value PlatformAgentDraft) (CanonicalPlatformDraft, error) {
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: value.DefinitionID, BaseVersionID: value.BaseVersionID, Kind: value.Kind,
		DisplayName: value.DisplayName, IconMediaType: value.IconMediaType, IconData: value.IconData,
		Manifest: value.Manifest, Bundle: value.Bundle,
	})
	if err != nil || canonical.ManifestDigest != value.ManifestDigest ||
		canonical.BundleDigest != value.BundleDigest || canonical.ContentDigest != value.ContentDigest {
		return CanonicalPlatformDraft{}, ErrOfficialVersionIntegrityFailed
	}
	return canonical, nil
}

func validPageRequest(value PageRequest) bool {
	return value.Limit >= 0 && value.Limit <= platformDraftPageLimitMax
}

func validPlatformDisplayName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > 100 {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

func normalizePageRequest(value PageRequest) PageRequest {
	if value.Limit == 0 {
		value.Limit = platformDraftPageLimit
	}
	return value
}

func validPlatformSubmissionFilter(value PlatformSubmissionFilter) bool {
	if !validPageRequest(value.Page) {
		return false
	}
	switch value.Status {
	case "", PlatformSubmissionPending, PlatformSubmissionApproved, PlatformSubmissionRejected,
		PlatformSubmissionWithdrawn, PlatformSubmissionSuperseded:
		return true
	default:
		return false
	}
}

func clonePlatformReservation(value PlatformDefinitionReservation) PlatformDefinitionReservation {
	value.IconData = bytes.Clone(value.IconData)
	return value
}

func clonePlatformDefinitionDetail(value PlatformDefinitionDetail) PlatformDefinitionDetail {
	value.Definition.IconData = bytes.Clone(value.Definition.IconData)
	value.Definition.LatestVersionID = cloneUUIDPointer(value.Definition.LatestVersionID)
	return value
}

func clonePlatformDraft(value PlatformAgentDraft) PlatformAgentDraft {
	value.IconData = bytes.Clone(value.IconData)
	value.Manifest = cloneAgentManifest(value.Manifest)
	value.Bundle = cloneVersionBundle(value.Bundle)
	return value
}

func clonePlatformSubmission(value PlatformAgentSubmission) PlatformAgentSubmission {
	value.IconData = bytes.Clone(value.IconData)
	value.Manifest = cloneAgentManifest(value.Manifest)
	value.Bundle = cloneVersionBundle(value.Bundle)
	value.TerminalAt = cloneTimePointer(value.TerminalAt)
	if value.Review != nil {
		review := *value.Review
		value.Review = &review
	}
	return value
}

func clonePlatformDefinitionPage(value PlatformDefinitionPage) PlatformDefinitionPage {
	value.Items = slices.Clone(value.Items)
	for index := range value.Items {
		value.Items[index] = clonePlatformDefinitionDetail(value.Items[index])
	}
	return value
}

func clonePlatformDraftPage(value PlatformDraftPage) PlatformDraftPage {
	value.Items = slices.Clone(value.Items)
	for index := range value.Items {
		value.Items[index] = clonePlatformDraft(value.Items[index])
	}
	return value
}

func clonePlatformSubmissionPage(value PlatformSubmissionPage) PlatformSubmissionPage {
	value.Items = slices.Clone(value.Items)
	for index := range value.Items {
		value.Items[index] = clonePlatformSubmission(value.Items[index])
	}
	return value
}

func clonePlatformVersionPage(value PlatformVersionPage) PlatformVersionPage {
	value.Items = slices.Clone(value.Items)
	for index := range value.Items {
		value.Items[index] = cloneVersion(value.Items[index])
	}
	return value
}

func cloneOfficialReleasePage(value OfficialReleasePage) OfficialReleasePage {
	items := make([]OfficialRelease, len(value.Items))
	for index := range value.Items {
		items[index] = cloneOfficialRelease(value.Items[index])
	}
	value.Items = items
	return value
}

func cloneOfficialDeliveryVerificationSummary(
	value OfficialDeliveryVerificationSummary,
) OfficialDeliveryVerificationSummary {
	value.Stages = slices.Clone(value.Stages)
	return value
}

func cloneOfficialDeliveryTarget(value OfficialDeliveryTarget) OfficialDeliveryTarget {
	value.Releases = slices.Clone(value.Releases)
	return value
}
