package officialquality

import (
	"context"
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
	QualityRoleDeveloper  = "developer"
	QualityRoleSuperAdmin = "super_admin"
	QualityRoleOperator   = "operator"
	QualityRoleAuditor    = "auditor"

	ProposalReviewApprove = "approve"
	ProposalReviewReject  = "reject"

	qualityActionProposalCreate = "official_quality_proposal_create"
	qualityActionProposalSubmit = "official_quality_proposal_submit"
	qualityActionProposalReview = "official_quality_proposal_review"
	qualityActionDraftClone     = "official_quality_draft_clone"
)

var (
	ErrAdminForbidden        = errors.New("official quality admin action is forbidden")
	ErrProposalNotFound      = errors.New("official quality proposal was not found")
	ErrProposalStateConflict = errors.New("official quality proposal state conflicts with the request")
)

var qualityRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type ProposalStatus string

const (
	ProposalStatusOpen        ProposalStatus = "open"
	ProposalStatusSubmitted   ProposalStatus = "submitted"
	ProposalStatusApproved    ProposalStatus = "approved"
	ProposalStatusRejected    ProposalStatus = "rejected"
	ProposalStatusDraftLinked ProposalStatus = "draft_linked"
	ProposalStatusClosed      ProposalStatus = "closed"
)

type QualityAdminOperationProof struct {
	OperationID        uuid.UUID
	Action             string
	TargetType         string
	TargetID           uuid.UUID
	ExpectedRevision   int64
	ServiceSubject     string
	IdempotencyKeyID   string
	IdempotencyKeyHMAC []byte
	RequestFingerprint []byte
	ReasonCode         string
	TicketReference    string
}

type QualityAdminActor struct {
	AdminID   uuid.UUID
	Role      string
	RequestID string
	Operation *QualityAdminOperationProof
}

type ProposalReview struct {
	ID               uuid.UUID `json:"review_id"`
	ReviewerAdminID  uuid.UUID `json:"reviewer_admin_id"`
	ReviewerRole     string    `json:"reviewer_role"`
	Decision         string    `json:"decision"`
	ReviewedRevision int64     `json:"reviewed_revision"`
	ReasonCode       string    `json:"reason_code"`
	TicketReference  string    `json:"ticket_reference,omitempty"`
	ReviewedAt       time.Time `json:"reviewed_at"`
}

type Proposal struct {
	ID                   uuid.UUID       `json:"proposal_id"`
	PlatformID           uuid.UUID       `json:"platform_id"`
	DefinitionID         uuid.UUID       `json:"definition_id"`
	VersionID            uuid.UUID       `json:"version_id"`
	ReleaseID            uuid.UUID       `json:"release_id"`
	ReleaseRevisionID    uuid.UUID       `json:"release_revision_id"`
	AggregateIDs         []uuid.UUID     `json:"aggregate_ids"`
	ProblemCategories    []string        `json:"problem_categories"`
	ImprovementObjective string          `json:"improvement_objective"`
	CreatedByAdminID     uuid.UUID       `json:"created_by_admin_id"`
	CreatedByRole        string          `json:"created_by_role"`
	Status               ProposalStatus  `json:"status"`
	Revision             int64           `json:"revision"`
	ReasonCode           string          `json:"reason_code"`
	TicketReference      string          `json:"ticket_reference,omitempty"`
	LinkedDraftID        uuid.UUID       `json:"linked_draft_id,omitempty"`
	Review               *ProposalReview `json:"review,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
	TerminalAt           *time.Time      `json:"terminal_at,omitempty"`
	Replayed             bool            `json:"replayed,omitempty"`
}

type ProposalFilter struct {
	PlatformID uuid.UUID
	Status     ProposalStatus
}

type ProposalPageRequest struct {
	After uuid.UUID
	Limit int
}

type ProposalPage struct {
	Items []Proposal `json:"items"`
	Next  uuid.UUID  `json:"-"`
}

type CreateProposalCommand struct {
	AggregateIDs         []uuid.UUID
	ProblemCategories    []string
	ImprovementObjective string
}

type SubmitProposalCommand struct {
	ProposalID       uuid.UUID
	ExpectedRevision int64
}

type ReviewProposalCommand struct {
	ProposalID       uuid.UUID
	ExpectedRevision int64
	Decision         string
}

type CloneProposalCommand struct {
	ProposalID       uuid.UUID
	ExpectedRevision int64
}

type CreateProposalRepositoryCommand struct {
	ProposalID           uuid.UUID
	PlatformID           uuid.UUID
	AggregateIDs         []uuid.UUID
	ProblemCategories    []string
	ImprovementObjective string
	MinimumSubjects      int
	Actor                QualityAdminActor
	CreatedAt            time.Time
}

type SubmitProposalRepositoryCommand struct {
	PlatformID       uuid.UUID
	ProposalID       uuid.UUID
	ExpectedRevision int64
	Actor            QualityAdminActor
	SubmittedAt      time.Time
}

type ReviewProposalRepositoryCommand struct {
	ReviewID         uuid.UUID
	PlatformID       uuid.UUID
	ProposalID       uuid.UUID
	ExpectedRevision int64
	Decision         string
	Actor            QualityAdminActor
	ReviewedAt       time.Time
}

type LinkProposalDraftRepositoryCommand struct {
	PlatformID       uuid.UUID
	ProposalID       uuid.UUID
	DraftID          uuid.UUID
	ExpectedRevision int64
	Actor            QualityAdminActor
	LinkedAt         time.Time
}

type ProposalRepository interface {
	CreateProposal(context.Context, CreateProposalRepositoryCommand) (Proposal, error)
	GetProposal(context.Context, uuid.UUID, uuid.UUID) (Proposal, error)
	SubmitProposal(context.Context, SubmitProposalRepositoryCommand) (Proposal, error)
	ReviewProposal(context.Context, ReviewProposalRepositoryCommand) (Proposal, error)
	LinkProposalDraft(context.Context, LinkProposalDraftRepositoryCommand) (Proposal, error)
	ListProposals(context.Context, ProposalFilter, ProposalPageRequest) (ProposalPage, error)
}

type AggregateReader interface {
	ListAggregates(context.Context, AggregateFilter, AggregatePageRequest, int) (AggregatePage, error)
}

type CloneApprovedProposalCommand struct {
	ProposalID     uuid.UUID
	PlatformID     uuid.UUID
	DefinitionID   uuid.UUID
	BaseVersionID  uuid.UUID
	ActorAdminID   uuid.UUID
	ActorRole      string
	RequestID      string
	IdempotencyKey string
}

type PlatformDraftCloner interface {
	CloneApprovedProposal(context.Context, CloneApprovedProposalCommand) (uuid.UUID, error)
}

type ProposalServiceConfig struct {
	Repository      ProposalRepository
	AggregateReader AggregateReader
	Scanner         QualityScanner
	DraftCloner     PlatformDraftCloner
	PlatformID      uuid.UUID
	MinimumSubjects int
	Clock           func() time.Time
	NewID           func() uuid.UUID
}

type ProposalService struct {
	repository      ProposalRepository
	aggregates      AggregateReader
	scanner         QualityScanner
	draftCloner     PlatformDraftCloner
	platformID      uuid.UUID
	minimumSubjects int
	clock           func() time.Time
	newID           func() uuid.UUID
}

type AdminService interface {
	ListAggregates(context.Context, QualityAdminActor, AggregateFilter, AggregatePageRequest) (AggregatePage, error)
	Create(context.Context, QualityAdminActor, CreateProposalCommand) (Proposal, error)
	Submit(context.Context, QualityAdminActor, SubmitProposalCommand) (Proposal, error)
	Review(context.Context, QualityAdminActor, ReviewProposalCommand) (Proposal, error)
	CloneToDraft(context.Context, QualityAdminActor, CloneProposalCommand) (Proposal, error)
	GetProposal(context.Context, QualityAdminActor, uuid.UUID) (Proposal, error)
	ListProposals(context.Context, QualityAdminActor, ProposalFilter, ProposalPageRequest) (ProposalPage, error)
}

func NewProposalService(config ProposalServiceConfig) (*ProposalService, error) {
	if config.Repository == nil || config.AggregateReader == nil || config.Scanner == nil ||
		config.DraftCloner == nil || config.PlatformID == uuid.Nil || config.MinimumSubjects < 10 {
		return nil, errors.New("official quality proposal service configuration is incomplete")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	newID := config.NewID
	if newID == nil {
		newID = uuid.New
	}
	return &ProposalService{
		repository: config.Repository, aggregates: config.AggregateReader,
		scanner: config.Scanner, draftCloner: config.DraftCloner,
		platformID: config.PlatformID, minimumSubjects: config.MinimumSubjects,
		clock: clock, newID: newID,
	}, nil
}

func (service *ProposalService) Create(
	ctx context.Context,
	actor QualityAdminActor,
	command CreateProposalCommand,
) (Proposal, error) {
	if service == nil || !qualityActorAllowed(actor, qualityActionProposalCreate) {
		return Proposal{}, ErrAdminForbidden
	}
	aggregateIDs, ok := validAggregateIDs(command.AggregateIDs)
	categories, categoriesOK := canonicalProblemCategories(command.ProblemCategories)
	objective := strings.TrimSpace(command.ImprovementObjective)
	if !ok || !categoriesOK || objective != command.ImprovementObjective || !validQualityText(objective, 20, 2000) {
		return Proposal{}, ErrInvalidRequest
	}
	if err := service.scanner.Scan([]byte(objective)); err != nil {
		if errors.Is(err, ErrDLPRejected) {
			return Proposal{}, ErrDLPRejected
		}
		return Proposal{}, ErrServiceUnavailable
	}
	proposalID := service.newID()
	if proposalID == uuid.Nil {
		return Proposal{}, ErrServiceUnavailable
	}
	actor, ok = bindQualityOperationTarget(actor, qualityActionProposalCreate, proposalID)
	if !ok {
		return Proposal{}, ErrInvalidRequest
	}
	return service.repository.CreateProposal(ctx, CreateProposalRepositoryCommand{
		ProposalID: proposalID, PlatformID: service.platformID,
		AggregateIDs: aggregateIDs, ProblemCategories: categories,
		ImprovementObjective: objective, MinimumSubjects: service.minimumSubjects,
		Actor: actor, CreatedAt: service.clock().UTC(),
	})
}

func (service *ProposalService) Submit(
	ctx context.Context,
	actor QualityAdminActor,
	command SubmitProposalCommand,
) (Proposal, error) {
	if service == nil || !qualityActorAllowed(actor, qualityActionProposalSubmit) {
		return Proposal{}, ErrAdminForbidden
	}
	if command.ProposalID == uuid.Nil || command.ExpectedRevision <= 0 {
		return Proposal{}, ErrInvalidRequest
	}
	actor, ok := bindQualityOperationTarget(actor, qualityActionProposalSubmit, command.ProposalID)
	if !ok {
		return Proposal{}, ErrInvalidRequest
	}
	return service.repository.SubmitProposal(ctx, SubmitProposalRepositoryCommand{
		PlatformID: service.platformID, ProposalID: command.ProposalID,
		ExpectedRevision: command.ExpectedRevision, Actor: actor, SubmittedAt: service.clock().UTC(),
	})
}

func (service *ProposalService) Review(
	ctx context.Context,
	actor QualityAdminActor,
	command ReviewProposalCommand,
) (Proposal, error) {
	if service == nil || !qualityActorAllowed(actor, qualityActionProposalReview) {
		return Proposal{}, ErrAdminForbidden
	}
	if command.ProposalID == uuid.Nil || command.ExpectedRevision <= 0 ||
		(command.Decision != ProposalReviewApprove && command.Decision != ProposalReviewReject) {
		return Proposal{}, ErrInvalidRequest
	}
	proposal, err := service.repository.GetProposal(ctx, service.platformID, command.ProposalID)
	if err != nil {
		return Proposal{}, err
	}
	if proposal.CreatedByAdminID == actor.AdminID {
		return Proposal{}, ErrAdminForbidden
	}
	if proposal.Status != ProposalStatusSubmitted && proposal.Status != ProposalStatusApproved &&
		proposal.Status != ProposalStatusRejected {
		return Proposal{}, ErrProposalStateConflict
	}
	reviewID := service.newID()
	if reviewID == uuid.Nil {
		return Proposal{}, ErrServiceUnavailable
	}
	actor, ok := bindQualityOperationTarget(actor, qualityActionProposalReview, command.ProposalID)
	if !ok {
		return Proposal{}, ErrInvalidRequest
	}
	return service.repository.ReviewProposal(ctx, ReviewProposalRepositoryCommand{
		ReviewID: reviewID, PlatformID: service.platformID, ProposalID: command.ProposalID,
		ExpectedRevision: command.ExpectedRevision, Decision: command.Decision,
		Actor: actor, ReviewedAt: service.clock().UTC(),
	})
}

func (service *ProposalService) CloneToDraft(
	ctx context.Context,
	actor QualityAdminActor,
	command CloneProposalCommand,
) (Proposal, error) {
	if service == nil || !qualityActorAllowed(actor, qualityActionDraftClone) {
		return Proposal{}, ErrAdminForbidden
	}
	if command.ProposalID == uuid.Nil || command.ExpectedRevision <= 0 {
		return Proposal{}, ErrInvalidRequest
	}
	proposal, err := service.repository.GetProposal(ctx, service.platformID, command.ProposalID)
	if err != nil {
		return Proposal{}, err
	}
	actor, ok := bindQualityOperationTarget(actor, qualityActionDraftClone, command.ProposalID)
	if !ok {
		return Proposal{}, ErrInvalidRequest
	}
	if proposal.Status == ProposalStatusDraftLinked && proposal.LinkedDraftID != uuid.Nil {
		return service.repository.LinkProposalDraft(ctx, LinkProposalDraftRepositoryCommand{
			PlatformID: service.platformID, ProposalID: proposal.ID, DraftID: proposal.LinkedDraftID,
			ExpectedRevision: command.ExpectedRevision, Actor: actor, LinkedAt: service.clock().UTC(),
		})
	}
	if proposal.Status != ProposalStatusApproved || proposal.Revision != command.ExpectedRevision {
		return Proposal{}, ErrProposalStateConflict
	}
	draftID, err := service.draftCloner.CloneApprovedProposal(ctx, CloneApprovedProposalCommand{
		ProposalID: proposal.ID, PlatformID: proposal.PlatformID,
		DefinitionID: proposal.DefinitionID, BaseVersionID: proposal.VersionID,
		ActorAdminID: actor.AdminID, ActorRole: actor.Role, RequestID: actor.RequestID,
		IdempotencyKey: proposal.ID.String(),
	})
	if err != nil {
		return Proposal{}, err
	}
	if draftID == uuid.Nil {
		return Proposal{}, ErrServiceUnavailable
	}
	return service.repository.LinkProposalDraft(ctx, LinkProposalDraftRepositoryCommand{
		PlatformID: service.platformID, ProposalID: proposal.ID, DraftID: draftID,
		ExpectedRevision: command.ExpectedRevision, Actor: actor, LinkedAt: service.clock().UTC(),
	})
}

func (service *ProposalService) ListAggregates(
	ctx context.Context,
	actor QualityAdminActor,
	filter AggregateFilter,
	page AggregatePageRequest,
) (AggregatePage, error) {
	if service == nil || !qualityActorCanReadAggregates(actor) || filter.PlatformID != service.platformID {
		return AggregatePage{}, ErrAdminForbidden
	}
	return service.aggregates.ListAggregates(ctx, filter, page, service.minimumSubjects)
}

func (service *ProposalService) GetProposal(ctx context.Context, actor QualityAdminActor, proposalID uuid.UUID) (Proposal, error) {
	if service == nil || !qualityActorCanReadProposals(actor) {
		return Proposal{}, ErrAdminForbidden
	}
	if proposalID == uuid.Nil {
		return Proposal{}, ErrInvalidRequest
	}
	return service.repository.GetProposal(ctx, service.platformID, proposalID)
}

func (service *ProposalService) ListProposals(
	ctx context.Context,
	actor QualityAdminActor,
	filter ProposalFilter,
	page ProposalPageRequest,
) (ProposalPage, error) {
	if service == nil || !qualityActorCanReadProposals(actor) || filter.PlatformID != service.platformID {
		return ProposalPage{}, ErrAdminForbidden
	}
	return service.repository.ListProposals(ctx, filter, page)
}

func qualityActorAllowed(actor QualityAdminActor, action string) bool {
	if actor.AdminID == uuid.Nil || !qualityRequestIDPattern.MatchString(actor.RequestID) {
		return false
	}
	switch action {
	case qualityActionProposalCreate, qualityActionProposalSubmit, qualityActionDraftClone:
		return actor.Role == QualityRoleDeveloper
	case qualityActionProposalReview:
		return actor.Role == QualityRoleSuperAdmin
	default:
		return false
	}
}

func qualityActorCanReadAggregates(actor QualityAdminActor) bool {
	if actor.AdminID == uuid.Nil || !qualityRequestIDPattern.MatchString(actor.RequestID) {
		return false
	}
	return actor.Role == QualityRoleDeveloper || actor.Role == QualityRoleSuperAdmin ||
		actor.Role == QualityRoleOperator || actor.Role == QualityRoleAuditor
}

func qualityActorCanReadProposals(actor QualityAdminActor) bool {
	if actor.AdminID == uuid.Nil || !qualityRequestIDPattern.MatchString(actor.RequestID) {
		return false
	}
	return actor.Role == QualityRoleDeveloper || actor.Role == QualityRoleSuperAdmin || actor.Role == QualityRoleAuditor
}

func bindQualityOperationTarget(actor QualityAdminActor, action string, targetID uuid.UUID) (QualityAdminActor, bool) {
	if actor.Operation == nil {
		return actor, true
	}
	if actor.Operation.OperationID == uuid.Nil || actor.Operation.Action != action ||
		actor.Operation.TargetType != "official_quality_proposal" ||
		actor.Operation.ExpectedRevision <= 0 || targetID == uuid.Nil {
		return QualityAdminActor{}, false
	}
	proof := *actor.Operation
	proof.TargetID = targetID
	proof.IdempotencyKeyHMAC = slices.Clone(proof.IdempotencyKeyHMAC)
	proof.RequestFingerprint = slices.Clone(proof.RequestFingerprint)
	actor.Operation = &proof
	return actor, true
}

func validAggregateIDs(values []uuid.UUID) ([]uuid.UUID, bool) {
	if len(values) == 0 || len(values) > 100 {
		return nil, false
	}
	result := slices.Clone(values)
	seen := make(map[uuid.UUID]struct{}, len(result))
	for _, value := range result {
		if value == uuid.Nil {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		seen[value] = struct{}{}
	}
	return result, true
}

func canonicalProblemCategories(values []string) ([]string, bool) {
	if len(values) == 0 || len(values) > 6 {
		return nil, false
	}
	allowed := map[string]struct{}{
		"reliability": {}, "latency": {}, "tool_quality": {},
		"correctness": {}, "safety": {}, "usability": {},
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, len(result) > 0
}

func validQualityText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum && strings.IndexFunc(value, unicode.IsControl) < 0
}
