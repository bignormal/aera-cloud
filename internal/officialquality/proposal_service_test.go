package officialquality

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProposalServiceRoleSeparationAndApprovalDoesNotCreateDraft(t *testing.T) {
	fixture := newProposalServiceFixture(t)
	proposal := fixture.proposal(ProposalStatusSubmitted)
	fixture.repository.get = func(context.Context, uuid.UUID, uuid.UUID) (Proposal, error) {
		return proposal, nil
	}
	fixture.repository.review = func(_ context.Context, command ReviewProposalRepositoryCommand) (Proposal, error) {
		proposal.Status = ProposalStatusApproved
		proposal.Revision = command.ExpectedRevision + 1
		proposal.Review = &ProposalReview{
			ID: command.ReviewID, ReviewerAdminID: command.Actor.AdminID,
			ReviewerRole: command.Actor.Role, Decision: command.Decision,
			ReviewedRevision: command.ExpectedRevision, ReviewedAt: command.ReviewedAt,
		}
		return proposal, nil
	}

	_, err := fixture.service.Review(context.Background(), fixture.developer, ReviewProposalCommand{
		ProposalID: proposal.ID, ExpectedRevision: proposal.Revision, Decision: ProposalReviewApprove,
	})
	if !errors.Is(err, ErrAdminForbidden) {
		t.Fatalf("Review(developer) error = %v, want ErrAdminForbidden", err)
	}
	_, err = fixture.service.Review(context.Background(), QualityAdminActor{
		AdminID: proposal.CreatedByAdminID, Role: QualityRoleSuperAdmin, RequestID: "req-self-review",
	}, ReviewProposalCommand{
		ProposalID: proposal.ID, ExpectedRevision: proposal.Revision, Decision: ProposalReviewApprove,
	})
	if !errors.Is(err, ErrAdminForbidden) {
		t.Fatalf("Review(creator) error = %v, want ErrAdminForbidden", err)
	}

	initialRevision := proposal.Revision
	approved, err := fixture.service.Review(context.Background(), fixture.superAdmin, ReviewProposalCommand{
		ProposalID: proposal.ID, ExpectedRevision: proposal.Revision, Decision: ProposalReviewApprove,
	})
	if err != nil || approved.Status != ProposalStatusApproved || approved.Revision != initialRevision+1 {
		t.Fatalf("Review(super_admin) = %+v error=%v", approved, err)
	}
	if fixture.cloner.calls != 0 {
		t.Fatalf("proposal approval created %d drafts, want 0", fixture.cloner.calls)
	}
}

func TestProposalServiceCreatesOnlyFromHumanObjectiveAndThresholdedAggregateIDs(t *testing.T) {
	fixture := newProposalServiceFixture(t)
	aggregateIDs := []uuid.UUID{uuid.New(), uuid.New()}
	var captured CreateProposalRepositoryCommand
	fixture.repository.create = func(_ context.Context, command CreateProposalRepositoryCommand) (Proposal, error) {
		captured = command
		return Proposal{
			ID: command.ProposalID, PlatformID: command.PlatformID,
			AggregateIDs:         append([]uuid.UUID(nil), command.AggregateIDs...),
			ProblemCategories:    append([]string(nil), command.ProblemCategories...),
			ImprovementObjective: command.ImprovementObjective,
			CreatedByAdminID:     command.Actor.AdminID, CreatedByRole: command.Actor.Role,
			Status: ProposalStatusOpen, Revision: 1, CreatedAt: command.CreatedAt, UpdatedAt: command.CreatedAt,
		}, nil
	}

	created, err := fixture.service.Create(context.Background(), fixture.developer, CreateProposalCommand{
		AggregateIDs:         aggregateIDs,
		ProblemCategories:    []string{"latency", "reliability", "latency"},
		ImprovementObjective: "Reduce bounded latency without changing user-owned runtime data.",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Status != ProposalStatusOpen || captured.MinimumSubjects != 10 ||
		!reflect.DeepEqual(captured.ProblemCategories, []string{"latency", "reliability"}) ||
		!reflect.DeepEqual(captured.AggregateIDs, aggregateIDs) {
		t.Fatalf("Create() captured = %+v result=%+v", captured, created)
	}
	if captured.ImprovementObjective == "" || captured.Actor.Role != QualityRoleDeveloper {
		t.Fatalf("Create() lost human objective/actor: %+v", captured)
	}

	fixture.scanner.err = ErrDLPRejected
	if _, err := fixture.service.Create(context.Background(), fixture.developer, CreateProposalCommand{
		AggregateIDs: aggregateIDs, ProblemCategories: []string{"correctness"},
		ImprovementObjective: "Copied private conversation content must not be accepted here.",
	}); !errors.Is(err, ErrDLPRejected) {
		t.Fatalf("Create(DLP) error = %v, want ErrDLPRejected", err)
	}
	if _, err := fixture.service.Create(context.Background(), fixture.superAdmin, CreateProposalCommand{
		AggregateIDs: aggregateIDs, ProblemCategories: []string{"correctness"},
		ImprovementObjective: "A super admin must not author the developer improvement proposal.",
	}); !errors.Is(err, ErrAdminForbidden) {
		t.Fatalf("Create(super_admin) error = %v, want ErrAdminForbidden", err)
	}
}

func TestProposalServiceExplicitCloneCopiesOnlyImmutableBaseReference(t *testing.T) {
	fixture := newProposalServiceFixture(t)
	proposal := fixture.proposal(ProposalStatusApproved)
	proposal.Revision = 3
	fixture.repository.get = func(context.Context, uuid.UUID, uuid.UUID) (Proposal, error) {
		return proposal, nil
	}
	fixture.repository.link = func(_ context.Context, command LinkProposalDraftRepositoryCommand) (Proposal, error) {
		proposal.Status = ProposalStatusDraftLinked
		proposal.Revision = command.ExpectedRevision + 1
		proposal.LinkedDraftID = command.DraftID
		return proposal, nil
	}

	linked, err := fixture.service.CloneToDraft(context.Background(), fixture.developer, CloneProposalCommand{
		ProposalID: proposal.ID, ExpectedRevision: proposal.Revision,
	})
	if err != nil {
		t.Fatalf("CloneToDraft() error = %v", err)
	}
	if linked.Status != ProposalStatusDraftLinked || linked.LinkedDraftID != fixture.cloner.draftID {
		t.Fatalf("CloneToDraft() = %+v", linked)
	}
	if fixture.cloner.calls != 1 || fixture.cloner.command.ProposalID != proposal.ID ||
		fixture.cloner.command.PlatformID != proposal.PlatformID ||
		fixture.cloner.command.DefinitionID != proposal.DefinitionID ||
		fixture.cloner.command.BaseVersionID != proposal.VersionID ||
		fixture.cloner.command.ActorAdminID != fixture.developer.AdminID {
		t.Fatalf("CloneApprovedProposal() command = %+v calls=%d", fixture.cloner.command, fixture.cloner.calls)
	}

	proposal.Status = ProposalStatusSubmitted
	if _, err := fixture.service.CloneToDraft(context.Background(), fixture.developer, CloneProposalCommand{
		ProposalID: proposal.ID, ExpectedRevision: proposal.Revision,
	}); !errors.Is(err, ErrProposalStateConflict) {
		t.Fatalf("CloneToDraft(submitted) error = %v, want ErrProposalStateConflict", err)
	}
	if _, err := fixture.service.CloneToDraft(context.Background(), fixture.superAdmin, CloneProposalCommand{
		ProposalID: proposal.ID, ExpectedRevision: proposal.Revision,
	}); !errors.Is(err, ErrAdminForbidden) {
		t.Fatalf("CloneToDraft(super_admin) error = %v, want ErrAdminForbidden", err)
	}
}

type proposalServiceRepositoryStub struct {
	create func(context.Context, CreateProposalRepositoryCommand) (Proposal, error)
	get    func(context.Context, uuid.UUID, uuid.UUID) (Proposal, error)
	submit func(context.Context, SubmitProposalRepositoryCommand) (Proposal, error)
	review func(context.Context, ReviewProposalRepositoryCommand) (Proposal, error)
	link   func(context.Context, LinkProposalDraftRepositoryCommand) (Proposal, error)
}

func (stub *proposalServiceRepositoryStub) CreateProposal(ctx context.Context, command CreateProposalRepositoryCommand) (Proposal, error) {
	return stub.create(ctx, command)
}

func (stub *proposalServiceRepositoryStub) GetProposal(ctx context.Context, platformID, proposalID uuid.UUID) (Proposal, error) {
	return stub.get(ctx, platformID, proposalID)
}

func (stub *proposalServiceRepositoryStub) SubmitProposal(ctx context.Context, command SubmitProposalRepositoryCommand) (Proposal, error) {
	return stub.submit(ctx, command)
}

func (stub *proposalServiceRepositoryStub) ReviewProposal(ctx context.Context, command ReviewProposalRepositoryCommand) (Proposal, error) {
	return stub.review(ctx, command)
}

func (stub *proposalServiceRepositoryStub) LinkProposalDraft(ctx context.Context, command LinkProposalDraftRepositoryCommand) (Proposal, error) {
	return stub.link(ctx, command)
}

func (stub *proposalServiceRepositoryStub) ListProposals(context.Context, ProposalFilter, ProposalPageRequest) (ProposalPage, error) {
	return ProposalPage{Items: []Proposal{}}, nil
}

type proposalScannerStub struct{ err error }

func (stub *proposalScannerStub) Scan([]byte) error { return stub.err }

type proposalDraftClonerStub struct {
	calls   int
	command CloneApprovedProposalCommand
	draftID uuid.UUID
	err     error
}

func (stub *proposalDraftClonerStub) CloneApprovedProposal(_ context.Context, command CloneApprovedProposalCommand) (uuid.UUID, error) {
	stub.calls++
	stub.command = command
	return stub.draftID, stub.err
}

type proposalServiceFixture struct {
	service     *ProposalService
	repository  *proposalServiceRepositoryStub
	scanner     *proposalScannerStub
	cloner      *proposalDraftClonerStub
	platformID  uuid.UUID
	developer   QualityAdminActor
	superAdmin  QualityAdminActor
	now         time.Time
	proposalIDs []uuid.UUID
}

func newProposalServiceFixture(t *testing.T) *proposalServiceFixture {
	t.Helper()
	now := time.Date(2026, 7, 23, 9, 0, 0, 0, time.UTC)
	repository := &proposalServiceRepositoryStub{}
	scanner := &proposalScannerStub{}
	cloner := &proposalDraftClonerStub{draftID: uuid.New()}
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	index := 0
	service, err := NewProposalService(ProposalServiceConfig{
		Repository: repository, AggregateReader: &proposalAggregateReaderStub{},
		Scanner: scanner, DraftCloner: cloner, PlatformID: uuid.New(), MinimumSubjects: 10,
		Clock: func() time.Time { return now }, NewID: func() uuid.UUID {
			value := ids[index]
			index++
			return value
		},
	})
	if err != nil {
		t.Fatalf("NewProposalService() error = %v", err)
	}
	return &proposalServiceFixture{
		service: service, repository: repository, scanner: scanner, cloner: cloner,
		platformID: service.platformID, now: now, proposalIDs: ids,
		developer:  QualityAdminActor{AdminID: uuid.New(), Role: QualityRoleDeveloper, RequestID: "req-developer"},
		superAdmin: QualityAdminActor{AdminID: uuid.New(), Role: QualityRoleSuperAdmin, RequestID: "req-super-admin"},
	}
}

func (fixture *proposalServiceFixture) proposal(status ProposalStatus) Proposal {
	return Proposal{
		ID: uuid.New(), PlatformID: fixture.platformID, DefinitionID: uuid.New(),
		VersionID: uuid.New(), ReleaseID: uuid.New(), ReleaseRevisionID: uuid.New(),
		AggregateIDs: []uuid.UUID{uuid.New()}, ProblemCategories: []string{"latency"},
		ImprovementObjective: "Improve the bounded official Agent release safely.",
		CreatedByAdminID:     uuid.New(), CreatedByRole: QualityRoleDeveloper,
		Status: status, Revision: 2, ReasonCode: "quality_review",
		CreatedAt: fixture.now.Add(-time.Hour), UpdatedAt: fixture.now.Add(-time.Hour),
	}
}

type proposalAggregateReaderStub struct{}

func (*proposalAggregateReaderStub) ListAggregates(context.Context, AggregateFilter, AggregatePageRequest, int) (AggregatePage, error) {
	return AggregatePage{Items: []Aggregate{}}, nil
}
