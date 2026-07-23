package officialquality

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresProposalRepositoryPersistsDualControlWorkflowAndIdempotency(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	repository := NewPostgresRepository(postgres)
	aggregateDay := fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	aggregateID := insertAggregateFixture(t, ctx, postgres, fixture, aggregateDay, "1s_5s")
	proposalID := uuid.New()
	developer := qualityRepositoryActor(QualityRoleDeveloper, qualityActionProposalCreate, proposalID, 1)
	create := CreateProposalRepositoryCommand{
		ProposalID: proposalID, PlatformID: fixture.platformID, AggregateIDs: []uuid.UUID{aggregateID},
		ProblemCategories:    []string{"latency", "reliability"},
		ImprovementObjective: "Reduce bounded latency while preserving the immutable official base version.",
		MinimumSubjects:      10, Actor: developer, CreatedAt: fixture.now,
	}

	created, err := repository.CreateProposal(ctx, create)
	if err != nil {
		t.Fatalf("CreateProposal() error = %v", err)
	}
	if created.Status != ProposalStatusOpen || created.Revision != 1 ||
		created.PlatformID != fixture.platformID || created.DefinitionID != fixture.definitionID ||
		created.VersionID != fixture.versionID || created.ReleaseID != fixture.releaseID ||
		created.ReleaseRevisionID != fixture.releaseRevisionID || len(created.AggregateIDs) != 1 {
		t.Fatalf("CreateProposal() = %+v", created)
	}
	replayed, err := repository.CreateProposal(ctx, create)
	if err != nil || !replayed.Replayed || replayed.ID != created.ID {
		t.Fatalf("CreateProposal(replay) = %+v error=%v", replayed, err)
	}

	developer = qualityRepositoryActor(QualityRoleDeveloper, qualityActionProposalSubmit, proposalID, 1)
	submitted, err := repository.SubmitProposal(ctx, SubmitProposalRepositoryCommand{
		PlatformID: fixture.platformID, ProposalID: proposalID, ExpectedRevision: 1,
		Actor: developer, SubmittedAt: fixture.now.Add(time.Minute),
	})
	if err != nil || submitted.Status != ProposalStatusSubmitted || submitted.Revision != 2 {
		t.Fatalf("SubmitProposal() = %+v error=%v", submitted, err)
	}

	superAdmin := qualityRepositoryActor(QualityRoleSuperAdmin, qualityActionProposalReview, proposalID, 2)
	approved, err := repository.ReviewProposal(ctx, ReviewProposalRepositoryCommand{
		ReviewID: uuid.New(), PlatformID: fixture.platformID, ProposalID: proposalID,
		ExpectedRevision: 2, Decision: ProposalReviewApprove,
		Actor: superAdmin, ReviewedAt: fixture.now.Add(2 * time.Minute),
	})
	if err != nil || approved.Status != ProposalStatusApproved || approved.Revision != 3 ||
		approved.Review == nil || approved.Review.ReviewerAdminID != superAdmin.AdminID {
		t.Fatalf("ReviewProposal() = %+v error=%v", approved, err)
	}
	var draftCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM platform_agent_drafts WHERE platform_id = $1`, fixture.platformID).Scan(&draftCount); err != nil {
		t.Fatalf("count platform drafts after approval: %v", err)
	}
	if draftCount != 1 {
		t.Fatalf("proposal approval platform draft count = %d, want existing 1", draftCount)
	}
	if _, err := postgres.Exec(ctx, `
		UPDATE platform_agent_drafts
		SET kind = 'next', base_version_id = $2, revision = revision + 1, updated_at = $3
		WHERE id = $1
	`, fixture.platformDraftID, fixture.versionID, fixture.now.Add(3*time.Minute)); err != nil {
		t.Fatalf("prepare exact immutable-base draft clone: %v", err)
	}

	developer = qualityRepositoryActor(QualityRoleDeveloper, qualityActionDraftClone, proposalID, 3)
	linked, err := repository.LinkProposalDraft(ctx, LinkProposalDraftRepositoryCommand{
		PlatformID: fixture.platformID, ProposalID: proposalID, DraftID: fixture.platformDraftID,
		ExpectedRevision: 3, Actor: developer, LinkedAt: fixture.now.Add(3 * time.Minute),
	})
	if err != nil || linked.Status != ProposalStatusDraftLinked || linked.Revision != 4 ||
		linked.LinkedDraftID != fixture.platformDraftID {
		t.Fatalf("LinkProposalDraft() = %+v error=%v", linked, err)
	}

	loaded, err := repository.GetProposal(ctx, fixture.platformID, proposalID)
	if err != nil || loaded.AggregateIDs == nil || loaded.ProblemCategories == nil || loaded.Review == nil {
		t.Fatalf("GetProposal() = %+v error=%v", loaded, err)
	}
	var operationCount, auditCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM admin_operations WHERE target_id = $1`, proposalID).Scan(&operationCount); err != nil {
		t.Fatalf("count proposal admin operations: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE object_id = $1 AND event_type LIKE 'official_quality_%'`, proposalID).Scan(&auditCount); err != nil {
		t.Fatalf("count proposal audit events: %v", err)
	}
	if operationCount != 4 || auditCount != 4 {
		t.Fatalf("proposal operation/audit counts = %d/%d, want 4/4", operationCount, auditCount)
	}
}

func TestPostgresProposalRepositoryRejectsSuppressedOrMixedAggregateSources(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	repository := NewPostgresRepository(postgres)
	day := fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	suppressedID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO official_quality_daily_aggregates (
			id, platform_id, definition_id, version_id, release_id, release_revision_id,
			aggregate_day, event_kind, result_code, latency_bucket, total_token_bucket,
			event_count, distinct_subject_count, suppression_threshold, is_suppressed,
			computed_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'metric', 'success', 'lt_1s', '1_1k',
			9, 9, 10, TRUE, $8, $8)
	`, suppressedID, fixture.platformID, fixture.definitionID, fixture.versionID,
		fixture.releaseID, fixture.releaseRevisionID, day, fixture.now); err != nil {
		t.Fatalf("insert suppressed aggregate: %v", err)
	}
	proposalID := uuid.New()
	_, err := repository.CreateProposal(ctx, CreateProposalRepositoryCommand{
		ProposalID: proposalID, PlatformID: fixture.platformID, AggregateIDs: []uuid.UUID{suppressedID},
		ProblemCategories:    []string{"reliability"},
		ImprovementObjective: "Suppressed aggregate sources must never become visible through proposals.",
		MinimumSubjects:      10,
		Actor:                qualityRepositoryActor(QualityRoleDeveloper, qualityActionProposalCreate, proposalID, 1),
		CreatedAt:            fixture.now,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CreateProposal(suppressed) error = %v, want ErrInvalidRequest", err)
	}
}

func TestOfficialQualityProposalMutationGuardBlocksInvalidTransitionAndDelete(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	repository := NewPostgresRepository(postgres)
	aggregateID := insertAggregateFixture(
		t, ctx, postgres, fixture,
		fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1), "5s_15s",
	)
	proposalID := uuid.New()
	_, err := repository.CreateProposal(ctx, CreateProposalRepositoryCommand{
		ProposalID: proposalID, PlatformID: fixture.platformID, AggregateIDs: []uuid.UUID{aggregateID},
		ProblemCategories:    []string{"reliability"},
		ImprovementObjective: "Keep proposal state transitions revisioned and protected by PostgreSQL.",
		MinimumSubjects:      10,
		Actor:                qualityRepositoryActor(QualityRoleDeveloper, qualityActionProposalCreate, proposalID, 1),
		CreatedAt:            fixture.now,
	})
	if err != nil {
		t.Fatalf("CreateProposal() error = %v", err)
	}

	_, err = postgres.Exec(ctx, `
		UPDATE official_quality_proposals
		SET status = 'approved', revision = 2, updated_at = $2, terminal_at = $2
		WHERE id = $1
	`, proposalID, fixture.now.Add(time.Minute))
	assertPostgresError(t, err, "55000", "")

	_, err = postgres.Exec(ctx, `DELETE FROM official_quality_proposals WHERE id = $1`, proposalID)
	assertPostgresError(t, err, "55000", "")
}

func qualityRepositoryActor(role, action string, targetID uuid.UUID, expectedRevision int64) QualityAdminActor {
	operationID := uuid.New()
	return QualityAdminActor{
		AdminID: uuid.New(), Role: role, RequestID: "req-" + operationID.String(),
		Operation: &QualityAdminOperationProof{
			OperationID: operationID, Action: action, TargetType: "official_quality_proposal",
			TargetID: targetID, ExpectedRevision: expectedRevision, ServiceSubject: "aera-admin-test",
			IdempotencyKeyID:   "admin-test-v1",
			IdempotencyKeyHMAC: sha256Digest("quality-admin-key", operationID),
			RequestFingerprint: sha256Digest("quality-admin-request", operationID),
			ReasonCode:         "quality_review", TicketReference: "QF-123",
		},
	}
}
