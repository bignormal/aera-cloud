package agentcontrol

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOrganizationExperienceCandidateRepositoryAllowsActiveMemberSubmission(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	publication := fixture.publishApprovedOrganizationAgent(t, 0x31, 0x32)
	created, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx,
		fixture.member,
		fixture.organizationInstallationCommand(publication, fixture.member, 0x33),
	)
	if err != nil {
		t.Fatalf("CreatePendingInstallation() error = %v", err)
	}
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, fixture.member, ActivationCommand{
		InstallationID:   created.Installation.ID,
		RuntimeProfileID: uuid.New(),
		AgentVersionID:   publication.Version.ID,
		PolicySnapshotID: created.Policy.ID,
		VersionDigest:    publication.Version.ContentDigest,
		Audit:            fixture.auditEvidence(0x34),
		ActivatedAt:      fixture.now.Add(34 * time.Minute),
	}); err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}

	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
	}
	createdAt := fixture.now.Add(35 * time.Minute)
	idempotency := fixture.idempotency(0x35)
	idempotency.ExpiresAt = createdAt.Add(24 * time.Hour)
	candidateID := uuid.New()
	candidate, replayed, err := fixture.repository.SubmitOrganizationExperienceCandidate(
		fixture.ctx,
		fixture.member,
		SubmitOrganizationExperienceCandidateCommand{
			CandidateID:     candidateID,
			OrganizationID:  fixture.organizationID,
			DefinitionID:    publication.Definition.ID,
			SourceVersionID: publication.Version.ID,
			SkillName:       canonical.Bundle.SkillName,
			Canonical:       canonical,
			DLPVersion:      ExperienceCandidateDLPVersion,
			Idempotency:     idempotency,
			Audit:           fixture.auditEvidence(0x35),
			CreatedAt:       createdAt,
		},
	)
	if err != nil || replayed {
		t.Fatalf("SubmitOrganizationExperienceCandidate() = %+v replayed=%t error=%v", candidate, replayed, err)
	}
	if candidate.ID != candidateID || candidate.AgentDefinitionID != publication.Definition.ID ||
		candidate.SourceAgentVersionID != publication.Version.ID || candidate.ContentDigest != canonical.ContentDigest {
		t.Fatalf("Organization ExperienceCandidate = %+v", candidate)
	}
}

func TestOrganizationExperienceCandidateRepositoryScopesListsDetailAndTerminalReview(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	publication := fixture.publishApprovedOrganizationAgent(t, 0x41, 0x42)
	created, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx,
		fixture.member,
		fixture.organizationInstallationCommand(publication, fixture.member, 0x43),
	)
	if err != nil {
		t.Fatalf("CreatePendingInstallation() error = %v", err)
	}
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, fixture.member, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: uuid.New(),
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest, Audit: fixture.auditEvidence(0x44),
		ActivatedAt: fixture.now.Add(44 * time.Minute),
	}); err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}
	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
	}
	createdAt := fixture.now.Add(45 * time.Minute)
	submitIdempotency := fixture.idempotency(0x45)
	submitIdempotency.ExpiresAt = createdAt.Add(24 * time.Hour)
	candidate, _, err := fixture.repository.SubmitOrganizationExperienceCandidate(
		fixture.ctx,
		fixture.member,
		SubmitOrganizationExperienceCandidateCommand{
			CandidateID: uuid.New(), OrganizationID: fixture.organizationID,
			DefinitionID: publication.Definition.ID, SourceVersionID: publication.Version.ID,
			SkillName: canonical.Bundle.SkillName, Canonical: canonical,
			DLPVersion: ExperienceCandidateDLPVersion, Idempotency: submitIdempotency,
			Audit: fixture.auditEvidence(0x45), CreatedAt: createdAt,
		},
	)
	if err != nil {
		t.Fatalf("SubmitOrganizationExperienceCandidate() error = %v", err)
	}

	own, err := fixture.repository.ListOwnOrganizationExperienceCandidates(
		fixture.ctx, fixture.member, fixture.organizationID,
	)
	if err != nil || len(own) != 1 || own[0].ID != candidate.ID {
		t.Fatalf("member own candidates = %+v error=%v", own, err)
	}
	all, err := fixture.repository.ListOrganizationExperienceCandidates(
		fixture.ctx, fixture.admin, fixture.organizationID,
	)
	if err != nil || len(all) != 1 || all[0].ID != candidate.ID {
		t.Fatalf("admin Organization candidates = %+v error=%v", all, err)
	}
	if _, err := fixture.repository.ListOrganizationExperienceCandidates(
		fixture.ctx, fixture.member, fixture.organizationID,
	); !errors.Is(err, ErrOrganizationAgentForbidden) {
		t.Fatalf("member review queue error = %v, want ErrOrganizationAgentForbidden", err)
	}
	detail, found, err := fixture.repository.FindOrganizationExperienceCandidate(
		fixture.ctx, fixture.member, fixture.organizationID, candidate.ID,
		fixture.auditEvidence(0x46), fixture.now.Add(46*time.Minute),
	)
	if err != nil || !found || detail.ID != candidate.ID {
		t.Fatalf("member own detail = %+v found=%t error=%v", detail, found, err)
	}
	if _, found, err := fixture.repository.FindOrganizationExperienceCandidate(
		fixture.ctx, fixture.outsider, fixture.organizationID, candidate.ID,
		fixture.auditEvidence(0x47), fixture.now.Add(47*time.Minute),
	); !errors.Is(err, ErrOrganizationAgentNotFound) || found {
		t.Fatalf("outsider detail found=%t error=%v", found, err)
	}

	reviewedAt := fixture.now.Add(48 * time.Minute)
	reviewIdempotency := fixture.idempotency(0x48)
	reviewIdempotency.ExpiresAt = reviewedAt.Add(24 * time.Hour)
	reviewCommand := ReviewOrganizationExperienceCandidateCommand{
		OrganizationID: fixture.organizationID, CandidateID: candidate.ID, ReviewID: uuid.New(),
		Decision: ExperienceCandidateApproved, Idempotency: reviewIdempotency,
		Audit: fixture.auditEvidence(0x48), ReviewedAt: reviewedAt,
	}
	reviewed, replayed, err := fixture.repository.ReviewOrganizationExperienceCandidate(
		fixture.ctx, fixture.admin, reviewCommand,
	)
	if err != nil || replayed || reviewed.Review == nil ||
		reviewed.Review.Decision != ExperienceCandidateApproved {
		t.Fatalf("admin review = %+v replayed=%t error=%v", reviewed, replayed, err)
	}
	replayedCandidate, replayed, err := fixture.repository.ReviewOrganizationExperienceCandidate(
		fixture.ctx, fixture.admin, reviewCommand,
	)
	if err != nil || !replayed || replayedCandidate.Review == nil || replayedCandidate.Review.ID != reviewCommand.ReviewID {
		t.Fatalf("review replay = %+v replayed=%t error=%v", replayedCandidate, replayed, err)
	}
	terminalAt := fixture.now.Add(49 * time.Minute)
	terminalIdempotency := fixture.idempotency(0x49)
	terminalIdempotency.ExpiresAt = terminalAt.Add(24 * time.Hour)
	if _, _, err := fixture.repository.ReviewOrganizationExperienceCandidate(
		fixture.ctx,
		fixture.owner,
		ReviewOrganizationExperienceCandidateCommand{
			OrganizationID: fixture.organizationID, CandidateID: candidate.ID, ReviewID: uuid.New(),
			Decision: ExperienceCandidateRejected, ReasonCode: "not_reusable",
			Idempotency: terminalIdempotency, Audit: fixture.auditEvidence(0x49), ReviewedAt: terminalAt,
		},
	); !errors.Is(err, ErrExperienceCandidateAlreadyReviewed) {
		t.Fatalf("terminal Organization review error = %v", err)
	}
}
