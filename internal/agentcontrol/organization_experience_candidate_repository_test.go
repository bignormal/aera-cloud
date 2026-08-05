package agentcontrol

import (
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
