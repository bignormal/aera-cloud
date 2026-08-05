package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceSubmitOrganizationExperienceCandidateCanonicalizesHashesAndDetaches(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	organizationID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]SubmitOrganizationExperienceCandidateCommand, 0, 3)
	fixture.repository.submitOrganizationExperienceCandidate = func(
		_ context.Context,
		principal Principal,
		command SubmitOrganizationExperienceCandidateCommand,
	) (OrganizationExperienceCandidate, bool, error) {
		if principal != fixture.principal {
			t.Fatalf("submission principal = %+v", principal)
		}
		commands = append(commands, command)
		return organizationExperienceCandidateFromSubmitCommand(command, principal), len(commands) > 1, nil
	}
	request := SubmitOrganizationExperienceCandidateRequest{
		DefinitionID: definitionID, SourceVersionID: versionID,
		SkillName: canonical.Bundle.SkillName, SchemaVersion: ExperienceCandidateSchemaVersion,
		DLPContractVersion: ExperienceCandidateDLPVersion, Bundle: canonical.Bundle,
		IdempotencyKey: "organization-candidate-submit-key", RequestID: "organization-candidate-submit-request",
	}
	created, err := fixture.service.SubmitOrganizationExperienceCandidate(
		context.Background(), fixture.principal, organizationID, request,
	)
	if err != nil {
		t.Fatalf("SubmitOrganizationExperienceCandidate() error = %v", err)
	}
	if len(commands) != 1 {
		t.Fatalf("repository submissions = %d, want 1", len(commands))
	}
	first := commands[0]
	if first.OrganizationID != organizationID || first.DefinitionID != definitionID ||
		first.SourceVersionID != versionID || first.SkillName != request.SkillName ||
		first.DLPVersion != ExperienceCandidateDLPVersion || first.Canonical.ContentDigest != canonical.ContentDigest ||
		!bytes.Equal(first.Canonical.CanonicalJSON, canonical.CanonicalJSON) ||
		first.Idempotency.KeyHash != sha256.Sum256([]byte(request.IdempotencyKey)) ||
		first.CreatedAt != fixture.now || first.Audit.RequestID != request.RequestID {
		t.Fatalf("organization submission command = %+v", first)
	}
	identifiers := map[uuid.UUID]struct{}{
		first.CandidateID: {}, first.Idempotency.ID: {}, first.Audit.EventID: {},
	}
	if len(identifiers) != 3 || first.CandidateID == uuid.Nil || first.Idempotency.ID == uuid.Nil || first.Audit.EventID == uuid.Nil {
		t.Fatalf("organization submission identifiers are not fresh and distinct: %+v", first)
	}
	created.Bundle.Assets[0].Content = "changed response"
	if first.Canonical.Bundle.Assets[0].Content != canonical.Bundle.Assets[0].Content {
		t.Fatal("service response aliases repository-owned Organization candidate content")
	}

	if _, err := fixture.service.SubmitOrganizationExperienceCandidate(
		context.Background(), fixture.principal, organizationID, request,
	); err != nil {
		t.Fatalf("SubmitOrganizationExperienceCandidate(repeat) error = %v", err)
	}
	changed := request
	changed.SourceVersionID = uuid.New()
	if _, err := fixture.service.SubmitOrganizationExperienceCandidate(
		context.Background(), fixture.principal, organizationID, changed,
	); err != nil {
		t.Fatalf("SubmitOrganizationExperienceCandidate(changed source) error = %v", err)
	}
	if len(commands) != 3 || commands[0].Idempotency.RequestHash != commands[1].Idempotency.RequestHash ||
		commands[1].Idempotency.RequestHash == commands[2].Idempotency.RequestHash {
		t.Fatalf("organization submission request hashes are not deterministic and content-bound: %+v", commands)
	}
}

func TestServiceSubmitOrganizationExperienceCandidateRejectsInvalidMetadataAndDLPBeforeRepository(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	calls := 0
	fixture.repository.submitOrganizationExperienceCandidate = func(
		context.Context, Principal, SubmitOrganizationExperienceCandidateCommand,
	) (OrganizationExperienceCandidate, bool, error) {
		calls++
		return OrganizationExperienceCandidate{}, false, nil
	}
	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		t.Fatal(err)
	}
	valid := SubmitOrganizationExperienceCandidateRequest{
		DefinitionID: uuid.New(), SourceVersionID: uuid.New(), SkillName: canonical.Bundle.SkillName,
		SchemaVersion: ExperienceCandidateSchemaVersion, DLPContractVersion: ExperienceCandidateDLPVersion,
		Bundle: canonical.Bundle, IdempotencyKey: "organization-candidate-submit-key",
		RequestID: "organization-candidate-submit-request",
	}
	wrongSkill := valid
	wrongSkill.SkillName = "other-skill"
	wrongSchema := valid
	wrongSchema.SchemaVersion++
	wrongDLP := valid
	wrongDLP.DLPContractVersion = "experience-candidate-dlp-v0"
	invalidBundle := valid
	invalidBundle.Bundle.Assets[0].Path = "../SKILL.md"
	invalidEnvelope := valid
	invalidEnvelope.IdempotencyKey = " bad-key"
	for _, test := range []struct {
		name    string
		request SubmitOrganizationExperienceCandidateRequest
		wanted  error
	}{
		{name: "mismatched skill", request: wrongSkill, wanted: ErrInvalidExperienceCandidate},
		{name: "mismatched schema", request: wrongSchema, wanted: ErrInvalidExperienceCandidate},
		{name: "mismatched DLP", request: wrongDLP, wanted: ErrInvalidExperienceCandidate},
		{name: "invalid bundle", request: invalidBundle, wanted: ErrInvalidExperienceCandidate},
		{name: "invalid envelope", request: invalidEnvelope, wanted: ErrInvalidRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fixture.service.SubmitOrganizationExperienceCandidate(
				context.Background(), fixture.principal, uuid.New(), test.request,
			); !errors.Is(err, test.wanted) {
				t.Fatalf("SubmitOrganizationExperienceCandidate() error = %v, want %v", err, test.wanted)
			}
		})
	}

	secret := "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
	blockedBundle := validExperienceCandidateBundle()
	blockedBundle.Assets[0].Content += secret
	blocked := valid
	blocked.Bundle = blockedBundle
	_, err = fixture.service.SubmitOrganizationExperienceCandidate(
		context.Background(), fixture.principal, uuid.New(), blocked,
	)
	var dlpError *ExperienceCandidateDLPError
	if !errors.As(err, &dlpError) || len(dlpError.Findings) != 1 ||
		dlpError.Findings[0].Code != "credential_bearer_token" || strings.Contains(err.Error(), secret) {
		t.Fatalf("blocked Organization submission error = %#v", err)
	}
	if calls != 0 {
		t.Fatalf("repository submissions after invalid or blocked requests = %d", calls)
	}
}

func TestServiceReviewOrganizationExperienceCandidateValidatesAndHashesTerminalDecision(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	organizationID := uuid.New()
	candidateID := uuid.New()
	commands := make([]ReviewOrganizationExperienceCandidateCommand, 0, 2)
	fixture.repository.reviewOrganizationExperienceCandidate = func(
		_ context.Context,
		principal Principal,
		command ReviewOrganizationExperienceCandidateCommand,
	) (OrganizationExperienceCandidate, bool, error) {
		commands = append(commands, command)
		return OrganizationExperienceCandidate{
			ID: command.CandidateID, OrganizationID: command.OrganizationID,
			Review: &ExperienceCandidateReview{
				ID: command.ReviewID, ReviewedByUserID: &principal.UserID, Decision: command.Decision,
				ReasonCode: command.ReasonCode, SafeNote: command.SafeNote, ReviewedAt: command.ReviewedAt,
			},
		}, len(commands) > 1, nil
	}
	request := ReviewOrganizationExperienceCandidateRequest{
		CandidateID: candidateID, Decision: ExperienceCandidateRejected,
		ReasonCode: "not_reusable", SafeNote: "Needs a narrower reusable workflow.",
		IdempotencyKey: "organization-candidate-review-key", RequestID: "organization-candidate-review-request",
	}
	result, err := fixture.service.ReviewOrganizationExperienceCandidate(
		context.Background(), fixture.principal, organizationID, request,
	)
	if err != nil || result.Review == nil || result.Review.Decision != ExperienceCandidateRejected {
		t.Fatalf("ReviewOrganizationExperienceCandidate() = %+v error=%v", result, err)
	}
	first := commands[0]
	if first.OrganizationID != organizationID || first.CandidateID != candidateID || first.Decision != request.Decision ||
		first.ReasonCode != request.ReasonCode || first.SafeNote != request.SafeNote || first.ReviewedAt != fixture.now ||
		first.Audit.RequestID != request.RequestID || first.Idempotency.KeyHash != sha256.Sum256([]byte(request.IdempotencyKey)) {
		t.Fatalf("organization review command = %+v", first)
	}
	if _, err := fixture.service.ReviewOrganizationExperienceCandidate(
		context.Background(), fixture.principal, organizationID, request,
	); err != nil {
		t.Fatalf("ReviewOrganizationExperienceCandidate(repeat) error = %v", err)
	}
	if commands[0].Idempotency.RequestHash != commands[1].Idempotency.RequestHash {
		t.Fatal("identical Organization review did not produce a deterministic request hash")
	}

	secret := "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
	for _, invalid := range []ReviewOrganizationExperienceCandidateRequest{
		{CandidateID: candidateID, Decision: ExperienceCandidateApproved, ReasonCode: "not_reusable", IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, ReasonCode: "Bad Reason", IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, ReasonCode: "not_reusable", SafeNote: "two\nlines", IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, ReasonCode: "not_reusable", SafeNote: secret, IdempotencyKey: "k", RequestID: "r"},
	} {
		if _, err := fixture.service.ReviewOrganizationExperienceCandidate(
			context.Background(), fixture.principal, organizationID, invalid,
		); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ReviewOrganizationExperienceCandidate(invalid %+v) error = %v", invalid, err)
		}
	}
	if len(commands) != 2 {
		t.Fatalf("repository reviews after invalid inputs = %d, want 2", len(commands))
	}
}

func TestServiceListAndGetOrganizationExperienceCandidatesDetachAndAuditAccess(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	organizationID := uuid.New()
	candidate := OrganizationExperienceCandidate{
		ID: uuid.New(), OrganizationID: organizationID, AgentDefinitionID: uuid.New(), SourceAgentVersionID: uuid.New(),
		SkillName: "weekly-summary", DLPContractVersion: ExperienceCandidateDLPVersion,
		Bundle: validExperienceCandidateBundle(), CreatedAt: fixture.now,
	}
	canonical, err := CanonicalizeExperienceCandidate(candidate.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	candidate.ContentDigest = canonical.ContentDigest
	fixture.repository.listOwnOrganizationCandidates = func(context.Context, Principal, uuid.UUID) ([]OrganizationExperienceCandidate, error) {
		return []OrganizationExperienceCandidate{candidate}, nil
	}
	fixture.repository.listOrganizationCandidates = func(context.Context, Principal, uuid.UUID) ([]OrganizationExperienceCandidate, error) {
		return []OrganizationExperienceCandidate{candidate}, nil
	}
	var capturedAudit AuditEvidence
	var capturedAt time.Time
	fixture.repository.findOrganizationExperienceCandidate = func(
		_ context.Context,
		_ Principal,
		gotOrganizationID uuid.UUID,
		gotCandidateID uuid.UUID,
		audit AuditEvidence,
		accessedAt time.Time,
	) (OrganizationExperienceCandidate, bool, error) {
		if gotOrganizationID != organizationID || gotCandidateID != candidate.ID {
			t.Fatalf("Organization candidate lookup target = %s/%s", gotOrganizationID, gotCandidateID)
		}
		capturedAudit, capturedAt = audit, accessedAt
		return candidate, true, nil
	}

	own, err := fixture.service.ListOwnOrganizationExperienceCandidates(context.Background(), fixture.principal, organizationID)
	if err != nil {
		t.Fatalf("ListOwnOrganizationExperienceCandidates() error = %v", err)
	}
	organization, err := fixture.service.ListOrganizationExperienceCandidates(context.Background(), fixture.principal, organizationID)
	if err != nil {
		t.Fatalf("ListOrganizationExperienceCandidates() error = %v", err)
	}
	detail, err := fixture.service.GetOrganizationExperienceCandidate(
		context.Background(), fixture.principal, organizationID, candidate.ID, "organization-candidate-detail-request",
	)
	if err != nil {
		t.Fatalf("GetOrganizationExperienceCandidate() error = %v", err)
	}
	if capturedAudit.EventID == uuid.Nil || capturedAudit.RequestID != "organization-candidate-detail-request" || capturedAt != fixture.now {
		t.Fatalf("Organization candidate detail audit = %+v at %v", capturedAudit, capturedAt)
	}
	own[0].Bundle.Assets[0].Content = "own changed"
	organization[0].Bundle.Assets[0].Content = "organization changed"
	detail.Bundle.Assets[0].Content = "detail changed"
	if candidate.Bundle.Assets[0].Content != validExperienceCandidateBundle().Assets[0].Content {
		t.Fatal("Organization candidate service response aliases repository-owned content")
	}

	fixture.repository.findOrganizationExperienceCandidate = func(
		context.Context, Principal, uuid.UUID, uuid.UUID, AuditEvidence, time.Time,
	) (OrganizationExperienceCandidate, bool, error) {
		return OrganizationExperienceCandidate{}, false, nil
	}
	if _, err := fixture.service.GetOrganizationExperienceCandidate(
		context.Background(), fixture.principal, organizationID, uuid.New(), "organization-candidate-missing-request",
	); !errors.Is(err, ErrOrganizationAgentNotFound) {
		t.Fatalf("GetOrganizationExperienceCandidate(missing) error = %v", err)
	}
}

func organizationExperienceCandidateFromSubmitCommand(
	command SubmitOrganizationExperienceCandidateCommand,
	principal Principal,
) OrganizationExperienceCandidate {
	return OrganizationExperienceCandidate{
		ID: command.CandidateID, OrganizationID: command.OrganizationID,
		AgentDefinitionID: command.DefinitionID, SourceAgentVersionID: command.SourceVersionID,
		SubmittedByUserID: &principal.UserID, SubmittedFromDeviceID: &principal.DeviceID,
		SkillName: command.SkillName, DLPContractVersion: command.DLPVersion,
		ContentDigest: command.Canonical.ContentDigest, Bundle: command.Canonical.Bundle, CreatedAt: command.CreatedAt,
	}
}
