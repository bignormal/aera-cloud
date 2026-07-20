package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceSubmitExperienceCandidateCanonicalizesHashesAndDetaches(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	workspaceID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
	}
	commands := make([]SubmitExperienceCandidateCommand, 0, 3)
	fixture.repository.submitExperienceCandidate = func(
		_ context.Context,
		principal Principal,
		command SubmitExperienceCandidateCommand,
	) (ExperienceCandidate, bool, error) {
		if principal != fixture.principal {
			t.Fatalf("submission principal = %+v, want %+v", principal, fixture.principal)
		}
		commands = append(commands, command)
		return experienceCandidateFromSubmitCommand(command, principal), len(commands) > 1, nil
	}
	request := SubmitExperienceCandidateRequest{
		DefinitionID: definitionID, SourceVersionID: versionID,
		Bundle: canonical.Bundle, ContentDigest: hex.EncodeToString(canonical.ContentDigest[:]),
		IdempotencyKey: "candidate-submit-key", RequestID: "candidate-submit-request",
	}

	created, err := fixture.service.SubmitExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, request,
	)
	if err != nil {
		t.Fatalf("SubmitExperienceCandidate() error = %v", err)
	}
	if len(commands) != 1 {
		t.Fatalf("repository submissions = %d, want 1", len(commands))
	}
	first := commands[0]
	if first.WorkspaceID != workspaceID || first.DefinitionID != definitionID || first.SourceVersionID != versionID ||
		first.SkillName != canonical.Bundle.SkillName || first.DLPVersion != ExperienceCandidateDLPVersion ||
		first.Canonical.ContentDigest != canonical.ContentDigest || !bytes.Equal(first.Canonical.CanonicalJSON, canonical.CanonicalJSON) ||
		first.Idempotency.KeyHash != sha256.Sum256([]byte(request.IdempotencyKey)) || first.CreatedAt != fixture.now ||
		first.Audit.RequestID != request.RequestID {
		t.Fatalf("submission command = %+v", first)
	}
	identifiers := map[uuid.UUID]struct{}{
		first.CandidateID: {}, first.Idempotency.ID: {}, first.Audit.EventID: {},
	}
	if len(identifiers) != 3 || first.CandidateID == uuid.Nil || first.Idempotency.ID == uuid.Nil || first.Audit.EventID == uuid.Nil {
		t.Fatalf("submission identifiers are not fresh and distinct: %+v", first)
	}
	if first.Idempotency.ExpiresAt != fixture.now.Add(idempotencyLifetime) {
		t.Fatalf("submission idempotency expiry = %v", first.Idempotency.ExpiresAt)
	}
	created.Bundle.Assets[0].Content = "changed response"
	if first.Canonical.Bundle.Assets[0].Content != canonical.Bundle.Assets[0].Content {
		t.Fatal("service response aliases repository-owned candidate content")
	}

	if _, err := fixture.service.SubmitExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, request,
	); err != nil {
		t.Fatalf("SubmitExperienceCandidate(repeat request) error = %v", err)
	}
	changed := request
	changed.SourceVersionID = uuid.New()
	if _, err := fixture.service.SubmitExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, changed,
	); err != nil {
		t.Fatalf("SubmitExperienceCandidate(changed source) error = %v", err)
	}
	if len(commands) != 3 || commands[0].Idempotency.RequestHash != commands[1].Idempotency.RequestHash ||
		commands[1].Idempotency.RequestHash == commands[2].Idempotency.RequestHash {
		t.Fatalf("submission request hashes are not deterministic and content-bound: %+v", commands)
	}
}

func TestServiceSubmitExperienceCandidateRejectsInvalidAndDLPContentBeforeRepository(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	calls := 0
	fixture.repository.submitExperienceCandidate = func(
		context.Context, Principal, SubmitExperienceCandidateCommand,
	) (ExperienceCandidate, bool, error) {
		calls++
		return ExperienceCandidate{}, false, nil
	}
	workspaceID := uuid.New()
	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		t.Fatal(err)
	}
	valid := SubmitExperienceCandidateRequest{
		DefinitionID: uuid.New(), SourceVersionID: uuid.New(), Bundle: canonical.Bundle,
		ContentDigest:  hex.EncodeToString(canonical.ContentDigest[:]),
		IdempotencyKey: "candidate-submit-key", RequestID: "candidate-submit-request",
	}

	invalidDigest := valid
	invalidDigest.ContentDigest = strings.ToUpper(valid.ContentDigest)
	mismatchedDigest := valid
	mismatchedDigest.ContentDigest = strings.Repeat("0", sha256.Size*2)
	invalidBundle := valid
	invalidBundle.Bundle.Assets[0].Path = "../SKILL.md"
	invalidEnvelope := valid
	invalidEnvelope.IdempotencyKey = " bad-key"
	for _, test := range []struct {
		name    string
		request SubmitExperienceCandidateRequest
		wanted  error
	}{
		{name: "uppercase digest", request: invalidDigest, wanted: ErrInvalidExperienceCandidate},
		{name: "mismatched digest", request: mismatchedDigest, wanted: ErrInvalidExperienceCandidate},
		{name: "invalid bundle", request: invalidBundle, wanted: ErrInvalidExperienceCandidate},
		{name: "invalid envelope", request: invalidEnvelope, wanted: ErrInvalidRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fixture.service.SubmitExperienceCandidate(
				context.Background(), fixture.principal, workspaceID, test.request,
			); !errors.Is(err, test.wanted) {
				t.Fatalf("SubmitExperienceCandidate() error = %v, want %v", err, test.wanted)
			}
		})
	}

	secret := "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
	blockedBundle := validExperienceCandidateBundle()
	blockedBundle.Assets[0].Content += secret
	blockedCanonical, err := CanonicalizeExperienceCandidate(blockedBundle)
	if err != nil {
		t.Fatal(err)
	}
	blocked := valid
	blocked.Bundle = blockedCanonical.Bundle
	blocked.ContentDigest = hex.EncodeToString(blockedCanonical.ContentDigest[:])
	_, err = fixture.service.SubmitExperienceCandidate(context.Background(), fixture.principal, workspaceID, blocked)
	var dlpError *ExperienceCandidateDLPError
	if !errors.As(err, &dlpError) || len(dlpError.Findings) != 1 ||
		dlpError.Findings[0].Code != "credential_bearer_token" || strings.Contains(err.Error(), secret) {
		t.Fatalf("blocked submission error = %#v", err)
	}
	if calls != 0 {
		t.Fatalf("repository submissions after invalid or blocked requests = %d", calls)
	}
}

func TestServiceReviewExperienceCandidateValidatesNotesAndHashesTerminalDecision(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	workspaceID := uuid.New()
	candidateID := uuid.New()
	commands := make([]ReviewExperienceCandidateCommand, 0, 2)
	fixture.repository.reviewExperienceCandidate = func(
		_ context.Context,
		principal Principal,
		command ReviewExperienceCandidateCommand,
	) (ExperienceCandidate, bool, error) {
		if principal != fixture.principal {
			t.Fatalf("review principal = %+v", principal)
		}
		commands = append(commands, command)
		return ExperienceCandidate{
			ID: command.CandidateID, WorkspaceID: command.WorkspaceID,
			Review: &ExperienceCandidateReview{
				ID: command.ReviewID, ReviewedByUserID: &principal.UserID, Decision: command.Decision,
				ReasonCode: command.ReasonCode, SafeNote: command.SafeNote, ReviewedAt: command.ReviewedAt,
			},
		}, len(commands) > 1, nil
	}
	request := ReviewExperienceCandidateRequest{
		CandidateID: candidateID, Decision: ExperienceCandidateRejected,
		ReasonCode: "not_reusable", SafeNote: "Needs a narrower reusable workflow.",
		IdempotencyKey: "candidate-review-key", RequestID: "candidate-review-request",
	}
	result, err := fixture.service.ReviewExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, request,
	)
	if err != nil || result.Review == nil || result.Review.Decision != ExperienceCandidateRejected {
		t.Fatalf("ReviewExperienceCandidate() = %+v error=%v", result, err)
	}
	if len(commands) != 1 {
		t.Fatalf("repository reviews = %d, want 1", len(commands))
	}
	first := commands[0]
	if first.WorkspaceID != workspaceID || first.CandidateID != candidateID || first.Decision != request.Decision ||
		first.ReasonCode != request.ReasonCode || first.SafeNote != request.SafeNote || first.ReviewedAt != fixture.now ||
		first.Audit.RequestID != request.RequestID || first.Idempotency.KeyHash != sha256.Sum256([]byte(request.IdempotencyKey)) {
		t.Fatalf("review command = %+v", first)
	}
	identifiers := map[uuid.UUID]struct{}{first.ReviewID: {}, first.Idempotency.ID: {}, first.Audit.EventID: {}}
	if len(identifiers) != 3 || first.ReviewID == uuid.Nil || first.Idempotency.ID == uuid.Nil || first.Audit.EventID == uuid.Nil {
		t.Fatalf("review identifiers are not fresh and distinct: %+v", first)
	}
	if _, err := fixture.service.ReviewExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, request,
	); err != nil {
		t.Fatalf("ReviewExperienceCandidate(repeat request) error = %v", err)
	}
	if commands[0].Idempotency.RequestHash != commands[1].Idempotency.RequestHash {
		t.Fatal("identical review request did not produce a deterministic request hash")
	}
	changed := request
	changed.SafeNote = "Needs a smaller reusable workflow."
	changed.IdempotencyKey = "candidate-review-changed-key"
	if _, err := fixture.service.ReviewExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, changed,
	); err != nil {
		t.Fatalf("ReviewExperienceCandidate(changed note) error = %v", err)
	}
	if commands[1].Idempotency.RequestHash == commands[2].Idempotency.RequestHash {
		t.Fatal("changed terminal review did not change the request hash")
	}
	approved := ReviewExperienceCandidateRequest{
		CandidateID: candidateID, Decision: ExperienceCandidateApproved,
		IdempotencyKey: "candidate-review-approved-key", RequestID: "candidate-review-approved-request",
	}
	if _, err := fixture.service.ReviewExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, approved,
	); err != nil {
		t.Fatalf("ReviewExperienceCandidate(approved) error = %v", err)
	}

	secret := "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
	for _, invalid := range []ReviewExperienceCandidateRequest{
		{CandidateID: candidateID, Decision: ExperienceCandidateApproved, ReasonCode: "not_reusable", IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, ReasonCode: "Bad Reason", IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, ReasonCode: "not_reusable", SafeNote: "two\nlines", IdempotencyKey: "k", RequestID: "r"},
		{CandidateID: candidateID, Decision: ExperienceCandidateRejected, ReasonCode: "not_reusable", SafeNote: secret, IdempotencyKey: "k", RequestID: "r"},
	} {
		if _, err := fixture.service.ReviewExperienceCandidate(
			context.Background(), fixture.principal, workspaceID, invalid,
		); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ReviewExperienceCandidate(invalid %+v) error = %v", invalid, err)
		}
	}
	if len(commands) != 4 {
		t.Fatalf("repository reviews after invalid notes = %d, want 4", len(commands))
	}
}

func TestServiceListAndGetExperienceCandidatesDetachAndAuditReviewerAccess(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	workspaceID := uuid.New()
	candidate := ExperienceCandidate{
		ID: uuid.New(), WorkspaceID: workspaceID, AgentDefinitionID: uuid.New(), SourceAgentVersionID: uuid.New(),
		SkillName: "weekly-summary", DLPContractVersion: ExperienceCandidateDLPVersion,
		Bundle: validExperienceCandidateBundle(), CreatedAt: fixture.now,
	}
	canonical, err := CanonicalizeExperienceCandidate(candidate.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	candidate.ContentDigest = canonical.ContentDigest
	fixture.repository.listOwnCandidates = func(context.Context, Principal, uuid.UUID) ([]ExperienceCandidate, error) {
		return []ExperienceCandidate{candidate}, nil
	}
	fixture.repository.listWorkspaceCandidates = func(context.Context, Principal, uuid.UUID) ([]ExperienceCandidate, error) {
		return []ExperienceCandidate{candidate}, nil
	}
	var capturedAudit AuditEvidence
	var capturedAt time.Time
	fixture.repository.findExperienceCandidate = func(
		_ context.Context,
		_ Principal,
		gotWorkspaceID uuid.UUID,
		gotCandidateID uuid.UUID,
		audit AuditEvidence,
		accessedAt time.Time,
	) (ExperienceCandidate, bool, error) {
		if gotWorkspaceID != workspaceID || gotCandidateID != candidate.ID {
			t.Fatalf("candidate lookup target = %s/%s", gotWorkspaceID, gotCandidateID)
		}
		capturedAudit, capturedAt = audit, accessedAt
		return candidate, true, nil
	}

	own, err := fixture.service.ListOwnExperienceCandidates(context.Background(), fixture.principal, workspaceID)
	if err != nil {
		t.Fatalf("ListOwnExperienceCandidates() error = %v", err)
	}
	workspace, err := fixture.service.ListWorkspaceExperienceCandidates(context.Background(), fixture.principal, workspaceID)
	if err != nil {
		t.Fatalf("ListWorkspaceExperienceCandidates() error = %v", err)
	}
	detail, err := fixture.service.GetExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, candidate.ID, "candidate-detail-request",
	)
	if err != nil {
		t.Fatalf("GetExperienceCandidate() error = %v", err)
	}
	if capturedAudit.EventID == uuid.Nil || capturedAudit.RequestID != "candidate-detail-request" || capturedAt != fixture.now {
		t.Fatalf("candidate detail audit = %+v at %v", capturedAudit, capturedAt)
	}
	own[0].Bundle.Assets[0].Content = "own changed"
	workspace[0].Bundle.Assets[0].Content = "workspace changed"
	detail.Bundle.Assets[0].Content = "detail changed"
	if candidate.Bundle.Assets[0].Content != validExperienceCandidateBundle().Assets[0].Content {
		t.Fatal("candidate service response aliases repository-owned content")
	}

	fixture.repository.findExperienceCandidate = func(
		context.Context, Principal, uuid.UUID, uuid.UUID, AuditEvidence, time.Time,
	) (ExperienceCandidate, bool, error) {
		return ExperienceCandidate{}, false, nil
	}
	if _, err := fixture.service.GetExperienceCandidate(
		context.Background(), fixture.principal, workspaceID, uuid.New(), "candidate-missing-request",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetExperienceCandidate(missing) error = %v", err)
	}
}

func experienceCandidateFromSubmitCommand(command SubmitExperienceCandidateCommand, principal Principal) ExperienceCandidate {
	return ExperienceCandidate{
		ID: command.CandidateID, WorkspaceID: command.WorkspaceID,
		AgentDefinitionID: command.DefinitionID, SourceAgentVersionID: command.SourceVersionID,
		SubmittedByUserID: &principal.UserID, SubmittedFromDeviceID: &principal.DeviceID,
		SkillName: command.SkillName, DLPContractVersion: command.DLPVersion,
		ContentDigest: command.Canonical.ContentDigest, Bundle: command.Canonical.Bundle, CreatedAt: command.CreatedAt,
	}
}
