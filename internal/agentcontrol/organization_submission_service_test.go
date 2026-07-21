package agentcontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSubmitOrganizationAgentCanonicalizesClaimsAndReplays(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	organizationID := uuid.New()
	request := lockedSubmitOrganizationInitialRequest(t)
	var stored OrganizationAgentSubmission
	var commands []SubmitOrganizationAgentCommand
	fixture.repository.submitOrganizationAgent = func(
		_ context.Context,
		command SubmitOrganizationAgentCommand,
	) (OrganizationAgentSubmission, error) {
		commands = append(commands, command)
		if stored.ID == uuid.Nil {
			stored = organizationSubmissionFromSubmitCommand(command)
		}
		return stored, nil
	}

	first, err := fixture.service.SubmitOrganizationAgent(
		context.Background(), fixture.principal, organizationID, request,
	)
	if err != nil {
		t.Fatalf("SubmitOrganizationAgent() error = %v", err)
	}
	first.Bundle.Assets[0].Content = "mutated response"
	second, err := fixture.service.SubmitOrganizationAgent(
		context.Background(), fixture.principal, organizationID, request,
	)
	if err != nil {
		t.Fatalf("SubmitOrganizationAgent(replay) error = %v", err)
	}
	if first.ID != second.ID || first.ContentDigest != second.ContentDigest {
		t.Fatal("idempotent replay changed authoritative result")
	}
	if second.Bundle.Assets[0].Content == "mutated response" {
		t.Fatal("submission response aliases repository-owned bundle")
	}
	if len(commands) != 2 {
		t.Fatalf("repository commands = %d, want 2", len(commands))
	}
	for _, command := range commands {
		if command.Principal != fixture.principal || command.OrganizationID != organizationID {
			t.Fatalf("command claims/organization = %+v/%s", command.Principal, command.OrganizationID)
		}
		if command.Canonical.Package.DefinitionID == uuid.Nil {
			t.Fatal("initial submission did not receive a server-reserved Definition ID")
		}
	}
	if commands[0].Canonical.Package.DefinitionID == commands[1].Canonical.Package.DefinitionID {
		t.Fatal("fresh replay attempt unexpectedly reused a generated Definition ID before repository idempotency")
	}
	if commands[0].Idempotency.KeyHash != commands[1].Idempotency.KeyHash ||
		commands[0].Idempotency.RequestHash != commands[1].Idempotency.RequestHash {
		t.Fatal("identical submission request did not produce stable idempotency evidence")
	}
}

func TestSubmitOrganizationAgentBlocksDLPAndCallerOwnershipBeforeRepository(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	called := false
	fixture.repository.submitOrganizationAgent = func(
		context.Context,
		SubmitOrganizationAgentCommand,
	) (OrganizationAgentSubmission, error) {
		called = true
		return OrganizationAgentSubmission{}, nil
	}

	secret := []byte("API_KEY=correct-horse-battery\nHERMES_HOME=/Users/alice/.hermes/profiles/work")
	manifest, bundle := singleAssetFixture("knowledge/private.md", secret)
	request := lockedSubmitOrganizationInitialRequest(t)
	request.Package.Manifest = manifest
	request.Package.Bundle = bundle
	_, err := fixture.service.SubmitOrganizationAgent(
		context.Background(), fixture.principal, uuid.New(), request,
	)
	var dlpError *OrganizationPublicationDLPError
	if !errors.As(err, &dlpError) || len(dlpError.Findings) != 2 {
		t.Fatalf("DLP error = %#v, want two safe findings", err)
	}
	if called {
		t.Fatal("repository was called for blocked publication content")
	}

	request = lockedSubmitOrganizationInitialRequest(t)
	request.Package.DefinitionID = uuid.New()
	if _, err := fixture.service.SubmitOrganizationAgent(
		context.Background(), fixture.principal, uuid.New(), request,
	); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("caller-supplied initial Definition ID error = %v, want ErrInvalidRequest", err)
	}
	if called {
		t.Fatal("repository was called for caller-supplied Organization ownership")
	}
}

func TestOrganizationSubmissionServiceValidatesTerminalRequestsAndDetachesHistory(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	organizationID := uuid.New()
	submissionID := uuid.New()
	canonical, err := CanonicalizeOrganizationSubmission(func() OrganizationSubmissionPackage {
		value := lockedOrganizationInitialPackage(t)
		value.DefinitionID = uuid.New()
		return value
	}())
	if err != nil {
		t.Fatalf("CanonicalizeOrganizationSubmission() error = %v", err)
	}
	stored := organizationSubmissionFromSubmitCommand(SubmitOrganizationAgentCommand{
		SubmissionID: submissionID, OrganizationID: organizationID, Principal: fixture.principal,
		Canonical: canonical, SubmittedAt: fixture.now,
	})
	fixture.repository.listOrganizationSubmissions = func(
		context.Context, Principal, uuid.UUID,
	) ([]OrganizationAgentSubmission, error) {
		return []OrganizationAgentSubmission{stored}, nil
	}
	fixture.repository.findOrganizationSubmission = func(
		context.Context, Principal, uuid.UUID, uuid.UUID,
	) (OrganizationAgentSubmission, bool, error) {
		return stored, true, nil
	}
	fixture.repository.withdrawOrganizationSubmission = func(
		_ context.Context, command WithdrawOrganizationAgentCommand,
	) (OrganizationAgentSubmission, error) {
		result := stored
		result.Status = OrganizationSubmissionWithdrawn
		result.Revision = command.ExpectedRevision + 1
		return result, nil
	}
	fixture.repository.reviewOrganizationSubmission = func(
		_ context.Context, command ReviewOrganizationAgentCommand,
	) (OrganizationAgentSubmission, error) {
		result := stored
		result.Status = OrganizationSubmissionRejected
		result.Revision = command.ExpectedRevision + 1
		return result, nil
	}

	history, err := fixture.service.ListOrganizationAgentSubmissions(
		context.Background(), fixture.principal, organizationID,
	)
	if err != nil || len(history) != 1 {
		t.Fatalf("ListOrganizationAgentSubmissions() = %+v error=%v", history, err)
	}
	detail, err := fixture.service.GetOrganizationAgentSubmission(
		context.Background(), fixture.principal, organizationID, submissionID,
	)
	if err != nil {
		t.Fatalf("GetOrganizationAgentSubmission() error = %v", err)
	}
	history[0].Bundle.Assets[0].Content = "history mutation"
	detail.Bundle.Assets[0].Content = "detail mutation"
	if stored.Bundle.Assets[0].Content == "history mutation" || stored.Bundle.Assets[0].Content == "detail mutation" {
		t.Fatal("history/detail response aliases repository storage")
	}

	withdrawn, err := fixture.service.WithdrawOrganizationAgentSubmission(
		context.Background(), fixture.principal, organizationID, WithdrawOrganizationAgentRequest{
			SubmissionID: submissionID, ExpectedRevision: 1,
			IdempotencyKey: "organization-withdraw", RequestID: "organization-withdraw-request",
		},
	)
	if err != nil || withdrawn.Status != OrganizationSubmissionWithdrawn {
		t.Fatalf("WithdrawOrganizationAgentSubmission() = %+v error=%v", withdrawn, err)
	}
	rejected, err := fixture.service.ReviewOrganizationAgentSubmission(
		context.Background(), fixture.principal, organizationID, ReviewOrganizationAgentRequest{
			SubmissionID: submissionID, ExpectedRevision: 1, Decision: OrganizationReviewReject,
			ReasonCode: "policy_mismatch", SafeNote: "Select an approved model.",
			IdempotencyKey: "organization-reject", RequestID: "organization-reject-request",
		},
	)
	if err != nil || rejected.Status != OrganizationSubmissionRejected {
		t.Fatalf("ReviewOrganizationAgentSubmission(reject) = %+v error=%v", rejected, err)
	}

	for _, invalid := range []ReviewOrganizationAgentRequest{
		{SubmissionID: submissionID, ExpectedRevision: 1, Decision: OrganizationReviewReject, IdempotencyKey: "k", RequestID: "r"},
		{SubmissionID: submissionID, ExpectedRevision: 1, Decision: OrganizationReviewReject, ReasonCode: "Bad Reason", IdempotencyKey: "k", RequestID: "r"},
		{SubmissionID: submissionID, ExpectedRevision: 1, Decision: OrganizationReviewReject, ReasonCode: "policy_mismatch", SafeNote: "API_KEY=correct-horse-battery", IdempotencyKey: "k", RequestID: "r"},
	} {
		if _, err := fixture.service.ReviewOrganizationAgentSubmission(
			context.Background(), fixture.principal, organizationID, invalid,
		); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid rejection %+v error = %v, want ErrInvalidRequest", invalid, err)
		}
	}
}

func lockedSubmitOrganizationInitialRequest(t *testing.T) SubmitOrganizationAgentRequest {
	t.Helper()
	value := lockedOrganizationInitialPackage(t)
	value.DefinitionID = uuid.Nil
	value.IconMediaType = ""
	value.IconData = nil
	return SubmitOrganizationAgentRequest{
		Package: value, IdempotencyKey: "organization-submit", RequestID: "organization-submit-request",
	}
}

func organizationSubmissionFromSubmitCommand(command SubmitOrganizationAgentCommand) OrganizationAgentSubmission {
	return OrganizationAgentSubmission{
		ID: command.SubmissionID, OrganizationID: command.OrganizationID,
		Kind: command.Canonical.Package.Kind, DefinitionID: command.Canonical.Package.DefinitionID,
		BaseVersionID: command.Canonical.Package.BaseVersionID, DisplayName: command.Canonical.Package.DisplayName,
		IconMediaType: command.Canonical.Package.IconMediaType, IconData: command.Canonical.Package.IconData,
		Manifest: command.Canonical.Package.Manifest, Bundle: command.Canonical.Package.Bundle,
		ManifestDigest: command.Canonical.ManifestDigest, BundleDigest: command.Canonical.BundleDigest,
		ContentDigest: command.Canonical.ContentDigest, SubmittedByUserID: command.Principal.UserID,
		Status: OrganizationSubmissionPending, Revision: 1,
		SubmittedAt: command.SubmittedAt, UpdatedAt: command.SubmittedAt,
	}
}
