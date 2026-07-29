package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
)

func TestOrganizationSubmissionRepositoryVisibilityWithdrawalAndRejection(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	submission := fixture.submitInitial(t, fixture.owner, 0x71)

	for name, principal := range map[string]Principal{
		"owner": fixture.owner, "admin": fixture.admin, "auditor": fixture.auditor,
	} {
		t.Run("history visible to "+name, func(t *testing.T) {
			history, err := fixture.repository.ListOrganizationAgentSubmissions(
				fixture.ctx, principal, fixture.organizationID,
			)
			if err != nil || len(history) != 1 || history[0].ID != submission.ID {
				t.Fatalf("history = %+v error=%v", history, err)
			}
			detail, found, err := fixture.repository.FindOrganizationAgentSubmission(
				fixture.ctx, principal, fixture.organizationID, submission.ID,
			)
			if err != nil || !found || detail.ID != submission.ID {
				t.Fatalf("detail = %+v found=%t error=%v", detail, found, err)
			}
		})
	}
	if _, err := fixture.repository.ListOrganizationAgentSubmissions(
		fixture.ctx, fixture.member, fixture.organizationID,
	); !errors.Is(err, ErrOrganizationAgentForbidden) {
		t.Fatalf("Member history error = %v, want ErrOrganizationAgentForbidden", err)
	}
	if _, err := fixture.repository.ListOrganizationAgentSubmissions(
		fixture.ctx, fixture.outsider, fixture.organizationID,
	); !errors.Is(err, ErrOrganizationAgentNotFound) {
		t.Fatalf("outsider history error = %v, want ErrOrganizationAgentNotFound", err)
	}

	rejected, err := fixture.repository.ReviewOrganizationAgentSubmission(fixture.ctx, ReviewOrganizationAgentCommand{
		ReviewID: uuid.New(), OrganizationID: fixture.organizationID, SubmissionID: submission.ID,
		ExpectedRevision: submission.Revision, Principal: fixture.admin, Decision: OrganizationReviewReject,
		ReasonCode: "policy_mismatch", SafeNote: "Select an approved model.",
		Idempotency: fixture.idempotency(0x72), Audit: fixture.auditEvidence(0x72), ReviewedAt: submission.SubmittedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ReviewOrganizationAgentSubmission(reject) error = %v", err)
	}
	if rejected.Status != OrganizationSubmissionRejected || rejected.Revision != 2 || rejected.Review == nil ||
		rejected.Review.ReviewerUserID != fixture.admin.UserID || rejected.Review.Decision != OrganizationReviewReject {
		t.Fatalf("rejected submission = %+v", rejected)
	}
	fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organization_agent_submissions SET display_name = 'Mutated' WHERE id = $1
	`, submission.ID); err == nil {
		t.Fatal("immutable Organization submission payload update succeeded")
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		DELETE FROM organization_agent_reviews WHERE submission_id = $1
	`, submission.ID); err == nil {
		t.Fatal("immutable Organization review delete succeeded")
	}

	var auditCount int64
	var metadata string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*), min(metadata::text)
		FROM audit_events
		WHERE organization_id = $1 AND object_id = $2
	`, fixture.organizationID, submission.ID).Scan(&auditCount, &metadata); err != nil {
		t.Fatalf("read Organization submission audit: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("Organization submission audit count = %d, want 2", auditCount)
	}
	for _, forbidden := range []string{"Research Agent", "SKILL.md", "Select an approved model", "system_prompt", "/Users/"} {
		if strings.Contains(metadata, forbidden) {
			t.Fatalf("Organization audit leaked %q: %s", forbidden, metadata)
		}
	}
}

func TestValidSubmitOrganizationAgentCommandAcceptsCanonicalPackage(t *testing.T) {
	now := time.Date(2026, 7, 21, 9, 0, 0, 0, time.UTC)
	canonical, err := CanonicalizeOrganizationSubmission(lockedOrganizationInitialPackage(t))
	if err != nil {
		t.Fatalf("CanonicalizeOrganizationSubmission() error = %v", err)
	}
	command := SubmitOrganizationAgentCommand{
		SubmissionID:   uuid.New(),
		OrganizationID: uuid.New(),
		Principal: Principal{
			UserID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New(),
		},
		Canonical: canonical,
		Idempotency: IdempotencyEvidence{
			ID:          uuid.New(),
			KeyHash:     sha256.Sum256([]byte("canonical-package-key")),
			RequestHash: sha256.Sum256([]byte("canonical-package-request")),
			ExpiresAt:   now.Add(time.Hour),
		},
		Audit:       AuditEvidence{EventID: uuid.New(), RequestID: "canonical-package-request"},
		SubmittedAt: now,
	}

	if !validSubmitOrganizationAgentCommand(command) {
		t.Fatal("validSubmitOrganizationAgentCommand() rejected a canonical Organization submission")
	}
}

func TestOrganizationSubmissionRepositoryIdempotencyWithdrawalAndLifecycle(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	command := fixture.submitCommand(t, fixture.owner, 0x81)
	first, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, command)
	if err != nil || first.Replayed {
		t.Fatalf("SubmitOrganizationAgent() = %+v error=%v", first, err)
	}
	replayed, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, command)
	if err != nil || !replayed.Replayed || replayed.ID != first.ID {
		t.Fatalf("SubmitOrganizationAgent(replay) = %+v error=%v", replayed, err)
	}
	changed := command
	changed.Idempotency.RequestHash = sha256.Sum256([]byte("changed Organization submission"))
	if _, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotency replay error = %v, want ErrIdempotencyConflict", err)
	}

	for name, principal := range map[string]Principal{"member": fixture.member, "auditor": fixture.auditor} {
		t.Run(name+" cannot submit", func(t *testing.T) {
			unauthorized := fixture.submitCommand(t, principal, byte(0x82+len(name)))
			if _, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, unauthorized); !errors.Is(err, ErrOrganizationAgentForbidden) {
				t.Fatalf("SubmitOrganizationAgent(%s) error = %v", name, err)
			}
		})
	}

	other := fixture.submitInitial(t, fixture.owner, 0x91)
	if _, err := fixture.repository.WithdrawOrganizationAgentSubmission(fixture.ctx, WithdrawOrganizationAgentCommand{
		OrganizationID: fixture.organizationID, SubmissionID: other.ID, ExpectedRevision: other.Revision,
		Principal: fixture.admin, Idempotency: fixture.idempotency(0x92),
		Audit: fixture.auditEvidence(0x92), WithdrawnAt: fixture.now.Add(2 * time.Minute),
	}); !errors.Is(err, ErrOrganizationAgentForbidden) {
		t.Fatalf("another Admin withdrawal error = %v, want ErrOrganizationAgentForbidden", err)
	}
	withdrawn, err := fixture.repository.WithdrawOrganizationAgentSubmission(fixture.ctx, WithdrawOrganizationAgentCommand{
		OrganizationID: fixture.organizationID, SubmissionID: other.ID, ExpectedRevision: other.Revision,
		Principal: fixture.owner, Idempotency: fixture.idempotency(0x93),
		Audit: fixture.auditEvidence(0x93), WithdrawnAt: fixture.now.Add(3 * time.Minute),
	})
	if err != nil || withdrawn.Status != OrganizationSubmissionWithdrawn || withdrawn.Revision != 2 {
		t.Fatalf("withdrawal = %+v error=%v", withdrawn, err)
	}
	if withdrawn.Review != nil {
		t.Fatal("withdrawal unexpectedly created a Review")
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations
		SET status = 'archived', archived_at = $2, updated_at = $2, revision = revision + 1
		WHERE id = $1
	`, fixture.organizationID, fixture.now.Add(4*time.Minute)); err != nil {
		t.Fatalf("archive Organization: %v", err)
	}
	archived := fixture.submitCommand(t, fixture.owner, 0x94)
	if _, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, archived); !errors.Is(err, ErrOrganizationArchived) {
		t.Fatalf("archived submission error = %v, want ErrOrganizationArchived", err)
	}
	history, err := fixture.repository.ListOrganizationAgentSubmissions(fixture.ctx, fixture.auditor, fixture.organizationID)
	if err != nil || len(history) != 2 {
		t.Fatalf("archived history = %+v error=%v", history, err)
	}
}

func TestOrganizationApprovalAllowsSingleCurrentOwnerReview(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	submission := fixture.submitInitial(t, fixture.owner, 0xa1)
	approved, err := fixture.repository.ReviewOrganizationAgentSubmission(
		fixture.ctx, fixture.approvalCommand(t, submission, fixture.owner, 0xa2),
	)
	if err != nil {
		t.Fatalf("owner approval error = %v", err)
	}
	if approved.Status != OrganizationSubmissionApproved || approved.Revision != 2 ||
		approved.Review == nil || approved.Review.ReviewerUserID != fixture.owner.UserID {
		t.Fatalf("owner-approved submission = %+v", approved)
	}
}

func TestOrganizationApprovalPublishesOneLinkedSignedVersionAndReplays(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	submission := fixture.submitInitial(t, fixture.owner, 0xa3)
	command := fixture.approvalCommand(t, submission, fixture.admin, 0xa4)
	approved, err := fixture.repository.ReviewOrganizationAgentSubmission(fixture.ctx, command)
	if err != nil {
		t.Fatalf("ReviewOrganizationAgentSubmission(approve) error = %v", err)
	}
	if approved.Status != OrganizationSubmissionApproved || approved.Revision != 2 ||
		approved.Review == nil || approved.Review.Decision != OrganizationReviewApprove {
		t.Fatalf("approved submission = %+v", approved)
	}
	replayed, err := fixture.repository.ReviewOrganizationAgentSubmission(fixture.ctx, command)
	if err != nil || !replayed.Replayed || replayed.Status != OrganizationSubmissionApproved {
		t.Fatalf("approval replay = %+v error=%v", replayed, err)
	}

	var definitionScope string
	var definitionOrganizationID, createdBy, versionID, submissionID, policyID, publishedBy uuid.UUID
	var versionNumber int64
	var signature []byte
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT definition.owner_scope, definition.organization_id, definition.created_by,
		       version.id, version.version_number, version.signature,
		       version.organization_submission_id, version.organization_policy_snapshot_id,
		       version.published_by
		FROM agent_definitions definition
		JOIN agent_versions version ON version.id = definition.latest_version_id
		WHERE definition.id = $1
	`, submission.DefinitionID).Scan(
		&definitionScope, &definitionOrganizationID, &createdBy, &versionID, &versionNumber,
		&signature, &submissionID, &policyID, &publishedBy,
	); err != nil {
		t.Fatalf("read approved Organization Agent = %v", err)
	}
	if definitionScope != "ORGANIZATION" || definitionOrganizationID != fixture.organizationID ||
		createdBy != fixture.owner.UserID || versionNumber != 1 || len(signature) != 64 ||
		submissionID != submission.ID || policyID != fixture.policyID || publishedBy != fixture.admin.UserID {
		t.Fatalf("approved linkage = scope=%s org=%s created=%s version=%s/%d signature=%d submission=%s policy=%s publisher=%s",
			definitionScope, definitionOrganizationID, createdBy, versionID, versionNumber, len(signature),
			submissionID, policyID, publishedBy)
	}
	fixture.assertVersionCount(t, submission.DefinitionID, 1)
}

func TestOrganizationApprovalRaceCreatesAtMostOneVersionAndReview(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	submission := fixture.submitInitial(t, fixture.owner, 0xa5)
	commands := []ReviewOrganizationAgentCommand{
		fixture.approvalCommand(t, submission, fixture.admin, 0xa6),
		fixture.approvalCommand(t, submission, fixture.secondAdmin, 0xa7),
	}
	start := make(chan struct{})
	errorsChannel := make(chan error, len(commands))
	var ready sync.WaitGroup
	ready.Add(len(commands))
	for _, command := range commands {
		command := command
		go func() {
			ready.Done()
			<-start
			_, err := fixture.repository.ReviewOrganizationAgentSubmission(fixture.ctx, command)
			errorsChannel <- err
		}()
	}
	ready.Wait()
	close(start)
	approved := 0
	for range commands {
		if err := <-errorsChannel; err == nil {
			approved++
		}
	}
	if approved != 1 {
		t.Fatalf("successful approvals = %d, want 1", approved)
	}
	fixture.assertVersionCount(t, submission.DefinitionID, 1)
	var reviews int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM organization_agent_reviews WHERE submission_id = $1
	`, submission.ID).Scan(&reviews); err != nil || reviews != 1 {
		t.Fatalf("review count = %d error=%v", reviews, err)
	}
}

func TestOrganizationNextApprovalCommitsSupersededWithoutVersion(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	initial := fixture.submitInitial(t, fixture.owner, 0xb1)
	if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
		fixture.ctx, fixture.approvalCommand(t, initial, fixture.admin, 0xb2),
	); err != nil {
		t.Fatalf("approve initial error = %v", err)
	}
	baseVersionID := fixture.latestVersionID(t, initial.DefinitionID)
	first := fixture.submitNext(t, fixture.owner, initial.DefinitionID, baseVersionID, 0xb3)
	second := fixture.submitNext(t, fixture.owner, initial.DefinitionID, baseVersionID, 0xb4)
	if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
		fixture.ctx, fixture.approvalCommand(t, first, fixture.admin, 0xb5),
	); err != nil {
		t.Fatalf("approve first next error = %v", err)
	}
	_, err := fixture.repository.ReviewOrganizationAgentSubmission(
		fixture.ctx, fixture.approvalCommand(t, second, fixture.secondAdmin, 0xb6),
	)
	var superseded *OrganizationSubmissionSupersededError
	if !errors.As(err, &superseded) || superseded.Submission.Status != OrganizationSubmissionSuperseded {
		t.Fatalf("second next error = %#v, want committed superseded result", err)
	}
	fixture.assertVersionCount(t, initial.DefinitionID, 2)
}

func TestOrganizationApprovalFailuresRollbackPublication(t *testing.T) {
	t.Run("signer failure", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		submission := fixture.submitInitial(t, fixture.owner, 0xc1)
		command := fixture.approvalCommand(t, submission, fixture.admin, 0xc2)
		builderError := errors.New("signer unavailable")
		command.BuildVersion = func(CanonicalOrganizationSubmission, int64) (VersionMaterial, error) {
			return VersionMaterial{}, builderError
		}
		if _, err := fixture.repository.ReviewOrganizationAgentSubmission(fixture.ctx, command); !errors.Is(err, builderError) {
			t.Fatalf("signer failure error = %v", err)
		}
		fixture.assertSubmissionPending(t, submission)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})

	t.Run("submitter demotion", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		submission := fixture.submitInitial(t, fixture.admin, 0xc3)
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			UPDATE organization_memberships SET role = 'member', revision = revision + 1, updated_at = $3
			WHERE organization_id = $1 AND user_id = $2
		`, fixture.organizationID, fixture.admin.UserID, fixture.now.Add(time.Minute)); err != nil {
			t.Fatalf("demote submitter: %v", err)
		}
		if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
			fixture.ctx, fixture.approvalCommand(t, submission, fixture.secondAdmin, 0xc4),
		); !errors.Is(err, ErrOrganizationAgentForbidden) {
			t.Fatalf("demoted submitter approval error = %v", err)
		}
		fixture.assertSubmissionPending(t, submission)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})

	t.Run("reviewer removal", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		submission := fixture.submitInitial(t, fixture.owner, 0xc5)
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2
		`, fixture.organizationID, fixture.admin.UserID); err != nil {
			t.Fatalf("remove reviewer: %v", err)
		}
		if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
			fixture.ctx, fixture.approvalCommand(t, submission, fixture.admin, 0xc6),
		); !errors.Is(err, ErrOrganizationAgentNotFound) {
			t.Fatalf("removed reviewer approval error = %v", err)
		}
		fixture.assertSubmissionPending(t, submission)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})

	t.Run("archived organization", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		submission := fixture.submitInitial(t, fixture.owner, 0xc7)
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			UPDATE organizations
			SET status = 'archived', archived_at = $2, updated_at = $2, revision = revision + 1
			WHERE id = $1
		`, fixture.organizationID, fixture.now.Add(time.Minute)); err != nil {
			t.Fatalf("archive Organization: %v", err)
		}
		if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
			fixture.ctx, fixture.approvalCommand(t, submission, fixture.admin, 0xc8),
		); !errors.Is(err, ErrOrganizationArchived) {
			t.Fatalf("archived approval error = %v", err)
		}
		fixture.assertSubmissionPending(t, submission)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})

	t.Run("current policy denial", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		submission := fixture.submitInitial(t, fixture.owner, 0xc9)
		fixture.replacePolicy(t, organization.PolicyDocument{
			SchemaVersion: 1,
			Models: organization.ModelPolicy{Allowlist: []organization.ModelIdentifier{{
				Provider: "blocked-provider", Model: "blocked-model",
			}}},
			Tools:                organization.ToolPolicy{Allowlist: nil},
			ExperienceCandidates: organization.ExperienceCandidatePolicy{Mode: organization.ExperienceCandidateManualReview},
			OfficialAgents:       organization.OfficialAgentPolicy{Installation: organization.OfficialAgentInstallationAllowed},
		})
		if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
			fixture.ctx, fixture.approvalCommand(t, submission, fixture.admin, 0xca),
		); !errors.Is(err, ErrOrganizationPublicationPolicyBlocked) {
			t.Fatalf("policy-denied approval error = %v", err)
		}
		fixture.assertSubmissionPending(t, submission)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})

	t.Run("current DLP denial", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		manifest, bundle := singleAssetFixture(
			"knowledge/private.md", []byte("API_KEY=correct-horse-battery\nHERMES_HOME=/Users/alice/.hermes"),
		)
		input := lockedOrganizationInitialPackage(t)
		input.DefinitionID = uuid.New()
		input.Manifest = manifest
		input.Bundle = bundle
		submission := fixture.insertPendingDirect(t, input, nil, 0xcb)
		_, err := fixture.repository.ReviewOrganizationAgentSubmission(
			fixture.ctx, fixture.approvalCommand(t, submission, fixture.admin, 0xcc),
		)
		var dlpError *OrganizationPublicationDLPError
		if !errors.As(err, &dlpError) || len(dlpError.Findings) != 2 {
			t.Fatalf("DLP-denied approval error = %#v", err)
		}
		fixture.assertSubmissionPending(t, submission)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})

	t.Run("stored digest mismatch", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		input := lockedOrganizationInitialPackage(t)
		input.DefinitionID = uuid.New()
		badDigest := sha256.Sum256([]byte("tampered digest"))
		submission := fixture.insertPendingDirect(t, input, &badDigest, 0xcd)
		if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
			fixture.ctx, fixture.approvalCommand(t, submission, fixture.admin, 0xce),
		); !errors.Is(err, ErrServiceUnavailable) && !errors.Is(err, ErrInvalidAgentContent) {
			t.Fatalf("digest mismatch approval error = %v", err)
		}
		fixture.assertRawSubmissionPending(t, submission.ID)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})

	t.Run("late audit failure", func(t *testing.T) {
		fixture := newOrganizationSubmissionRepositoryFixture(t)
		submitCommand := fixture.submitCommand(t, fixture.owner, 0xcf)
		submission, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, submitCommand)
		if err != nil {
			t.Fatalf("SubmitOrganizationAgent() error = %v", err)
		}
		command := fixture.approvalCommand(t, submission, fixture.admin, 0xd0)
		command.Audit = submitCommand.Audit
		if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
			fixture.ctx, command,
		); !errors.Is(err, ErrServiceUnavailable) {
			t.Fatalf("duplicate audit approval error = %v", err)
		}
		fixture.assertSubmissionPending(t, submission)
		fixture.assertNoDefinitionOrVersion(t, submission.DefinitionID)
	})
}

type organizationSubmissionRepositoryFixture struct {
	*agentControlRepositoryFixture
	organizationID uuid.UUID
	policyID       uuid.UUID
	owner          Principal
	admin          Principal
	secondAdmin    Principal
	auditor        Principal
	member         Principal
	outsider       Principal
}

func newOrganizationSubmissionRepositoryFixture(t *testing.T) *organizationSubmissionRepositoryFixture {
	t.Helper()
	base := newAgentControlRepositoryFixture(t)
	fixture := &organizationSubmissionRepositoryFixture{
		agentControlRepositoryFixture: base,
		organizationID:                uuid.New(),
		policyID:                      uuid.New(),
		owner:                         base.principal(t, 0x51),
		admin:                         base.principal(t, 0x52),
		secondAdmin:                   base.principal(t, 0x56),
		auditor:                       base.principal(t, 0x53),
		member:                        base.principal(t, 0x54),
		outsider:                      base.principal(t, 0x55),
	}
	policy, err := organization.CanonicalizePolicy(organization.DefaultPolicyDocument())
	if err != nil {
		t.Fatalf("CanonicalizePolicy() error = %v", err)
	}
	tx, err := fixture.postgres.Begin(fixture.ctx)
	if err != nil {
		t.Fatalf("begin Organization submission fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organizations (
			id, display_name, status, revision, current_policy_snapshot_id, created_at, updated_at
		) VALUES ($1, 'Organization Agent fixture', 'active', 1, $2, $3, $3)
	`, fixture.organizationID, fixture.policyID, fixture.now); err != nil {
		t.Fatalf("insert Organization: %v", err)
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document, content_digest,
			issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES ($1, $2, 1, 1, $3::jsonb, $4, 'agentera://test', 'organization-agent-test', $5, $6, $7)
	`, fixture.policyID, fixture.organizationID, string(policy.CanonicalJSON), policy.ContentDigest[:],
		bytes.Repeat([]byte{0x41}, 64), fixture.owner.UserID, fixture.now); err != nil {
		t.Fatalf("insert Organization policy: %v", err)
	}
	for _, membership := range []struct {
		role      string
		principal Principal
	}{
		{role: "owner", principal: fixture.owner},
		{role: "admin", principal: fixture.admin},
		{role: "admin", principal: fixture.secondAdmin},
		{role: "auditor", principal: fixture.auditor},
		{role: "member", principal: fixture.member},
	} {
		if _, err := tx.Exec(fixture.ctx, `
			INSERT INTO organization_memberships (
				organization_id, user_id, role, revision, joined_at, updated_at
			) VALUES ($1, $2, $3, 1, $4, $4)
		`, fixture.organizationID, membership.principal.UserID, membership.role, fixture.now); err != nil {
			t.Fatalf("insert %s membership: %v", membership.role, err)
		}
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatalf("commit Organization submission fixture: %v", err)
	}
	return fixture
}

func (fixture *organizationSubmissionRepositoryFixture) submitNext(
	t *testing.T,
	principal Principal,
	definitionID uuid.UUID,
	baseVersionID uuid.UUID,
	discriminator byte,
) OrganizationAgentSubmission {
	t.Helper()
	input := lockedOrganizationInitialPackage(t)
	input.Kind = OrganizationSubmissionNext
	input.DefinitionID = definitionID
	input.BaseVersionID = baseVersionID
	input.DisplayName = ""
	input.IconMediaType = ""
	input.IconData = nil
	canonical, err := CanonicalizeOrganizationSubmission(input)
	if err != nil {
		t.Fatalf("CanonicalizeOrganizationSubmission(next) error = %v", err)
	}
	result, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, SubmitOrganizationAgentCommand{
		SubmissionID: uuid.New(), OrganizationID: fixture.organizationID, Principal: principal,
		Canonical: canonical, Idempotency: fixture.idempotency(discriminator),
		Audit: fixture.auditEvidence(discriminator), SubmittedAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	})
	if err != nil {
		t.Fatalf("SubmitOrganizationAgent(next) error = %v", err)
	}
	return result
}

func (fixture *organizationSubmissionRepositoryFixture) approvalCommand(
	t *testing.T,
	submission OrganizationAgentSubmission,
	reviewer Principal,
	discriminator byte,
) ReviewOrganizationAgentCommand {
	t.Helper()
	versionID := uuid.New()
	return ReviewOrganizationAgentCommand{
		ReviewID: uuid.New(), OrganizationID: fixture.organizationID, SubmissionID: submission.ID,
		ExpectedRevision: submission.Revision, Principal: reviewer, Decision: OrganizationReviewApprove,
		BuildVersion: func(canonical CanonicalOrganizationSubmission, versionNumber int64) (VersionMaterial, error) {
			version, err := CanonicalizeVersion(canonical.Package.Manifest, canonical.Package.Bundle)
			if err != nil {
				return VersionMaterial{}, err
			}
			return VersionMaterial{
				ID: versionID, VersionNumber: versionNumber,
				CanonicalManifest: version.ManifestJSON, Bundle: version.BundleJSON,
				ContentDigest: version.ContentDigest, SigningKeyID: "agent-control-v1",
				Signature:                      bytes.Repeat([]byte{discriminator}, 64),
				RuntimeMinimumVersion:          canonical.Package.Manifest.RuntimeCompatibility.MinimumVersion,
				RuntimeMaximumVersionExclusive: canonical.Package.Manifest.RuntimeCompatibility.MaximumVersionExclusive,
			}, nil
		},
		Idempotency: fixture.idempotency(discriminator), Audit: fixture.auditEvidence(discriminator),
		ReviewedAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	}
}

func (fixture *organizationSubmissionRepositoryFixture) assertSubmissionPending(
	t *testing.T,
	submission OrganizationAgentSubmission,
) {
	t.Helper()
	current, found, err := fixture.repository.FindOrganizationAgentSubmission(
		fixture.ctx, fixture.owner, fixture.organizationID, submission.ID,
	)
	if err != nil || !found || current.Status != OrganizationSubmissionPending ||
		current.Revision != submission.Revision || current.Review != nil {
		t.Fatalf("pending submission = %+v found=%t error=%v", current, found, err)
	}
}

func (fixture *organizationSubmissionRepositoryFixture) assertVersionCount(
	t *testing.T,
	definitionID uuid.UUID,
	want int64,
) {
	t.Helper()
	var count int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM agent_versions WHERE definition_id = $1
	`, definitionID).Scan(&count); err != nil || count != want {
		t.Fatalf("version count = %d, want %d, error=%v", count, want, err)
	}
}

func (fixture *organizationSubmissionRepositoryFixture) latestVersionID(
	t *testing.T,
	definitionID uuid.UUID,
) uuid.UUID {
	t.Helper()
	var versionID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT latest_version_id FROM agent_definitions WHERE id = $1
	`, definitionID).Scan(&versionID); err != nil {
		t.Fatalf("read latest version: %v", err)
	}
	return versionID
}

func (fixture *organizationSubmissionRepositoryFixture) replacePolicy(
	t *testing.T,
	document organization.PolicyDocument,
) {
	t.Helper()
	canonical, err := organization.CanonicalizePolicy(document)
	if err != nil {
		t.Fatalf("CanonicalizePolicy() error = %v", err)
	}
	policyID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document, content_digest,
			issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES ($1, $2, 2, 1, $3::jsonb, $4, 'agentera://test', 'organization-agent-test', $5, $6, $7)
	`, policyID, fixture.organizationID, string(canonical.CanonicalJSON), canonical.ContentDigest[:],
		bytes.Repeat([]byte{0x42}, 64), fixture.owner.UserID, fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("insert replacement Organization policy: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations
		SET current_policy_snapshot_id = $2, revision = revision + 1, updated_at = $3
		WHERE id = $1
	`, fixture.organizationID, policyID, fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("activate replacement Organization policy: %v", err)
	}
}

func (fixture *organizationSubmissionRepositoryFixture) insertPendingDirect(
	t *testing.T,
	input OrganizationSubmissionPackage,
	contentDigestOverride *[sha256.Size]byte,
	discriminator byte,
) OrganizationAgentSubmission {
	t.Helper()
	canonical, err := CanonicalizeOrganizationSubmission(input)
	if err != nil {
		t.Fatalf("CanonicalizeOrganizationSubmission() error = %v", err)
	}
	version, err := CanonicalizeVersion(canonical.Package.Manifest, canonical.Package.Bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	contentDigest := canonical.ContentDigest
	if contentDigestOverride != nil {
		contentDigest = *contentDigestOverride
	}
	submissionID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_agent_submissions (
			id, organization_id, kind, definition_id, base_version_id, display_name,
			icon_media_type, icon_data, canonical_manifest, bundle, manifest_digest,
			bundle_digest, content_digest, submitted_by_user_id, status, revision,
			submitted_at, terminal_at, updated_at
		) VALUES ($1, $2, 'initial', $3, NULL, $4, NULLIF($5, ''), $6,
		          $7::jsonb, $8::jsonb, $9, $10, $11, $12, 'pending', 1, $13, NULL, $13)
	`, submissionID, fixture.organizationID, input.DefinitionID, input.DisplayName,
		input.IconMediaType, nilIfEmptyBytes(input.IconData), string(version.ManifestJSON),
		string(version.BundleJSON), canonical.ManifestDigest[:], canonical.BundleDigest[:],
		contentDigest[:], fixture.owner.UserID,
		fixture.now.Add(time.Duration(discriminator)*time.Second)); err != nil {
		t.Fatalf("insert direct pending submission: %v", err)
	}
	return OrganizationAgentSubmission{
		ID: submissionID, OrganizationID: fixture.organizationID,
		DefinitionID: input.DefinitionID, Revision: 1, Status: OrganizationSubmissionPending,
		SubmittedByUserID: fixture.owner.UserID,
	}
}

func (fixture *organizationSubmissionRepositoryFixture) assertRawSubmissionPending(
	t *testing.T,
	submissionID uuid.UUID,
) {
	t.Helper()
	var status string
	var revision int64
	var reviews int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT submission.status, submission.revision,
		       (SELECT count(*) FROM organization_agent_reviews review WHERE review.submission_id = submission.id)
		FROM organization_agent_submissions submission WHERE submission.id = $1
	`, submissionID).Scan(&status, &revision, &reviews); err != nil {
		t.Fatalf("read raw pending submission: %v", err)
	}
	if status != "pending" || revision != 1 || reviews != 0 {
		t.Fatalf("raw submission state = %s/%d reviews=%d", status, revision, reviews)
	}
}

func (fixture *organizationSubmissionRepositoryFixture) submitCommand(
	t *testing.T,
	principal Principal,
	discriminator byte,
) SubmitOrganizationAgentCommand {
	t.Helper()
	input := lockedOrganizationInitialPackage(t)
	input.DefinitionID = uuid.New()
	input.IconMediaType = ""
	input.IconData = nil
	canonical, err := CanonicalizeOrganizationSubmission(input)
	if err != nil {
		t.Fatalf("CanonicalizeOrganizationSubmission() error = %v", err)
	}
	return SubmitOrganizationAgentCommand{
		SubmissionID: uuid.New(), OrganizationID: fixture.organizationID, Principal: principal,
		Canonical: canonical, Idempotency: fixture.idempotency(discriminator),
		Audit: fixture.auditEvidence(discriminator), SubmittedAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	}
}

func (fixture *organizationSubmissionRepositoryFixture) submitInitial(
	t *testing.T,
	principal Principal,
	discriminator byte,
) OrganizationAgentSubmission {
	t.Helper()
	result, err := fixture.repository.SubmitOrganizationAgent(fixture.ctx, fixture.submitCommand(t, principal, discriminator))
	if err != nil {
		t.Fatalf("SubmitOrganizationAgent() error = %v", err)
	}
	return result
}

func (fixture *organizationSubmissionRepositoryFixture) assertNoDefinitionOrVersion(
	t *testing.T,
	definitionID uuid.UUID,
) {
	t.Helper()
	var definitions, versions int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT
			(SELECT count(*) FROM agent_definitions WHERE id = $1),
			(SELECT count(*) FROM agent_versions WHERE definition_id = $1)
	`, definitionID).Scan(&definitions, &versions); err != nil {
		t.Fatalf("count Organization Agent publication rows: %v", err)
	}
	if definitions != 0 || versions != 0 {
		t.Fatalf("Definition/Version counts = %d/%d, want 0/0", definitions, versions)
	}
}
