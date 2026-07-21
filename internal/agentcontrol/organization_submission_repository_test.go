package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
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
		Idempotency: fixture.idempotency(0x72), Audit: fixture.auditEvidence(0x72), ReviewedAt: fixture.now.Add(time.Minute),
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

type organizationSubmissionRepositoryFixture struct {
	*agentControlRepositoryFixture
	organizationID uuid.UUID
	policyID       uuid.UUID
	owner          Principal
	admin          Principal
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
	for role, principal := range map[string]Principal{
		"owner": fixture.owner, "admin": fixture.admin, "auditor": fixture.auditor, "member": fixture.member,
	} {
		if _, err := tx.Exec(fixture.ctx, `
			INSERT INTO organization_memberships (
				organization_id, user_id, role, revision, joined_at, updated_at
			) VALUES ($1, $2, $3, 1, $4, $4)
		`, fixture.organizationID, principal.UserID, role, fixture.now); err != nil {
			t.Fatalf("insert %s membership: %v", role, err)
		}
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatalf("commit Organization submission fixture: %v", err)
	}
	return fixture
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
