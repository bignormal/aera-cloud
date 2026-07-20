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

	accountrepo "github.com/bignormal/aera-cloud/internal/account"
	"github.com/google/uuid"
)

func TestExperienceCandidateRepositoryAllowsEveryActiveWorkspaceRoleToSubmit(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 41)
	admin := fixture.principal(t, 42)
	member := fixture.principal(t, 43)
	workspaceID := seedAgentWorkspace(t, fixture, owner, admin, member)
	publication := publishWorkspaceCandidateFixture(t, fixture, owner, workspaceID, 41)

	for index, actor := range []struct {
		name      string
		principal Principal
	}{
		{name: "owner", principal: owner},
		{name: "admin", principal: admin},
		{name: "member", principal: member},
	} {
		t.Run(actor.name, func(t *testing.T) {
			discriminator := byte(44 + index*3)
			activateWorkspaceCandidateInstallation(
				t, fixture, actor.principal, workspaceID, publication, discriminator,
			)
			command := fixture.submitExperienceCandidateCommand(workspaceID, publication, discriminator+2)
			candidate, replayed, err := fixture.repository.SubmitExperienceCandidate(
				fixture.ctx, actor.principal, command,
			)
			if err != nil || replayed || candidate.SubmittedByUserID == nil ||
				*candidate.SubmittedByUserID != actor.principal.UserID {
				t.Fatalf("SubmitExperienceCandidate(%s) = %+v replayed=%t error=%v", actor.name, candidate, replayed, err)
			}
		})
	}
}

func TestExperienceCandidateRepositorySubmissionVisibilityIdempotencyAndAudit(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 61)
	admin := fixture.principal(t, 62)
	member := fixture.principal(t, 63)
	otherMember := fixture.principal(t, 64)
	outsider := fixture.principal(t, 65)
	workspaceID := seedAgentWorkspaceWithMembers(t, fixture, owner, admin, member, otherMember)
	publication := publishWorkspaceCandidateFixture(t, fixture, owner, workspaceID, 61)
	activateWorkspaceCandidateInstallation(t, fixture, member, workspaceID, publication, 63)

	command := fixture.submitExperienceCandidateCommand(workspaceID, publication, 66)
	candidate, replayed, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command)
	if err != nil {
		t.Fatalf("SubmitExperienceCandidate() error = %v", err)
	}
	if replayed || candidate.ID != command.CandidateID || candidate.WorkspaceID != workspaceID ||
		candidate.AgentDefinitionID != publication.Definition.ID || candidate.SourceAgentVersionID != publication.Version.ID ||
		candidate.SubmittedByUserID == nil || *candidate.SubmittedByUserID != member.UserID ||
		candidate.SubmittedFromDeviceID == nil || *candidate.SubmittedFromDeviceID != member.DeviceID || candidate.Review != nil {
		t.Fatalf("submitted candidate = %+v replayed=%t", candidate, replayed)
	}

	replayedCandidate, replayed, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command)
	if err != nil || !replayed || replayedCandidate.ID != candidate.ID {
		t.Fatalf("SubmitExperienceCandidate(replay) = %+v replayed=%t error=%v", replayedCandidate, replayed, err)
	}
	changed := command
	changed.Idempotency.RequestHash = sha256.Sum256([]byte("changed candidate request"))
	if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("SubmitExperienceCandidate(changed replay) error = %v", err)
	}

	own, err := fixture.repository.ListOwnExperienceCandidates(fixture.ctx, member, workspaceID)
	if err != nil || len(own) != 1 || own[0].ID != candidate.ID {
		t.Fatalf("ListOwnExperienceCandidates() = %+v error=%v", own, err)
	}
	otherOwn, err := fixture.repository.ListOwnExperienceCandidates(fixture.ctx, otherMember, workspaceID)
	if err != nil || len(otherOwn) != 0 {
		t.Fatalf("ListOwnExperienceCandidates(other Member) = %+v error=%v", otherOwn, err)
	}
	for name, principal := range map[string]Principal{"owner": owner, "admin": admin} {
		t.Run("review queue as "+name, func(t *testing.T) {
			all, listErr := fixture.repository.ListWorkspaceExperienceCandidates(fixture.ctx, principal, workspaceID)
			if listErr != nil || len(all) != 1 || all[0].ID != candidate.ID {
				t.Fatalf("ListWorkspaceExperienceCandidates() = %+v error=%v", all, listErr)
			}
		})
	}
	if _, err := fixture.repository.ListWorkspaceExperienceCandidates(fixture.ctx, member, workspaceID); !errors.Is(err, ErrWorkspaceForbidden) {
		t.Fatalf("ListWorkspaceExperienceCandidates(Member) error = %v", err)
	}
	if _, err := fixture.repository.ListWorkspaceExperienceCandidates(fixture.ctx, outsider, workspaceID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListWorkspaceExperienceCandidates(outsider) error = %v", err)
	}

	if _, found, err := fixture.repository.FindExperienceCandidate(
		fixture.ctx, otherMember, workspaceID, candidate.ID, fixture.auditEvidence(67), fixture.now,
	); err != nil || found {
		t.Fatalf("FindExperienceCandidate(other Member) found=%t error=%v", found, err)
	}
	detail, found, err := fixture.repository.FindExperienceCandidate(
		fixture.ctx, owner, workspaceID, candidate.ID, fixture.auditEvidence(68), fixture.now.Add(68*time.Minute),
	)
	if err != nil || !found || detail.ID != candidate.ID || detail.Bundle.Assets[0].Content != command.Canonical.Bundle.Assets[0].Content {
		t.Fatalf("FindExperienceCandidate(Owner) = %+v found=%t error=%v", detail, found, err)
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE experience_candidates SET skill_name = 'changed' WHERE id = $1
	`, candidate.ID); err == nil {
		t.Fatal("immutable candidate core update succeeded")
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `DELETE FROM experience_candidates WHERE id = $1`, candidate.ID); err == nil {
		t.Fatal("immutable candidate delete succeeded")
	}

	var submittedAudits, detailAudits int64
	var submittedMetadata string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*), min(metadata::text)
		FROM audit_events
		WHERE event_type = 'agent_experience_candidate_submitted' AND object_id = $1
	`, candidate.ID).Scan(&submittedAudits, &submittedMetadata); err != nil {
		t.Fatalf("read candidate submission audit: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM audit_events
		WHERE event_type = 'agent_experience_candidate_detail_accessed' AND object_id = $1
	`, candidate.ID).Scan(&detailAudits); err != nil {
		t.Fatalf("read candidate detail audit: %v", err)
	}
	if submittedAudits != 1 || detailAudits != 1 {
		t.Fatalf("candidate audit counts submitted/detail = %d/%d, want 1/1", submittedAudits, detailAudits)
	}
	for _, forbidden := range []string{"Weekly summary", "SKILL.md", "bundle_document", "source_path", "/Users/"} {
		if strings.Contains(submittedMetadata, forbidden) {
			t.Fatalf("candidate audit metadata leaked %q: %s", forbidden, submittedMetadata)
		}
	}
}

func TestExperienceCandidateRepositoryRequiresExactActiveUserInstallation(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 71)
	member := fixture.principal(t, 72)
	workspaceID := seedAgentWorkspace(t, fixture, owner, Principal{}, member)
	publication := publishWorkspaceCandidateFixture(t, fixture, owner, workspaceID, 71)

	pending := fixture.pendingInstallation(member, publication.Definition.ID, publication.Version.ID, 1, 72)
	pending.SourceWorkspaceID = &workspaceID
	created, err := fixture.repository.CreatePendingInstallation(fixture.ctx, member, pending)
	if err != nil {
		t.Fatalf("CreatePendingInstallation() error = %v", err)
	}
	command := fixture.submitExperienceCandidateCommand(workspaceID, publication, 73)
	if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SubmitExperienceCandidate(pending Installation) error = %v", err)
	}

	runtimeProfileID := uuid.New()
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, member, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: runtimeProfileID,
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest,
		Audit:         fixture.auditEvidence(74), ActivatedAt: fixture.now.Add(74 * time.Minute),
	}); err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}
	if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command); err != nil {
		t.Fatalf("SubmitExperienceCandidate(active Installation) error = %v", err)
	}

	for name, mutate := range map[string]func(*SubmitExperienceCandidateCommand){
		"wrong definition": func(value *SubmitExperienceCandidateCommand) { value.DefinitionID = uuid.New() },
		"wrong version":    func(value *SubmitExperienceCandidateCommand) { value.SourceVersionID = uuid.New() },
		"wrong workspace":  func(value *SubmitExperienceCandidateCommand) { value.WorkspaceID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := fixture.submitExperienceCandidateCommand(workspaceID, publication, byte(80+len(name)))
			mutate(&invalid)
			if _, _, submitErr := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, invalid); !errors.Is(submitErr, ErrNotFound) {
				t.Fatalf("SubmitExperienceCandidate() error = %v", submitErr)
			}
		})
	}

	otherDevice := member
	otherDevice.DeviceID = uuid.New()
	wrongDevice := fixture.submitExperienceCandidateCommand(workspaceID, publication, 91)
	if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, otherDevice, wrongDevice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SubmitExperienceCandidate(wrong device) error = %v", err)
	}
}

func TestExperienceCandidateRepositoryFailsClosedAfterWorkspaceLifecycleChanges(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)

	seedCandidateSource := func(discriminator byte) (Principal, Principal, uuid.UUID, Publication) {
		t.Helper()
		owner := fixture.principal(t, discriminator)
		member := fixture.principal(t, discriminator+1)
		workspaceID := seedAgentWorkspace(t, fixture, owner, Principal{}, member)
		publication := publishWorkspaceCandidateFixture(t, fixture, owner, workspaceID, discriminator)
		activateWorkspaceCandidateInstallation(t, fixture, member, workspaceID, publication, discriminator+1)
		return owner, member, workspaceID, publication
	}

	t.Run("removed membership", func(t *testing.T) {
		_, member, workspaceID, publication := seedCandidateSource(121)
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2
		`, workspaceID, member.UserID); err != nil {
			t.Fatalf("remove Workspace Member: %v", err)
		}
		command := fixture.submitExperienceCandidateCommand(workspaceID, publication, 123)
		if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command); !errors.Is(err, ErrNotFound) {
			t.Fatalf("SubmitExperienceCandidate(removed Member) error = %v", err)
		}
	})

	t.Run("archived workspace", func(t *testing.T) {
		_, member, workspaceID, publication := seedCandidateSource(131)
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			UPDATE workspaces SET status = 'archived', archived_at = $2, updated_at = $2 WHERE id = $1
		`, workspaceID, fixture.now.Add(time.Hour)); err != nil {
			t.Fatalf("archive Workspace: %v", err)
		}
		command := fixture.submitExperienceCandidateCommand(workspaceID, publication, 133)
		if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command); !errors.Is(err, ErrWorkspaceArchived) {
			t.Fatalf("SubmitExperienceCandidate(archived Workspace) error = %v", err)
		}
	})

	t.Run("owner unavailable", func(t *testing.T) {
		owner, member, workspaceID, publication := seedCandidateSource(141)
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			UPDATE users SET status = 'pending_deletion', deletion_requested_at = $2, updated_at = $2 WHERE id = $1
		`, owner.UserID, fixture.now.Add(time.Hour)); err != nil {
			t.Fatalf("freeze Workspace Owner: %v", err)
		}
		command := fixture.submitExperienceCandidateCommand(workspaceID, publication, 143)
		if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command); !errors.Is(err, ErrWorkspaceOwnerUnavailable) {
			t.Fatalf("SubmitExperienceCandidate(owner unavailable) error = %v", err)
		}
	})
}

func TestExperienceCandidateContributionSerializesMembershipRemoval(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 151)
	member := fixture.principal(t, 152)
	workspaceID := seedAgentWorkspace(t, fixture, owner, Principal{}, member)
	publication := publishWorkspaceCandidateFixture(t, fixture, owner, workspaceID, 151)
	activateWorkspaceCandidateInstallation(t, fixture, member, workspaceID, publication, 152)

	tx, err := fixture.postgres.Begin(fixture.ctx)
	if err != nil {
		t.Fatalf("begin membership lock transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := requireWorkspaceAgentAccess(
		fixture.ctx, tx, member, workspaceID, workspaceAgentContribute, true,
	); err != nil {
		t.Fatalf("lock candidate contribution access: %v", err)
	}

	blockedContext, cancel := context.WithTimeout(fixture.ctx, 250*time.Millisecond)
	defer cancel()
	if _, err := fixture.postgres.Exec(blockedContext, `
		DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2
	`, workspaceID, member.UserID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("racing membership removal error = %v, want deadline while contribution lock is held", err)
	}
	if err := tx.Rollback(fixture.ctx); err != nil {
		t.Fatalf("release contribution lock: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2
	`, workspaceID, member.UserID); err != nil {
		t.Fatalf("remove membership after contribution transaction: %v", err)
	}
	command := fixture.submitExperienceCandidateCommand(workspaceID, publication, 154)
	if _, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SubmitExperienceCandidate(after racing removal) error = %v", err)
	}
}

func TestExperienceCandidateRepositoryTerminalReviewRaceAndAccountDeletion(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 101)
	admin := fixture.principal(t, 102)
	member := fixture.principal(t, 103)
	workspaceID := seedAgentWorkspace(t, fixture, owner, admin, member)
	publication := publishWorkspaceCandidateFixture(t, fixture, owner, workspaceID, 101)
	activateWorkspaceCandidateInstallation(t, fixture, member, workspaceID, publication, 103)
	command := fixture.submitExperienceCandidateCommand(workspaceID, publication, 104)
	candidate, _, err := fixture.repository.SubmitExperienceCandidate(fixture.ctx, member, command)
	if err != nil {
		t.Fatalf("SubmitExperienceCandidate() error = %v", err)
	}

	memberReview := fixture.reviewExperienceCandidateCommand(workspaceID, candidate.ID, ExperienceCandidateApproved, 105)
	if _, _, err := fixture.repository.ReviewExperienceCandidate(fixture.ctx, member, memberReview); !errors.Is(err, ErrWorkspaceForbidden) {
		t.Fatalf("ReviewExperienceCandidate(Member) error = %v", err)
	}

	commands := []struct {
		principal Principal
		command   ReviewExperienceCandidateCommand
	}{
		{principal: owner, command: fixture.reviewExperienceCandidateCommand(workspaceID, candidate.ID, ExperienceCandidateApproved, 106)},
		{principal: admin, command: fixture.reviewExperienceCandidateCommand(workspaceID, candidate.ID, ExperienceCandidateRejected, 107)},
	}
	commands[1].command.ReasonCode = "not_reusable"
	commands[1].command.SafeNote = "Candidate needs another review cycle."
	start := make(chan struct{})
	results := make(chan error, len(commands))
	var runners sync.WaitGroup
	for _, item := range commands {
		item := item
		runners.Add(1)
		go func() {
			defer runners.Done()
			<-start
			_, _, reviewErr := fixture.repository.ReviewExperienceCandidate(fixture.ctx, item.principal, item.command)
			results <- reviewErr
		}()
	}
	close(start)
	runners.Wait()
	close(results)
	successes := 0
	terminalConflicts := 0
	for reviewErr := range results {
		switch {
		case reviewErr == nil:
			successes++
		case errors.Is(reviewErr, ErrExperienceCandidateAlreadyReviewed):
			terminalConflicts++
		default:
			t.Fatalf("ReviewExperienceCandidate(race) error = %v", reviewErr)
		}
	}
	if successes != 1 || terminalConflicts != 1 {
		t.Fatalf("review race successes/conflicts = %d/%d, want 1/1", successes, terminalConflicts)
	}

	stored, found, err := fixture.repository.FindExperienceCandidate(
		fixture.ctx, owner, workspaceID, candidate.ID, fixture.auditEvidence(108), fixture.now.Add(108*time.Minute),
	)
	if err != nil || !found || stored.Review == nil {
		t.Fatalf("FindExperienceCandidate(reviewed) = %+v found=%t error=%v", stored, found, err)
	}

	winningPrincipal := owner
	winningCommand := commands[0].command
	if stored.Review.Decision == ExperienceCandidateRejected {
		winningPrincipal = admin
		winningCommand = commands[1].command
	}
	replayed, replayedReview, err := fixture.repository.ReviewExperienceCandidate(fixture.ctx, winningPrincipal, winningCommand)
	if err != nil || !replayedReview || replayed.Review == nil || replayed.Review.Decision != stored.Review.Decision {
		t.Fatalf("ReviewExperienceCandidate(replay) = %+v replayed=%t error=%v", replayed, replayedReview, err)
	}
	changed := winningCommand
	changed.Idempotency.RequestHash = sha256.Sum256([]byte("changed terminal review"))
	if _, _, err := fixture.repository.ReviewExperienceCandidate(fixture.ctx, winningPrincipal, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("ReviewExperienceCandidate(changed replay) error = %v", err)
	}

	replacementDecision := ExperienceCandidateRejected
	replacementReason := "forced_change"
	if stored.Review.Decision == ExperienceCandidateRejected {
		replacementDecision = ExperienceCandidateApproved
		replacementReason = ""
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE experience_candidate_reviews
		SET decision = $2, reason_code = NULLIF($3, ''), safe_note = NULL
		WHERE candidate_id = $1
	`, candidate.ID, replacementDecision, replacementReason); err == nil {
		t.Fatal("terminal review update succeeded")
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `DELETE FROM experience_candidate_reviews WHERE candidate_id = $1`, candidate.ID); err == nil {
		t.Fatal("terminal review delete succeeded")
	}

	accountRepository := accountrepo.NewPostgresRepository(fixture.postgres, nil)
	finalizeAccount := func(userID uuid.UUID, requestedAt time.Time) {
		t.Helper()
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			UPDATE users
			SET status = 'pending_deletion', deletion_requested_at = $2, updated_at = $2
			WHERE id = $1
		`, userID, requestedAt); err != nil {
			t.Fatalf("mark candidate actor pending deletion: %v", err)
		}
		if err := accountRepository.FinalizeDeletion(
			fixture.ctx, userID, uuid.New(), requestedAt.Add(7*24*time.Hour),
		); err != nil {
			t.Fatalf("finalize candidate actor account deletion: %v", err)
		}
	}
	finalizeAccount(member.UserID, fixture.now.Add(4*time.Hour))
	if stored.Review.ReviewedByUserID != nil && *stored.Review.ReviewedByUserID != owner.UserID {
		finalizeAccount(*stored.Review.ReviewedByUserID, fixture.now.Add(5*time.Hour))
	}
	var submitterDetached, deviceDetached bool
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT submitted_by_user_id IS NULL, submitted_from_device_id IS NULL
		FROM experience_candidates WHERE id = $1
	`, candidate.ID).Scan(&submitterDetached, &deviceDetached); err != nil {
		t.Fatalf("read detached candidate actors: %v", err)
	}
	if !submitterDetached || !deviceDetached {
		t.Fatalf("candidate submitter/device detached = %t/%t, want true/true", submitterDetached, deviceDetached)
	}
	if stored.Review.ReviewedByUserID != nil && *stored.Review.ReviewedByUserID != owner.UserID {
		var reviewerDetached bool
		if err := fixture.postgres.QueryRow(fixture.ctx, `
			SELECT reviewed_by_user_id IS NULL FROM experience_candidate_reviews WHERE candidate_id = $1
		`, candidate.ID).Scan(&reviewerDetached); err != nil || !reviewerDetached {
			t.Fatalf("reviewer detached=%t error=%v", reviewerDetached, err)
		}
	}
	preserved, found, err := fixture.repository.FindExperienceCandidate(
		fixture.ctx, owner, workspaceID, candidate.ID, fixture.auditEvidence(109), fixture.now.Add(109*time.Minute),
	)
	if err != nil || !found || preserved.ContentDigest != stored.ContentDigest || preserved.Review == nil ||
		preserved.Review.ID != stored.Review.ID || preserved.Review.Decision != stored.Review.Decision {
		t.Fatalf("candidate after account deletion = %+v found=%t error=%v", preserved, found, err)
	}
	preservedCanonical, err := CanonicalizeExperienceCandidate(preserved.Bundle)
	if err != nil || !bytes.Equal(preservedCanonical.CanonicalJSON, command.Canonical.CanonicalJSON) {
		t.Fatalf("candidate bundle changed after account deletion: error=%v", err)
	}

	var conflictAudits int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM audit_events
		WHERE event_type = 'agent_experience_candidate_review_conflicted' AND object_id = $1
	`, candidate.ID).Scan(&conflictAudits); err != nil {
		t.Fatalf("read review conflict audit: %v", err)
	}
	if conflictAudits != 1 {
		t.Fatalf("review conflict audit count = %d, want 1", conflictAudits)
	}
}

func publishWorkspaceCandidateFixture(
	t *testing.T,
	fixture *agentControlRepositoryFixture,
	owner Principal,
	workspaceID uuid.UUID,
	discriminator byte,
) Publication {
	t.Helper()
	publication, err := fixture.repository.PublishWorkspaceInitial(
		fixture.ctx, owner, workspaceID,
		fixture.initialPublication(owner, "Candidate Workspace Agent", discriminator),
	)
	if err != nil {
		t.Fatalf("PublishWorkspaceInitial() error = %v", err)
	}
	return publication
}

func activateWorkspaceCandidateInstallation(
	t *testing.T,
	fixture *agentControlRepositoryFixture,
	principal Principal,
	workspaceID uuid.UUID,
	publication Publication,
	discriminator byte,
) Installation {
	t.Helper()
	command := fixture.pendingInstallation(
		principal, publication.Definition.ID, publication.Version.ID, 1, discriminator,
	)
	command.SourceWorkspaceID = &workspaceID
	created, err := fixture.repository.CreatePendingInstallation(fixture.ctx, principal, command)
	if err != nil {
		t.Fatalf("CreatePendingInstallation() error = %v", err)
	}
	activated, err := fixture.repository.ActivateInstallation(fixture.ctx, principal, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: uuid.New(),
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest,
		Audit:         fixture.auditEvidence(discriminator + 1), ActivatedAt: fixture.now.Add(time.Duration(discriminator+1) * time.Minute),
	})
	if err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}
	return activated
}

func (f *agentControlRepositoryFixture) submitExperienceCandidateCommand(
	workspaceID uuid.UUID,
	publication Publication,
	discriminator byte,
) SubmitExperienceCandidateCommand {
	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		panic(err)
	}
	createdAt := f.now.Add(time.Duration(discriminator) * time.Minute)
	idempotency := f.idempotency(discriminator)
	idempotency.ExpiresAt = createdAt.Add(24 * time.Hour)
	return SubmitExperienceCandidateCommand{
		CandidateID: uuid.New(), WorkspaceID: workspaceID, DefinitionID: publication.Definition.ID,
		SourceVersionID: publication.Version.ID, SkillName: canonical.Bundle.SkillName,
		Canonical: canonical, DLPVersion: ExperienceCandidateDLPVersion,
		Idempotency: idempotency, Audit: f.auditEvidence(discriminator), CreatedAt: createdAt,
	}
}

func (f *agentControlRepositoryFixture) reviewExperienceCandidateCommand(
	workspaceID uuid.UUID,
	candidateID uuid.UUID,
	decision ExperienceCandidateDecision,
	discriminator byte,
) ReviewExperienceCandidateCommand {
	reviewedAt := f.now.Add(time.Duration(discriminator) * time.Minute)
	idempotency := f.idempotency(discriminator)
	idempotency.ExpiresAt = reviewedAt.Add(24 * time.Hour)
	return ReviewExperienceCandidateCommand{
		ReviewID: uuid.New(), WorkspaceID: workspaceID, CandidateID: candidateID, Decision: decision,
		Idempotency: idempotency, Audit: f.auditEvidence(discriminator), ReviewedAt: reviewedAt,
	}
}

func seedAgentWorkspaceWithMembers(
	t *testing.T,
	fixture *agentControlRepositoryFixture,
	owner Principal,
	admin Principal,
	members ...Principal,
) uuid.UUID {
	t.Helper()
	workspaceID := seedAgentWorkspace(t, fixture, owner, admin, Principal{})
	for _, member := range members {
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
			VALUES ($1, $2, 'member', 1, $3, $3)
		`, workspaceID, member.UserID, fixture.now); err != nil {
			t.Fatalf("insert Workspace Member: %v", err)
		}
	}
	return workspaceID
}
