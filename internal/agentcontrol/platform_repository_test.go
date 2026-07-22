package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type failingOfficialCommitTx struct {
	pgx.Tx
}

func (failingOfficialCommitTx) Commit(context.Context) error {
	return errors.New("injected database commit failure")
}

func TestOfficialRepositoryCommitFailuresFailClosed(t *testing.T) {
	tx := failingOfficialCommitTx{}
	if _, err := commitPlatformPolicy(context.Background(), tx, PlatformPolicySnapshot{ID: uuid.New()}); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("platform policy commit error = %v", err)
	}
	if err := commitOfficialRelease(context.Background(), tx, OfficialRelease{ID: uuid.New()}); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("official release commit error = %v", err)
	}
}

func TestPlatformRepositoryPublicationCreatesImmutableVersionAndLeavesExistingReleaseHead(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	reservation := fixture.reserveDefinition(t, 0x11)
	draft := fixture.createInitialDraft(t, reservation.ID, 0x12)
	submission := fixture.submitDraft(t, draft, 0x13)

	selfReviewer := fixture.superAdmin
	selfReviewer.AdminID = fixture.developer.AdminID
	selfReview := fixture.approvalCommand(t, submission, selfReviewer, 0x14)
	if _, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, selfReview); !errors.Is(err, ErrOfficialSubmissionSelfReview) {
		t.Fatalf("self review error = %v", err)
	}
	fixture.assertPending(t, submission.ID)

	approved, firstVersionID := fixture.approve(t, submission, fixture.superAdmin, 0x15)
	if approved.Status != PlatformSubmissionApproved || approved.Review == nil ||
		approved.Review.ReviewerAdminID != fixture.superAdmin.AdminID {
		t.Fatalf("approved submission = %+v", approved)
	}
	var versionScope string
	var platformID, submissionID, policyID, publisherID uuid.UUID
	var versionNumber int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT owner_scope, platform_id, platform_submission_id, platform_policy_snapshot_id,
		       published_by_admin_id, version_number
		FROM agent_versions WHERE id = $1
	`, firstVersionID).Scan(&versionScope, &platformID, &submissionID, &policyID, &publisherID, &versionNumber); err != nil {
		t.Fatalf("read PLATFORM version: %v", err)
	}
	if versionScope != "PLATFORM" || platformID != fixture.platformID || submissionID != submission.ID ||
		policyID != fixture.policyID || publisherID != fixture.superAdmin.AdminID || versionNumber != 1 {
		t.Fatalf("PLATFORM version linkage = %s %s %s %s %s %d", versionScope, platformID, submissionID, policyID, publisherID, versionNumber)
	}

	var releaseCount, pausedCount int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*), count(*) FILTER (WHERE revision.state = 'paused' AND revision.rollout_basis_points = 0)
		FROM official_releases release
		JOIN official_release_revisions revision ON revision.id = release.current_release_revision_id
		WHERE release.platform_id = $1 AND release.definition_id = $2 AND revision.agent_version_id = $3
	`, fixture.platformID, reservation.ID, firstVersionID).Scan(&releaseCount, &pausedCount); err != nil {
		t.Fatalf("read initial releases: %v", err)
	}
	if releaseCount != 2 || pausedCount != 2 {
		t.Fatalf("initial release counts = %d/%d, want 2/2", releaseCount, pausedCount)
	}

	manifest, bundle := validManifestFixture()
	bundle.Assets[0].Content = "# Alpha v2\n"
	manifest.Assets[0].SHA256 = digestHex([]byte(bundle.Assets[0].Content))
	updated, err := fixture.repository.UpdatePlatformDraft(fixture.ctx, UpdatePlatformDraftRepositoryCommand{
		DraftID: draft.ID, PlatformID: fixture.platformID, Actor: fixture.developer,
		ExpectedRevision: draft.Revision, Kind: PlatformDraftNext, BaseVersionID: firstVersionID,
		DisplayName: "Official Research v2", Manifest: manifest, Bundle: bundle,
		Idempotency: fixture.idempotency(0x16), Audit: fixture.auditEvidence(0x16),
		UpdatedAt: fixture.now.Add(6 * time.Minute),
	})
	if err != nil {
		t.Fatalf("UpdatePlatformDraft(v2) error = %v", err)
	}
	secondSubmission := fixture.submitDraft(t, updated, 0x17)
	_, secondVersionID := fixture.approve(t, secondSubmission, fixture.secondSuperAdmin, 0x18)
	if secondVersionID == firstVersionID {
		t.Fatal("v2 approval reused v1 version ID")
	}

	var unchangedReleaseHeads int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*)
		FROM official_releases release
		JOIN official_release_revisions revision ON revision.id = release.current_release_revision_id
		WHERE release.platform_id = $1 AND release.definition_id = $2
		  AND release.head_revision = 1 AND revision.agent_version_id = $3
	`, fixture.platformID, reservation.ID, firstVersionID).Scan(&unchangedReleaseHeads); err != nil {
		t.Fatalf("read release heads after v2: %v", err)
	}
	if unchangedReleaseHeads != 2 {
		t.Fatalf("unchanged v1 release heads = %d, want 2", unchangedReleaseHeads)
	}
}

func TestPlatformRepositoryPersistsOfficialAdminOperationAtomically(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	definitionID, operationID := uuid.New(), uuid.New()
	operationDigest := sha256.Sum256(operationID[:])
	requestDigest := sha256.Sum256(definitionID[:])
	actor := fixture.developer
	actor.Operation = &PlatformAdminOperationProof{
		OperationID: operationID, Action: "official_definition_reserve",
		TargetType: "platform_definition", TargetID: definitionID,
		ExpectedRevision: 1, ServiceSubject: "aera-admin-e2e",
		IdempotencyKeyID: "v1", IdempotencyKeyHMAC: operationDigest[:],
		RequestFingerprint: requestDigest[:], ReasonCode: "definition_create",
	}
	command := ReservePlatformDefinitionRepositoryCommand{
		DefinitionID: definitionID, PlatformID: fixture.platformID, Actor: actor,
		DisplayName: "Official Atomic", Idempotency: fixture.idempotency(0x09),
		Audit: fixture.auditEvidence(0x09), CreatedAt: fixture.now.Add(9 * time.Second),
	}
	created, err := fixture.repository.ReservePlatformDefinition(fixture.ctx, command)
	if err != nil || created.ID != definitionID {
		t.Fatalf("ReservePlatformDefinition() = %+v / %v", created, err)
	}
	var action, targetType, status, actorRole, subject string
	var targetID uuid.UUID
	var expectedRevision, resultRevision int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT action, target_type, target_id, status, actor_admin_role, service_subject,
		       expected_revision, result_revision
		FROM admin_operations WHERE operation_id = $1
	`, operationID).Scan(&action, &targetType, &targetID, &status, &actorRole, &subject, &expectedRevision, &resultRevision); err != nil {
		t.Fatalf("read official admin operation: %v", err)
	}
	if action != "official_definition_reserve" || targetType != "platform_definition" || targetID != definitionID ||
		status != "succeeded" || actorRole != "developer" || subject != "aera-admin-e2e" ||
		expectedRevision != 1 || resultRevision != 1 {
		t.Fatalf("operation = %s %s %s %s %s %s %d %d", action, targetType, targetID, status, actorRole, subject, expectedRevision, resultRevision)
	}
	replayed, err := fixture.repository.ReservePlatformDefinition(fixture.ctx, command)
	if err != nil || replayed.ID != definitionID || !replayed.Replayed {
		t.Fatalf("official operation replay = %+v / %v", replayed, err)
	}
	var operationCount, auditCount int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM admin_operations WHERE operation_id = $1
	`, operationID).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM audit_events
		WHERE id = $1 AND reason_code = 'definition_create'
		  AND metadata->>'operation_id' = $2
		  AND metadata->>'action' = 'official_definition_reserve'
		  AND metadata->>'service_subject' = 'aera-admin-e2e'
	`, command.Audit.EventID, operationID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if operationCount != 1 || auditCount != 1 {
		t.Fatalf("replayed operation/audit counts = %d/%d, want 1/1", operationCount, auditCount)
	}

	badDefinitionID := uuid.New()
	badOperationID := uuid.New()
	badOperationDigest := sha256.Sum256(badOperationID[:])
	badRequestDigest := sha256.Sum256(badDefinitionID[:])
	badActor := fixture.developer
	badActor.Operation = &PlatformAdminOperationProof{
		OperationID: badOperationID, Action: "official_definition_reserve",
		TargetType: "platform_definition", TargetID: uuid.New(), ExpectedRevision: 1,
		ServiceSubject: "aera-admin-e2e", IdempotencyKeyID: "v1",
		IdempotencyKeyHMAC: badOperationDigest[:], RequestFingerprint: badRequestDigest[:],
		ReasonCode: "definition_create",
	}
	badCommand := command
	badCommand.DefinitionID, badCommand.Actor = badDefinitionID, badActor
	badCommand.Idempotency, badCommand.Audit = fixture.idempotency(0x0a), fixture.auditEvidence(0x0a)
	if _, err := fixture.repository.ReservePlatformDefinition(fixture.ctx, badCommand); !errors.Is(err, ErrInvalidRepositoryCommand) {
		t.Fatalf("mismatched operation proof error = %v", err)
	}
	var count int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM agent_definitions WHERE id = $1`, badDefinitionID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled back definition count = %d / %v", count, err)
	}
}

func TestPlatformRepositorySupersedesPendingAndEnforcesRevisionAndActorSeparation(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	reservation := fixture.reserveDefinition(t, 0x21)
	draft := fixture.createInitialDraft(t, reservation.ID, 0x22)
	first := fixture.submitDraft(t, draft, 0x23)
	second := fixture.submitDraft(t, draft, 0x24)

	firstStored, found, err := fixture.repository.GetPlatformSubmission(fixture.ctx, fixture.platformID, first.ID)
	if err != nil || !found || firstStored.Status != PlatformSubmissionSuperseded || firstStored.Revision != 2 {
		t.Fatalf("superseded submission = %+v found=%t error=%v", firstStored, found, err)
	}
	if second.Status != PlatformSubmissionPending {
		t.Fatalf("second submission = %+v", second)
	}

	stale := fixture.withdrawCommand(second, fixture.developer, 0x25)
	stale.ExpectedRevision++
	if _, err := fixture.repository.WithdrawPlatformSubmission(fixture.ctx, stale); !errors.Is(err, ErrOfficialSubmissionConflict) {
		t.Fatalf("stale withdrawal error = %v", err)
	}
	otherDeveloper := fixture.developer
	otherDeveloper.AdminID = uuid.New()
	if _, err := fixture.repository.WithdrawPlatformSubmission(
		fixture.ctx, fixture.withdrawCommand(second, otherDeveloper, 0x26),
	); !errors.Is(err, ErrPlatformForbidden) {
		t.Fatalf("other developer withdrawal error = %v", err)
	}
	withdrawn, err := fixture.repository.WithdrawPlatformSubmission(
		fixture.ctx, fixture.withdrawCommand(second, fixture.developer, 0x27),
	)
	if err != nil || withdrawn.Status != PlatformSubmissionWithdrawn || withdrawn.Revision != 2 {
		t.Fatalf("withdrawn = %+v error=%v", withdrawn, err)
	}
}

func TestPlatformRepositoryRejectionCreatesImmutableReviewWithoutPublication(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	reservation := fixture.reserveDefinition(t, 0x28)
	draft := fixture.createInitialDraft(t, reservation.ID, 0x29)
	submission := fixture.submitDraft(t, draft, 0x2a)
	command := ReviewPlatformSubmissionRepositoryCommand{
		ReviewID: uuid.New(), PlatformID: fixture.platformID, SubmissionID: submission.ID,
		ExpectedRevision: submission.Revision, Actor: fixture.superAdmin,
		Decision: PlatformReviewReject, ReasonCode: "policy_mismatch", SafeNote: "Use an approved model.",
		Idempotency: fixture.idempotency(0x2b), Audit: fixture.auditEvidence(0x2b),
		ReviewedAt: fixture.now.Add(43 * time.Second),
	}
	rejected, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, command)
	if err != nil || rejected.Status != PlatformSubmissionRejected || rejected.Review == nil ||
		rejected.Review.Decision != PlatformReviewReject || rejected.Review.ReasonCode != "policy_mismatch" {
		t.Fatalf("rejected = %+v error=%v", rejected, err)
	}
	var versions, releases int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM agent_versions WHERE platform_submission_id = $1`, submission.ID).Scan(&versions); err != nil {
		t.Fatalf("count rejected versions: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM official_releases WHERE definition_id = $1`, submission.DefinitionID).Scan(&releases); err != nil {
		t.Fatalf("count rejected releases: %v", err)
	}
	if versions != 0 || releases != 0 {
		t.Fatalf("rejected publication rows = versions %d releases %d", versions, releases)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `DELETE FROM platform_agent_reviews WHERE id = $1`, command.ReviewID); err == nil {
		t.Fatal("immutable PLATFORM review delete succeeded")
	}
}

func TestPlatformPublicationFailuresRollbackReviewVersionReleaseAndAudit(t *testing.T) {
	t.Run("version builder failure", func(t *testing.T) {
		fixture := newPlatformRepositoryFixture(t)
		reservation := fixture.reserveDefinition(t, 0x31)
		draft := fixture.createInitialDraft(t, reservation.ID, 0x32)
		submission := fixture.submitDraft(t, draft, 0x33)
		command := fixture.approvalCommand(t, submission, fixture.superAdmin, 0x34)
		builderError := errors.New("signer unavailable")
		command.BuildVersion = func(CanonicalPlatformDraft, int64) (VersionMaterial, error) {
			return VersionMaterial{}, builderError
		}
		if _, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, command); !errors.Is(err, builderError) {
			t.Fatalf("builder failure error = %v", err)
		}
		fixture.assertNoPublication(t, submission)
	})

	t.Run("audit failure", func(t *testing.T) {
		fixture := newPlatformRepositoryFixture(t)
		reservation := fixture.reserveDefinition(t, 0x41)
		draft := fixture.createInitialDraft(t, reservation.ID, 0x42)
		submission := fixture.submitDraft(t, draft, 0x43)
		command := fixture.approvalCommand(t, submission, fixture.superAdmin, 0x44)
		command.Audit.EventID = fixture.lastAuditID
		if _, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, command); !errors.Is(err, ErrServiceUnavailable) {
			t.Fatalf("audit failure error = %v", err)
		}
		fixture.assertNoPublication(t, submission)
	})

	t.Run("version integrity failure", func(t *testing.T) {
		fixture := newPlatformRepositoryFixture(t)
		reservation := fixture.reserveDefinition(t, 0x45)
		draft := fixture.createInitialDraft(t, reservation.ID, 0x46)
		submission := fixture.submitDraft(t, draft, 0x47)
		command := fixture.approvalCommand(t, submission, fixture.superAdmin, 0x48)
		originalBuilder := command.BuildVersion
		command.BuildVersion = func(canonical CanonicalPlatformDraft, versionNumber int64) (VersionMaterial, error) {
			material, err := originalBuilder(canonical, versionNumber)
			if err == nil {
				material.Bundle = []byte(`{"assets":[]}`)
			}
			return material, err
		}
		if _, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, command); !errors.Is(err, ErrOfficialVersionIntegrityFailed) {
			t.Fatalf("integrity failure error = %v", err)
		}
		fixture.assertNoPublication(t, submission)
	})
}

func TestPlatformRepositoryBootstrapIsIdempotentAndRejectsConfiguredIdentityDrift(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	first, err := fixture.repository.EnsurePlatform(fixture.ctx, fixture.ensureCommand(0x51))
	if err != nil {
		t.Fatalf("EnsurePlatform(replay) error = %v", err)
	}
	if first.ID != fixture.policyID || first.Version != 1 {
		t.Fatalf("replayed policy = %+v", first)
	}
	var platformCount, policyCount int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM platforms WHERE id = $1`, fixture.platformID).Scan(&platformCount); err != nil {
		t.Fatalf("count platform: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM platform_agent_policy_snapshots WHERE platform_id = $1`, fixture.platformID).Scan(&policyCount); err != nil {
		t.Fatalf("count policy: %v", err)
	}
	if platformCount != 1 || policyCount != 1 {
		t.Fatalf("bootstrap counts = platform %d policy %d", platformCount, policyCount)
	}
	drift := fixture.ensureCommand(0x52)
	drift.PlatformDisplayName = "Other Platform"
	if _, err := fixture.repository.EnsurePlatform(fixture.ctx, drift); !errors.Is(err, ErrInvalidRepositoryCommand) {
		t.Fatalf("identity drift error = %v", err)
	}
}

type platformRepositoryFixture struct {
	*agentControlRepositoryFixture
	platformID       uuid.UUID
	policyID         uuid.UUID
	developer        PlatformAdminActor
	superAdmin       PlatformAdminActor
	secondSuperAdmin PlatformAdminActor
	lastAuditID      uuid.UUID
}

func newPlatformRepositoryFixture(t *testing.T) *platformRepositoryFixture {
	t.Helper()
	base := newAgentControlRepositoryFixture(t)
	if _, err := base.postgres.Exec(base.ctx, `TRUNCATE platforms CASCADE`); err != nil {
		t.Fatalf("truncate PLATFORM fixture: %v", err)
	}
	fixture := &platformRepositoryFixture{
		agentControlRepositoryFixture: base,
		platformID:                    uuid.New(), policyID: uuid.New(),
		developer:        PlatformAdminActor{AdminID: uuid.New(), Role: "developer", RequestID: "platform-developer"},
		superAdmin:       PlatformAdminActor{AdminID: uuid.New(), Role: "super_admin", RequestID: "platform-super-admin"},
		secondSuperAdmin: PlatformAdminActor{AdminID: uuid.New(), Role: "super_admin", RequestID: "platform-super-admin-2"},
	}
	policy, err := fixture.repository.EnsurePlatform(fixture.ctx, fixture.ensureCommand(0x01))
	if err != nil {
		t.Fatalf("EnsurePlatform() error = %v", err)
	}
	fixture.policyID = policy.ID
	return fixture
}

func (fixture *platformRepositoryFixture) ensureCommand(discriminator byte) EnsurePlatformCommand {
	return EnsurePlatformCommand{
		PlatformID: fixture.platformID, PlatformKey: "agentera_official",
		PlatformDisplayName: "AgentEra Official", EnsuredAt: fixture.now,
		BuildPolicy: func(version int64) (PlatformPolicyMaterial, error) {
			canonical := []byte(`{"schema_version":1,"manifest_schema_version":1,"dlp_version":"agent-publication-dlp-v1","model_constraint_mode":"manifest_allowlist","tool_constraint_mode":"manifest_allowlist","runtime_compatibility_mode":"strict_semver","dependency_mode":"immutable_versions","permitted_channels":["internal","stable"],"maximum_asset_count":128,"maximum_asset_bytes":262144,"maximum_bundle_bytes":2097152,"maximum_manifest_bytes":262144,"maximum_icon_bytes":524288,"maximum_rollout_basis_points":10000}`)
			digest := sha256.Sum256(canonical)
			return PlatformPolicyMaterial{
				ID: fixture.policyID, Version: version, CanonicalPolicy: canonical,
				PolicyDigest: digest, SigningKeyID: "agent-control-v1",
				Signature: bytes.Repeat([]byte{discriminator}, 64),
			}, nil
		},
	}
}

func (fixture *platformRepositoryFixture) reserveDefinition(t *testing.T, discriminator byte) PlatformDefinitionReservation {
	t.Helper()
	command := ReservePlatformDefinitionRepositoryCommand{
		DefinitionID: uuid.New(), PlatformID: fixture.platformID, Actor: fixture.developer,
		DisplayName: "Official Research", Idempotency: fixture.idempotency(discriminator),
		Audit: fixture.auditEvidence(discriminator), CreatedAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	}
	fixture.lastAuditID = command.Audit.EventID
	value, err := fixture.repository.ReservePlatformDefinition(fixture.ctx, command)
	if err != nil {
		t.Fatalf("ReservePlatformDefinition() error = %v", err)
	}
	return value
}

func (fixture *platformRepositoryFixture) createInitialDraft(t *testing.T, definitionID uuid.UUID, discriminator byte) PlatformAgentDraft {
	t.Helper()
	manifest, bundle := validManifestFixture()
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: definitionID, Kind: PlatformDraftInitial, DisplayName: "Official Research",
		Manifest: manifest, Bundle: bundle,
	})
	if err != nil {
		t.Fatalf("CanonicalizePlatformDraft() error = %v", err)
	}
	command := CreatePlatformDraftRepositoryCommand{
		DraftID: uuid.New(), PlatformID: fixture.platformID, Actor: fixture.developer,
		Canonical: canonical, Idempotency: fixture.idempotency(discriminator),
		Audit: fixture.auditEvidence(discriminator), CreatedAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	}
	fixture.lastAuditID = command.Audit.EventID
	value, err := fixture.repository.CreatePlatformDraft(fixture.ctx, command)
	if err != nil {
		t.Fatalf("CreatePlatformDraft() error = %v", err)
	}
	return value
}

func (fixture *platformRepositoryFixture) submitDraft(t *testing.T, draft PlatformAgentDraft, discriminator byte) PlatformAgentSubmission {
	t.Helper()
	command := SubmitPlatformDraftRepositoryCommand{
		SubmissionID: uuid.New(), PlatformID: fixture.platformID, DraftID: draft.ID,
		ExpectedRevision: draft.Revision, Actor: fixture.developer,
		Idempotency: fixture.idempotency(discriminator), Audit: fixture.auditEvidence(discriminator),
		SubmittedAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	}
	fixture.lastAuditID = command.Audit.EventID
	value, err := fixture.repository.SubmitPlatformDraft(fixture.ctx, command)
	if err != nil {
		t.Fatalf("SubmitPlatformDraft() error = %v", err)
	}
	return value
}

func (fixture *platformRepositoryFixture) approvalCommand(
	t *testing.T,
	submission PlatformAgentSubmission,
	actor PlatformAdminActor,
	discriminator byte,
) ReviewPlatformSubmissionRepositoryCommand {
	t.Helper()
	versionID := uuid.New()
	return ReviewPlatformSubmissionRepositoryCommand{
		ReviewID: uuid.New(), PlatformID: fixture.platformID, SubmissionID: submission.ID,
		ExpectedRevision: submission.Revision, Actor: actor, Decision: PlatformReviewApprove,
		InitialReleases: []InitialOfficialRelease{
			{ReleaseID: uuid.New(), RevisionID: uuid.New(), Channel: OfficialChannelInternal},
			{ReleaseID: uuid.New(), RevisionID: uuid.New(), Channel: OfficialChannelStable},
		},
		RolloutKeyID: "rollout-v1",
		BuildVersion: func(canonical CanonicalPlatformDraft, versionNumber int64) (VersionMaterial, error) {
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

func (fixture *platformRepositoryFixture) approve(
	t *testing.T,
	submission PlatformAgentSubmission,
	actor PlatformAdminActor,
	discriminator byte,
) (PlatformAgentSubmission, uuid.UUID) {
	t.Helper()
	command := fixture.approvalCommand(t, submission, actor, discriminator)
	value, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, command)
	if err != nil {
		t.Fatalf("ReviewPlatformSubmission() error = %v", err)
	}
	var versionID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT id FROM agent_versions WHERE platform_submission_id = $1
	`, submission.ID).Scan(&versionID); err != nil {
		t.Fatalf("read published version: %v", err)
	}
	return value, versionID
}

func (fixture *platformRepositoryFixture) withdrawCommand(
	submission PlatformAgentSubmission,
	actor PlatformAdminActor,
	discriminator byte,
) TerminalPlatformSubmissionRepositoryCommand {
	return TerminalPlatformSubmissionRepositoryCommand{
		PlatformID: fixture.platformID, SubmissionID: submission.ID,
		ExpectedRevision: submission.Revision, Actor: actor,
		Idempotency: fixture.idempotency(discriminator), Audit: fixture.auditEvidence(discriminator),
		TerminalAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	}
}

func (fixture *platformRepositoryFixture) assertPending(t *testing.T, submissionID uuid.UUID) {
	t.Helper()
	value, found, err := fixture.repository.GetPlatformSubmission(fixture.ctx, fixture.platformID, submissionID)
	if err != nil || !found || value.Status != PlatformSubmissionPending || value.Review != nil {
		t.Fatalf("pending submission = %+v found=%t error=%v", value, found, err)
	}
}

func (fixture *platformRepositoryFixture) assertNoPublication(t *testing.T, submission PlatformAgentSubmission) {
	t.Helper()
	fixture.assertPending(t, submission.ID)
	var reviews, versions, releases int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM platform_agent_reviews WHERE submission_id = $1`, submission.ID).Scan(&reviews); err != nil {
		t.Fatalf("count reviews: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM agent_versions WHERE platform_submission_id = $1`, submission.ID).Scan(&versions); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM official_releases WHERE definition_id = $1`, submission.DefinitionID).Scan(&releases); err != nil {
		t.Fatalf("count releases: %v", err)
	}
	if reviews != 0 || versions != 0 || releases != 0 {
		t.Fatalf("partial publication rows = reviews %d versions %d releases %d", reviews, versions, releases)
	}
}
