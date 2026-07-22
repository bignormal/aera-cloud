package agentcontrol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOfficialBucketIsStableAndBounded(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	releaseID, userID := uuid.New(), uuid.New()
	first := officialBucket(key, officialBucketAlgorithmV1, releaseID, userID)
	second := officialBucket(key, officialBucketAlgorithmV1, releaseID, userID)
	if first != second || first < 0 || first >= 10000 {
		t.Fatalf("bucket = %d/%d", first, second)
	}
}

func TestOfficialEligibilityPercentageExpansionIsMonotonic(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	releaseID, userID := uuid.New(), uuid.New()
	bucket := officialBucket(key, officialBucketAlgorithmV1, releaseID, userID)
	thresholds := []int{100, 1000, 5000, 10000}
	seenEligible := false
	for _, threshold := range thresholds {
		eligible := bucket < threshold
		if seenEligible && !eligible {
			t.Fatalf("bucket %d left cohort at threshold %d", bucket, threshold)
		}
		seenEligible = seenEligible || eligible
	}
}

func TestOfficialReleaseServiceRequiresOperatorAndCanonicalizesAudience(t *testing.T) {
	fixture := newPlatformReleaseServiceFixture(t)
	releaseID, versionID := uuid.New(), uuid.New()
	firstUser, secondUser := uuid.New(), uuid.New()
	command := ActivateOfficialReleaseCommand{
		ReleaseID: releaseID, VersionID: versionID, ExpectedHeadRevision: 1,
		RolloutBasisPoints: 1000, MinimumDesktopVersion: "1.2.3",
		AllowlistedUserIDs: []uuid.UUID{secondUser, firstUser, secondUser},
		Evidence: PlatformOperationEvidence{
			ReasonCode: "approved_rollout", TicketReference: "OPS-42", IdempotencyKey: "activate-v1",
		},
	}
	operator := PlatformAdminActor{AdminID: uuid.New(), Role: "operator", RequestID: "official-operator"}
	if _, err := fixture.service.ActivateOfficialRelease(context.Background(), fixture.developer, command); !errors.Is(err, ErrPlatformForbidden) {
		t.Fatalf("Developer activation error = %v", err)
	}
	if _, err := fixture.service.ActivateOfficialRelease(context.Background(), operator, command); err != nil {
		t.Fatalf("ActivateOfficialRelease() error = %v", err)
	}
	got := fixture.repository.lastMutation
	if got.Action != OfficialReleaseActionActivate || got.ReleaseID != releaseID || got.VersionID != versionID ||
		got.RolloutBasisPoints != 1000 || got.MinimumDesktopVersion != "v1.2.3" || len(got.AllowlistedUserIDs) != 2 ||
		got.AllowlistedUserIDs[0].String() >= got.AllowlistedUserIDs[1].String() {
		t.Fatalf("canonical release mutation = %+v", got)
	}
}

func TestOfficialRollbackRequiresSuperAdminExecutionRole(t *testing.T) {
	fixture := newPlatformReleaseServiceFixture(t)
	request := RollbackOfficialReleaseCommand{
		ReleaseID: uuid.New(), TargetVersionID: uuid.New(), TargetReleaseRevisionID: uuid.New(),
		ExpectedHeadRevision: 3, ApprovalID: uuid.New(),
		Evidence: PlatformOperationEvidence{ReasonCode: "rollback_approved", IdempotencyKey: "rollback-approved"},
	}
	operator := PlatformAdminActor{AdminID: uuid.New(), Role: "operator", RequestID: "rollback-requester"}
	if _, err := fixture.service.RollbackOfficialRelease(context.Background(), operator, request); !errors.Is(err, ErrPlatformForbidden) {
		t.Fatalf("Operator rollback execution error = %v", err)
	}
	approver := PlatformAdminActor{AdminID: uuid.New(), Role: "super_admin", RequestID: "rollback-approver"}
	if _, err := fixture.service.RollbackOfficialRelease(context.Background(), approver, request); err != nil {
		t.Fatalf("Super Admin rollback execution error = %v", err)
	}
}

func TestOfficialEligibilityHonorsPauseSemverPolicyAllowlistAndBucket(t *testing.T) {
	fixture := newPlatformReleaseServiceFixture(t)
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New()}
	releaseID := uuid.New()
	contextValue := OfficialEligibilityContext{
		Channel: OfficialChannelStable, DesktopVersion: "2.0.0",
		Selector: OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: principal.PersonalSpaceID},
	}
	base := OfficialEligibilityRecord{
		AccountDeviceActive: true, PlatformActive: true, ChannelEntitled: true,
		ContextAuthorized: true, ContextPolicyAllowed: true,
		Release: OfficialRelease{ID: releaseID, PlatformID: fixture.platformID, DefinitionID: uuid.New(), Channel: OfficialChannelStable, HeadRevision: 2},
		Revision: OfficialReleaseRevision{
			ID: uuid.New(), ReleaseID: releaseID, RevisionNumber: 2, AgentVersionID: uuid.New(),
			State: OfficialReleaseStateActive, RolloutBasisPoints: 10000,
			MinimumDesktopVersion: "v1.5.0", BucketAlgorithmVersion: officialBucketAlgorithmV1,
			RolloutKeyID: "rollout-v1",
		},
	}
	base.Release.CurrentRevisionID = base.Revision.ID
	fixture.repository.eligibility = func(context.Context, uuid.UUID, uuid.UUID, Principal, OfficialEligibilityContext) (OfficialEligibilityRecord, bool, error) {
		return base, true, nil
	}
	if target, err := fixture.service.ResolveOfficialRelease(context.Background(), principal, releaseID, contextValue); err != nil ||
		target.ReleaseRevisionID != base.Revision.ID || target.VersionID != base.Revision.AgentVersionID {
		t.Fatalf("ResolveOfficialRelease() = %+v, %v", target, err)
	}

	paused := base
	paused.Revision.State = OfficialReleaseStatePaused
	fixture.repository.eligibility = fixedOfficialEligibility(paused)
	if _, err := fixture.service.ResolveOfficialRelease(context.Background(), principal, releaseID, contextValue); !errors.Is(err, ErrOfficialReleasePaused) {
		t.Fatalf("paused eligibility error = %v", err)
	}

	minimum := base
	minimum.Revision.MinimumDesktopVersion = "v3.0.0"
	fixture.repository.eligibility = fixedOfficialEligibility(minimum)
	if _, err := fixture.service.ResolveOfficialRelease(context.Background(), principal, releaseID, contextValue); !errors.Is(err, ErrOfficialClientVersionUnsupported) {
		t.Fatalf("minimum-version error = %v", err)
	}

	blocked := base
	blocked.ContextPolicyAllowed = false
	fixture.repository.eligibility = fixedOfficialEligibility(blocked)
	if _, err := fixture.service.ResolveOfficialRelease(context.Background(), principal, releaseID, contextValue); !errors.Is(err, ErrOfficialInstallationPolicyBlocked) {
		t.Fatalf("context-policy error = %v", err)
	}

	allowlisted := base
	allowlisted.UserAllowlisted = true
	allowlisted.Revision.RolloutBasisPoints = 0
	fixture.repository.eligibility = fixedOfficialEligibility(allowlisted)
	if _, err := fixture.service.ResolveOfficialRelease(context.Background(), principal, releaseID, contextValue); err != nil {
		t.Fatalf("allowlisted eligibility error = %v", err)
	}

	outsideBucket := base
	outsideBucket.Revision.RolloutBasisPoints = 0
	fixture.repository.eligibility = fixedOfficialEligibility(outsideBucket)
	if _, err := fixture.service.ResolveOfficialRelease(context.Background(), principal, releaseID, contextValue); !errors.Is(err, ErrOfficialAgentNotEligible) {
		t.Fatalf("outside-bucket eligibility error = %v", err)
	}

	unknownKey := base
	unknownKey.Revision.RolloutKeyID = "retired-unknown"
	fixture.repository.eligibility = fixedOfficialEligibility(unknownKey)
	if _, err := fixture.service.ResolveOfficialRelease(context.Background(), principal, releaseID, contextValue); !errors.Is(err, ErrCloudUnavailable) {
		t.Fatalf("unknown-key eligibility error = %v", err)
	}
}

func TestOfficialReleaseRepositoryAppendsTransitionsAndRollbackChain(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	principal := fixture.principal(t, 0x70)
	_, v1, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0x71)

	activated, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, OfficialReleaseMutationRepositoryCommand{
		RevisionID: uuid.New(), PlatformID: fixture.platformID, ReleaseID: release.ID,
		ExpectedHeadRevision: release.HeadRevision, Actor: PlatformAdminActor{AdminID: uuid.New(), Role: "operator", RequestID: "activate-v1"},
		Action: OfficialReleaseActionActivate, VersionID: v1, RolloutBasisPoints: 1000,
		MinimumDesktopVersion: "v1.0.0", RolloutKeyID: "rollout-v1",
		AllowlistedUserIDs: []uuid.UUID{principal.UserID}, ReasonCode: "approved_rollout",
		Idempotency: fixture.idempotency(0x72), Audit: fixture.auditEvidence(0x72), ChangedAt: fixture.now.Add(2 * time.Minute),
	})
	if err != nil || activated.HeadRevision != release.HeadRevision+1 || activated.CurrentRevision.State != OfficialReleaseStateActive {
		t.Fatalf("activate = %+v, %v", activated, err)
	}
	if len(activated.CurrentRevision.AllowlistedUserIDs) != 1 || activated.CurrentRevision.AllowlistedUserIDs[0] != principal.UserID {
		t.Fatalf("activated audience = %+v", activated.CurrentRevision.AllowlistedUserIDs)
	}

	paused, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, OfficialReleaseMutationRepositoryCommand{
		RevisionID: uuid.New(), PlatformID: fixture.platformID, ReleaseID: release.ID,
		ExpectedHeadRevision: activated.HeadRevision, Actor: PlatformAdminActor{AdminID: uuid.New(), Role: "operator", RequestID: "pause-v1"},
		Action: OfficialReleaseActionPause, ReasonCode: "incident_pause",
		Idempotency: fixture.idempotency(0x73), Audit: fixture.auditEvidence(0x73), ChangedAt: fixture.now.Add(3 * time.Minute),
	})
	if err != nil || paused.CurrentRevision.State != OfficialReleaseStatePaused ||
		paused.CurrentRevision.AgentVersionID != v1 || len(paused.CurrentRevision.AllowlistedUserIDs) != 1 {
		t.Fatalf("pause = %+v, %v", paused, err)
	}

	resumed, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, OfficialReleaseMutationRepositoryCommand{
		RevisionID: uuid.New(), PlatformID: fixture.platformID, ReleaseID: release.ID,
		ExpectedHeadRevision: paused.HeadRevision, Actor: PlatformAdminActor{AdminID: uuid.New(), Role: "operator", RequestID: "resume-v1"},
		Action: OfficialReleaseActionResume, ReasonCode: "incident_resolved",
		Idempotency: fixture.idempotency(0x74), Audit: fixture.auditEvidence(0x74), ChangedAt: fixture.now.Add(4 * time.Minute),
	})
	if err != nil || resumed.CurrentRevision.State != OfficialReleaseStateActive {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}

	v2 := fixture.publishNextOfficialVersion(t, release.DefinitionID, v1, 0x75)
	v2Active, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, OfficialReleaseMutationRepositoryCommand{
		RevisionID: uuid.New(), PlatformID: fixture.platformID, ReleaseID: release.ID,
		ExpectedHeadRevision: resumed.HeadRevision, Actor: PlatformAdminActor{AdminID: uuid.New(), Role: "operator", RequestID: "activate-v2"},
		Action: OfficialReleaseActionActivate, VersionID: v2, RolloutBasisPoints: 5000,
		MinimumDesktopVersion: "v1.1.0", RolloutKeyID: "rollout-v1", ReasonCode: "approved_rollout",
		Idempotency: fixture.idempotency(0x76), Audit: fixture.auditEvidence(0x76), ChangedAt: fixture.now.Add(6 * time.Minute),
	})
	if err != nil || v2Active.CurrentRevision.AgentVersionID != v2 {
		t.Fatalf("activate v2 = %+v, %v", v2Active, err)
	}

	rolledBack, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, OfficialReleaseMutationRepositoryCommand{
		RevisionID: uuid.New(), PlatformID: fixture.platformID, ReleaseID: release.ID,
		ExpectedHeadRevision: v2Active.HeadRevision, Actor: PlatformAdminActor{AdminID: uuid.New(), Role: "super_admin", RequestID: "rollback-v1"},
		Action: OfficialReleaseActionRollback, VersionID: v1,
		TargetReleaseRevisionID: activated.CurrentRevision.ID, ApprovalID: uuid.New(), ReasonCode: "rollback_approved",
		Idempotency: fixture.idempotency(0x77), Audit: fixture.auditEvidence(0x77), ChangedAt: fixture.now.Add(7 * time.Minute),
	})
	if err != nil || rolledBack.CurrentRevision.AgentVersionID != v1 ||
		rolledBack.CurrentRevision.RollbackTargetRevisionID != activated.CurrentRevision.ID ||
		rolledBack.CurrentRevision.State != v2Active.CurrentRevision.State {
		t.Fatalf("rollback = %+v, %v", rolledBack, err)
	}
}

func TestOfficialReleaseRepositoryConcurrentHeadUpdateHasOneWinner(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	_, versionID, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0x81)
	commands := []OfficialReleaseMutationRepositoryCommand{
		fixture.releaseMutation(release, versionID, 0x82),
		fixture.releaseMutation(release, versionID, 0x83),
	}
	errorsByCall := make([]error, len(commands))
	var wait sync.WaitGroup
	for index := range commands {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, errorsByCall[index] = fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, commands[index])
		}(index)
	}
	wait.Wait()
	successes, conflicts := 0, 0
	for _, err := range errorsByCall {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrOfficialReleaseRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent mutation error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes/conflicts = %d/%d (%v)", successes, conflicts, errorsByCall)
	}
}

func TestOfficialReleaseRepositoryRejectsForeignVersionAndAuditFailureAtomically(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	_, ownVersionID, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0x91)
	_, foreignVersionID, _ := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0x96)

	foreign := fixture.releaseMutation(release, foreignVersionID, 0x9b)
	if _, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, foreign); !errors.Is(err, ErrOfficialRolloutInvalid) {
		t.Fatalf("foreign version error = %v", err)
	}
	unchanged, found, err := fixture.repository.GetOfficialRelease(fixture.ctx, fixture.platformID, release.ID)
	if err != nil || !found || unchanged.HeadRevision != release.HeadRevision {
		t.Fatalf("release after foreign version = %+v, found=%v, error=%v", unchanged, found, err)
	}

	var existingAuditID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT id FROM audit_events ORDER BY created_at LIMIT 1`).Scan(&existingAuditID); err != nil {
		t.Fatalf("read existing audit: %v", err)
	}
	auditFailure := fixture.releaseMutation(release, ownVersionID, 0x9c)
	auditFailure.Audit.EventID = existingAuditID
	if _, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, auditFailure); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("audit failure error = %v", err)
	}
	unchanged, found, err = fixture.repository.GetOfficialRelease(fixture.ctx, fixture.platformID, release.ID)
	if err != nil || !found || unchanged.HeadRevision != release.HeadRevision {
		t.Fatalf("release after audit failure = %+v, found=%v, error=%v", unchanged, found, err)
	}
	var revisionCount int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM official_release_revisions WHERE release_id = $1
	`, release.ID).Scan(&revisionCount); err != nil || revisionCount != 1 {
		t.Fatalf("revision count after rollback = %d, error=%v", revisionCount, err)
	}
}

func TestOfficialEligibilityRepositoryChecksAccountDeviceContextAndChannel(t *testing.T) {
	fixture := newPlatformRepositoryFixture(t)
	principal := fixture.principal(t, 0xa1)
	_, versionID, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0xa2)
	activation := fixture.releaseMutation(release, versionID, 0xa7)
	activation.RolloutBasisPoints = 10000
	active, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, activation)
	if err != nil {
		t.Fatalf("activate release: %v", err)
	}
	contextValue := OfficialEligibilityContext{
		Channel: OfficialChannelStable, DesktopVersion: "v1.0.0",
		Selector: OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: principal.PersonalSpaceID},
	}
	record, found, err := fixture.repository.GetOfficialEligibility(
		fixture.ctx, fixture.platformID, active.ID, principal, contextValue,
	)
	if err != nil || !found || !record.AccountDeviceActive || !record.PlatformActive ||
		!record.ChannelEntitled || !record.ContextAuthorized || !record.ContextPolicyAllowed {
		t.Fatalf("personal eligibility = %+v, found=%v, error=%v", record, found, err)
	}
	if record.Release.CurrentRevision.AllowlistedUserIDs != nil || record.Revision.AllowlistedUserIDs != nil {
		t.Fatalf("eligibility leaked audience: %+v", record)
	}

	wrongChannel := contextValue
	wrongChannel.Channel = OfficialChannelInternal
	record, found, err = fixture.repository.GetOfficialEligibility(
		fixture.ctx, fixture.platformID, active.ID, principal, wrongChannel,
	)
	if err != nil || !found || record.ChannelEntitled {
		t.Fatalf("wrong-channel eligibility = %+v, found=%v, error=%v", record, found, err)
	}

	workspaceContext := contextValue
	workspaceContext.Selector = OfficialProductSelector{Scope: OwnerScopeWorkspace, WorkspaceID: uuid.New()}
	record, found, err = fixture.repository.GetOfficialEligibility(
		fixture.ctx, fixture.platformID, active.ID, principal, workspaceContext,
	)
	if err != nil || !found || record.ContextAuthorized || record.ContextPolicyAllowed {
		t.Fatalf("foreign-workspace eligibility = %+v, found=%v, error=%v", record, found, err)
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `UPDATE devices SET status = 'inactive' WHERE id = $1`, principal.DeviceID); err != nil {
		t.Fatalf("disable eligibility device: %v", err)
	}
	record, found, err = fixture.repository.GetOfficialEligibility(
		fixture.ctx, fixture.platformID, active.ID, principal, contextValue,
	)
	if err != nil || !found || record.AccountDeviceActive {
		t.Fatalf("inactive-device eligibility = %+v, found=%v, error=%v", record, found, err)
	}
}

type platformReleaseServiceFixture struct {
	service    PlatformService
	repository *stubPlatformRepository
	platformID uuid.UUID
	developer  PlatformAdminActor
}

func newPlatformReleaseServiceFixture(t *testing.T) *platformReleaseServiceFixture {
	t.Helper()
	signer, _ := signingFixture(t)
	repository := &stubPlatformRepository{}
	platformID := uuid.New()
	service, err := NewPlatformService(PlatformServiceConfig{
		Repository: repository, Signer: signer, PlatformID: platformID,
		PlatformKey: "agentera_official", PlatformDisplayName: "AgentEra Official",
		RolloutKeyID: "rollout-v1",
		RolloutKeys:  map[string][]byte{"rollout-v1": []byte("0123456789abcdef0123456789abcdef")},
		Clock:        func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) },
		NewID:        uuid.New,
	})
	if err != nil {
		t.Fatalf("NewPlatformService() error = %v", err)
	}
	return &platformReleaseServiceFixture{
		service: service, repository: repository, platformID: platformID,
		developer: PlatformAdminActor{AdminID: uuid.New(), Role: "developer", RequestID: "official-developer"},
	}
}

func fixedOfficialEligibility(value OfficialEligibilityRecord) func(context.Context, uuid.UUID, uuid.UUID, Principal, OfficialEligibilityContext) (OfficialEligibilityRecord, bool, error) {
	return func(context.Context, uuid.UUID, uuid.UUID, Principal, OfficialEligibilityContext) (OfficialEligibilityRecord, bool, error) {
		return value, true, nil
	}
}

func (fixture *platformRepositoryFixture) publishInitialOfficialRelease(
	t *testing.T,
	channel OfficialChannel,
	discriminator byte,
) (PlatformAgentSubmission, uuid.UUID, OfficialRelease) {
	t.Helper()
	reservation := fixture.reserveDefinition(t, discriminator)
	draft := fixture.createInitialDraft(t, reservation.ID, discriminator+1)
	submission := fixture.submitDraft(t, draft, discriminator+2)
	command := fixture.approvalCommand(t, submission, fixture.superAdmin, discriminator+3)
	command.InitialReleases = []InitialOfficialRelease{{ReleaseID: uuid.New(), RevisionID: uuid.New(), Channel: channel}}
	approved, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, command)
	if err != nil {
		t.Fatalf("ReviewPlatformSubmission() error = %v", err)
	}
	var versionID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT id FROM agent_versions WHERE platform_submission_id = $1`, submission.ID).Scan(&versionID); err != nil {
		t.Fatalf("read platform version: %v", err)
	}
	release, found, err := fixture.repository.GetOfficialRelease(fixture.ctx, fixture.platformID, command.InitialReleases[0].ReleaseID)
	if err != nil || !found {
		t.Fatalf("GetOfficialRelease() = %+v, %v, found=%v", release, err, found)
	}
	return approved, versionID, release
}

func (fixture *platformRepositoryFixture) publishNextOfficialVersion(
	t *testing.T,
	definitionID uuid.UUID,
	baseVersionID uuid.UUID,
	discriminator byte,
) uuid.UUID {
	t.Helper()
	manifest, bundle := validManifestFixture()
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: definitionID, BaseVersionID: baseVersionID, Kind: PlatformDraftNext,
		DisplayName: "Official Research v2", Manifest: manifest, Bundle: bundle,
	})
	if err != nil {
		t.Fatalf("CanonicalizePlatformDraft(next) error = %v", err)
	}
	var draftID uuid.UUID
	var draftRevision int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT id, revision FROM platform_agent_drafts WHERE platform_id = $1 AND definition_id = $2
	`, fixture.platformID, definitionID).Scan(&draftID, &draftRevision); err != nil {
		t.Fatalf("read prior platform draft: %v", err)
	}
	draft, err := fixture.repository.UpdatePlatformDraft(fixture.ctx, UpdatePlatformDraftRepositoryCommand{
		DraftID: draftID, PlatformID: fixture.platformID, Actor: fixture.developer,
		ExpectedRevision: draftRevision, Kind: canonical.Package.Kind,
		BaseVersionID: canonical.Package.BaseVersionID, DisplayName: canonical.Package.DisplayName,
		IconMediaType: canonical.Package.IconMediaType, IconData: canonical.Package.IconData,
		Manifest: canonical.Package.Manifest, Bundle: canonical.Package.Bundle,
		Idempotency: fixture.idempotency(discriminator), Audit: fixture.auditEvidence(discriminator),
		UpdatedAt: fixture.now.Add(time.Duration(discriminator) * time.Second),
	})
	if err != nil {
		t.Fatalf("CreatePlatformDraft(next) error = %v", err)
	}
	submission := fixture.submitDraft(t, draft, discriminator+1)
	command := fixture.approvalCommand(t, submission, fixture.secondSuperAdmin, discriminator+2)
	command.InitialReleases = []InitialOfficialRelease{{ReleaseID: uuid.New(), RevisionID: uuid.New(), Channel: OfficialChannelStable}}
	if _, err := fixture.repository.ReviewPlatformSubmission(fixture.ctx, command); err != nil {
		t.Fatalf("ReviewPlatformSubmission(next) error = %v", err)
	}
	var versionID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT id FROM agent_versions WHERE platform_submission_id = $1`, submission.ID).Scan(&versionID); err != nil {
		t.Fatalf("read next platform version: %v", err)
	}
	return versionID
}

func (fixture *platformRepositoryFixture) releaseMutation(
	release OfficialRelease,
	versionID uuid.UUID,
	discriminator byte,
) OfficialReleaseMutationRepositoryCommand {
	return OfficialReleaseMutationRepositoryCommand{
		RevisionID: uuid.New(), PlatformID: fixture.platformID, ReleaseID: release.ID,
		ExpectedHeadRevision: release.HeadRevision,
		Actor:                PlatformAdminActor{AdminID: uuid.New(), Role: "operator", RequestID: "concurrent-release"},
		Action:               OfficialReleaseActionActivate, VersionID: versionID,
		RolloutBasisPoints: int(discriminator), MinimumDesktopVersion: "v1.0.0", RolloutKeyID: "rollout-v1",
		ReasonCode: "approved_rollout", Idempotency: fixture.idempotency(discriminator),
		Audit: fixture.auditEvidence(discriminator), ChangedAt: release.CreatedAt.Add(time.Duration(discriminator) * time.Second),
	}
}
