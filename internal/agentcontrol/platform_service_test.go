package agentcontrol

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlatformDraftRoleMatrix(t *testing.T) {
	tests := []struct {
		role    string
		action  platformAction
		allowed bool
	}{
		{role: "developer", action: platformActionRead, allowed: true},
		{role: "developer", action: platformActionDraftWrite, allowed: true},
		{role: "developer", action: platformActionReview, allowed: false},
		{role: "super_admin", action: platformActionRead, allowed: true},
		{role: "super_admin", action: platformActionReview, allowed: true},
		{role: "super_admin", action: platformActionDraftWrite, allowed: false},
		{role: "operator", action: platformActionReleaseWrite, allowed: true},
		{role: "operator", action: platformActionReview, allowed: false},
		{role: "auditor", action: platformActionRead, allowed: true},
		{role: "auditor", action: platformActionDraftWrite, allowed: false},
		{role: "support", action: platformActionRead, allowed: false},
		{role: "finance", action: platformActionRead, allowed: false},
	}
	for _, test := range tests {
		t.Run(test.role+"/"+string(test.action), func(t *testing.T) {
			if got := platformRoleAllowed(test.role, test.action); got != test.allowed {
				t.Fatalf("platformRoleAllowed(%q, %q) = %t, want %t", test.role, test.action, got, test.allowed)
			}
		})
	}
}

func TestPlatformDraftServiceCanonicalizesAndReturnsDetachedValues(t *testing.T) {
	fixture := newPlatformServiceFixture(t)
	manifest, bundle := validManifestFixture()
	definitionID := uuid.New()
	var captured CreatePlatformDraftRepositoryCommand
	fixture.repository.createDraft = func(_ context.Context, command CreatePlatformDraftRepositoryCommand) (PlatformAgentDraft, error) {
		captured = command
		return platformDraftFromCreate(command), nil
	}

	draft, err := fixture.service.CreateDraft(context.Background(), fixture.developer, CreatePlatformDraftCommand{
		DefinitionID: definitionID, Kind: PlatformDraftInitial, DisplayName: "Official Research",
		Manifest: manifest, Bundle: bundle, IdempotencyKey: "official-draft-create",
	})
	if err != nil {
		t.Fatalf("CreateDraft() error = %v", err)
	}
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	if captured.PlatformID != fixture.platformID || captured.Actor.AdminID != fixture.developer.AdminID ||
		captured.Canonical.ContentDigest != canonical.ContentDigest || captured.Canonical.Package.DisplayName != "Official Research" {
		t.Fatalf("CreateDraft() captured = %+v", captured)
	}

	draft.Bundle.Assets[0].Content = "mutated"
	if captured.Canonical.Package.Bundle.Assets[0].Content == "mutated" {
		t.Fatal("CreateDraft() returned repository aliases")
	}
}

func TestPlatformDraftServiceRejectsPrivateDataBeforeRepository(t *testing.T) {
	fixture := newPlatformServiceFixture(t)
	manifest, bundle := singleAssetFixture(
		"knowledge/private.md",
		[]byte("API_KEY=correct-horse-battery\nHERMES_HOME=/Users/alice/.hermes"),
	)
	called := false
	fixture.repository.createDraft = func(context.Context, CreatePlatformDraftRepositoryCommand) (PlatformAgentDraft, error) {
		called = true
		return PlatformAgentDraft{}, nil
	}

	_, err := fixture.service.CreateDraft(context.Background(), fixture.developer, CreatePlatformDraftCommand{
		DefinitionID: uuid.New(), Kind: PlatformDraftInitial, DisplayName: "Unsafe",
		Manifest: manifest, Bundle: bundle, IdempotencyKey: "official-draft-private",
	})
	var dlpError *PlatformPublicationDLPError
	if !errors.As(err, &dlpError) || len(dlpError.Findings) != 2 {
		t.Fatalf("CreateDraft() error = %#v, want two safe DLP findings", err)
	}
	if called {
		t.Fatal("CreateDraft() called repository after DLP rejection")
	}
}

func TestPlatformSubmissionServiceRequiresDeveloper(t *testing.T) {
	fixture := newPlatformServiceFixture(t)
	fixture.repository.submitDraft = func(_ context.Context, command SubmitPlatformDraftRepositoryCommand) (PlatformAgentSubmission, error) {
		return PlatformAgentSubmission{
			ID: command.SubmissionID, PlatformID: command.PlatformID, DraftID: command.DraftID,
			SubmittedByAdminID: command.Actor.AdminID, SubmittedByRole: command.Actor.Role,
			Status: PlatformSubmissionPending, Revision: 1,
		}, nil
	}
	request := SubmitPlatformDraftCommand{
		DraftID: uuid.New(), ExpectedRevision: 2, IdempotencyKey: "official-draft-submit",
	}
	if _, err := fixture.service.SubmitDraft(context.Background(), fixture.superAdmin, request); !errors.Is(err, ErrPlatformForbidden) {
		t.Fatalf("SubmitDraft(super_admin) error = %v", err)
	}
	result, err := fixture.service.SubmitDraft(context.Background(), fixture.developer, request)
	if err != nil || result.SubmittedByAdminID != fixture.developer.AdminID || result.Status != PlatformSubmissionPending {
		t.Fatalf("SubmitDraft(developer) = %+v error=%v", result, err)
	}
}

func TestPlatformReviewServiceSignsOnlyRepositoryApprovedCanonicalSubmission(t *testing.T) {
	fixture := newPlatformServiceFixture(t)
	manifest, bundle := validManifestFixture()
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: uuid.New(), Kind: PlatformDraftInitial, DisplayName: "Official Research",
		Manifest: manifest, Bundle: bundle,
	})
	if err != nil {
		t.Fatalf("CanonicalizePlatformDraft() error = %v", err)
	}
	var material VersionMaterial
	fixture.repository.reviewSubmission = func(_ context.Context, command ReviewPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error) {
		built, err := command.BuildVersion(canonical, 1)
		if err != nil {
			return PlatformAgentSubmission{}, err
		}
		material = built
		return PlatformAgentSubmission{
			ID: command.SubmissionID, PlatformID: command.PlatformID, DefinitionID: canonical.Package.DefinitionID,
			Status: PlatformSubmissionApproved, Revision: 2,
			Review: &PlatformAgentReview{ID: command.ReviewID, Decision: PlatformReviewApprove},
		}, nil
	}

	request := ReviewPlatformSubmissionCommand{
		SubmissionID: uuid.New(), ExpectedRevision: 1, Decision: PlatformReviewApprove,
		InitialChannels: []OfficialChannel{OfficialChannelStable, OfficialChannelStable, OfficialChannelInternal},
		IdempotencyKey:  "official-review-approve",
	}
	if _, err := fixture.service.ReviewSubmission(context.Background(), fixture.developer, request); !errors.Is(err, ErrPlatformForbidden) {
		t.Fatalf("ReviewSubmission(developer) error = %v", err)
	}
	approved, err := fixture.service.ReviewSubmission(context.Background(), fixture.superAdmin, request)
	if err != nil {
		t.Fatalf("ReviewSubmission(super_admin) error = %v", err)
	}
	if approved.Status != PlatformSubmissionApproved || material.VersionNumber != 1 || len(material.Signature) != 64 {
		t.Fatalf("approved = %+v material = %+v", approved, material)
	}
	if len(fixture.repository.lastInitialReleases) != 2 ||
		fixture.repository.lastInitialReleases[0].Channel != OfficialChannelInternal ||
		fixture.repository.lastInitialReleases[1].Channel != OfficialChannelStable {
		t.Fatalf("initial releases = %+v", fixture.repository.lastInitialReleases)
	}

	fixture.repository.reviewSubmission = func(_ context.Context, command ReviewPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error) {
		changed := canonical
		changed.ContentDigest = sha256.Sum256([]byte("changed"))
		_, err := command.BuildVersion(changed, 1)
		return PlatformAgentSubmission{}, err
	}
	if _, err := fixture.service.ReviewSubmission(context.Background(), fixture.superAdmin, withPlatformReviewKey(request, "official-review-digest")); !errors.Is(err, ErrOfficialVersionIntegrityFailed) {
		t.Fatalf("ReviewSubmission(digest mismatch) error = %v", err)
	}
}

func TestPlatformReviewServiceRejectsUnsafeOrIncompleteApproval(t *testing.T) {
	fixture := newPlatformServiceFixture(t)
	base := ReviewPlatformSubmissionCommand{
		SubmissionID: uuid.New(), ExpectedRevision: 1, Decision: PlatformReviewApprove,
		InitialChannels: []OfficialChannel{OfficialChannelStable}, IdempotencyKey: "official-review-valid",
	}
	for name, mutate := range map[string]func(*ReviewPlatformSubmissionCommand){
		"missing channel": func(value *ReviewPlatformSubmissionCommand) { value.InitialChannels = nil },
		"unknown channel": func(value *ReviewPlatformSubmissionCommand) { value.InitialChannels = []OfficialChannel{"beta"} },
		"approval reason": func(value *ReviewPlatformSubmissionCommand) { value.ReasonCode = "not_allowed" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := fixture.service.ReviewSubmission(context.Background(), fixture.superAdmin, request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ReviewSubmission() error = %v", err)
			}
		})
	}
}

func TestPlatformReviewServiceBuildVersionRechecksFrozenDLP(t *testing.T) {
	fixture := newPlatformServiceFixture(t)
	manifest, bundle := singleAssetFixture(
		"knowledge/private.md",
		[]byte("API_KEY=correct-horse-battery\nHERMES_HOME=/Users/alice/.hermes"),
	)
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: uuid.New(), Kind: PlatformDraftInitial, DisplayName: "Unsafe frozen submission",
		Manifest: manifest, Bundle: bundle,
	})
	if err != nil {
		t.Fatalf("CanonicalizePlatformDraft() error = %v", err)
	}
	fixture.repository.reviewSubmission = func(_ context.Context, command ReviewPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error) {
		_, err := command.BuildVersion(canonical, 1)
		return PlatformAgentSubmission{}, err
	}
	_, err = fixture.service.ReviewSubmission(context.Background(), fixture.superAdmin, ReviewPlatformSubmissionCommand{
		SubmissionID: uuid.New(), ExpectedRevision: 1, Decision: PlatformReviewApprove,
		InitialChannels: []OfficialChannel{OfficialChannelInternal},
		IdempotencyKey:  "official-review-frozen-dlp",
	})
	var dlpError *PlatformPublicationDLPError
	if !errors.As(err, &dlpError) || len(dlpError.Findings) != 2 {
		t.Fatalf("ReviewSubmission(frozen DLP) error = %#v", err)
	}
}

func TestPlatformReviewServiceRejectCommandCarriesNoRolloutAuthority(t *testing.T) {
	fixture := newPlatformServiceFixture(t)
	fixture.repository.reviewSubmission = func(_ context.Context, command ReviewPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error) {
		if command.BuildVersion != nil || command.RolloutKeyID != "" || len(command.InitialReleases) != 0 {
			t.Fatalf("reject command carried publication authority: %+v", command)
		}
		return PlatformAgentSubmission{
			ID: command.SubmissionID, PlatformID: command.PlatformID,
			Status: PlatformSubmissionRejected, Revision: 2,
			Review: &PlatformAgentReview{ID: command.ReviewID, Decision: PlatformReviewReject},
		}, nil
	}
	result, err := fixture.service.ReviewSubmission(context.Background(), fixture.superAdmin, ReviewPlatformSubmissionCommand{
		SubmissionID: uuid.New(), ExpectedRevision: 1, Decision: PlatformReviewReject,
		ReasonCode: "policy_mismatch", SafeNote: "Use an approved model.",
		IdempotencyKey: "official-review-reject",
	})
	if err != nil || result.Status != PlatformSubmissionRejected {
		t.Fatalf("ReviewSubmission(reject) = %+v error=%v", result, err)
	}
}

func withPlatformReviewKey(
	request ReviewPlatformSubmissionCommand,
	key string,
) ReviewPlatformSubmissionCommand {
	request.IdempotencyKey = key
	return request
}

type platformServiceFixture struct {
	service    PlatformService
	repository *stubPlatformRepository
	platformID uuid.UUID
	developer  PlatformAdminActor
	superAdmin PlatformAdminActor
	now        time.Time
}

func newPlatformServiceFixture(t *testing.T) *platformServiceFixture {
	t.Helper()
	signer, _ := signingFixture(t)
	repository := &stubPlatformRepository{}
	platformID := uuid.New()
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	counter := 0
	service, err := NewPlatformService(PlatformServiceConfig{
		Repository:          repository,
		Signer:              signer,
		PlatformID:          platformID,
		PlatformKey:         "agentera_official",
		PlatformDisplayName: "AgentEra Official",
		RolloutKeyID:        "rollout-v1",
		Clock:               func() time.Time { return now },
		NewID: func() uuid.UUID {
			counter++
			return uuid.NewSHA1(uuid.NameSpaceOID, []byte("platform-"+strconv.Itoa(counter)))
		},
	})
	if err != nil {
		t.Fatalf("NewPlatformService() error = %v", err)
	}
	return &platformServiceFixture{
		service: service, repository: repository, platformID: platformID, now: now,
		developer:  PlatformAdminActor{AdminID: uuid.New(), Role: "developer", RequestID: "request-developer"},
		superAdmin: PlatformAdminActor{AdminID: uuid.New(), Role: "super_admin", RequestID: "request-super-admin"},
	}
}

type stubPlatformRepository struct {
	createDraft         func(context.Context, CreatePlatformDraftRepositoryCommand) (PlatformAgentDraft, error)
	submitDraft         func(context.Context, SubmitPlatformDraftRepositoryCommand) (PlatformAgentSubmission, error)
	reviewSubmission    func(context.Context, ReviewPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error)
	appendRelease       func(context.Context, OfficialReleaseMutationRepositoryCommand) (OfficialRelease, error)
	eligibility         func(context.Context, uuid.UUID, uuid.UUID, Principal, OfficialEligibilityContext) (OfficialEligibilityRecord, bool, error)
	lastMutation        OfficialReleaseMutationRepositoryCommand
	lastInitialReleases []InitialOfficialRelease
}

func (s *stubPlatformRepository) EnsurePlatform(context.Context, EnsurePlatformCommand) (PlatformPolicySnapshot, error) {
	return PlatformPolicySnapshot{}, errors.New("unexpected EnsurePlatform call")
}

func (s *stubPlatformRepository) ReservePlatformDefinition(context.Context, ReservePlatformDefinitionRepositoryCommand) (PlatformDefinitionReservation, error) {
	return PlatformDefinitionReservation{}, errors.New("unexpected ReservePlatformDefinition call")
}

func (s *stubPlatformRepository) CreatePlatformDraft(ctx context.Context, command CreatePlatformDraftRepositoryCommand) (PlatformAgentDraft, error) {
	if s.createDraft == nil {
		return PlatformAgentDraft{}, errors.New("unexpected CreatePlatformDraft call")
	}
	return s.createDraft(ctx, command)
}

func (s *stubPlatformRepository) UpdatePlatformDraft(context.Context, UpdatePlatformDraftRepositoryCommand) (PlatformAgentDraft, error) {
	return PlatformAgentDraft{}, errors.New("unexpected UpdatePlatformDraft call")
}

func (s *stubPlatformRepository) GetPlatformDraft(context.Context, uuid.UUID, uuid.UUID) (PlatformAgentDraft, bool, error) {
	return PlatformAgentDraft{}, false, errors.New("unexpected GetPlatformDraft call")
}

func (s *stubPlatformRepository) SubmitPlatformDraft(ctx context.Context, command SubmitPlatformDraftRepositoryCommand) (PlatformAgentSubmission, error) {
	if s.submitDraft == nil {
		return PlatformAgentSubmission{}, errors.New("unexpected SubmitPlatformDraft call")
	}
	return s.submitDraft(ctx, command)
}

func (s *stubPlatformRepository) WithdrawPlatformSubmission(context.Context, TerminalPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error) {
	return PlatformAgentSubmission{}, errors.New("unexpected WithdrawPlatformSubmission call")
}

func (s *stubPlatformRepository) ReviewPlatformSubmission(ctx context.Context, command ReviewPlatformSubmissionRepositoryCommand) (PlatformAgentSubmission, error) {
	s.lastInitialReleases = append([]InitialOfficialRelease(nil), command.InitialReleases...)
	if s.reviewSubmission == nil {
		return PlatformAgentSubmission{}, errors.New("unexpected ReviewPlatformSubmission call")
	}
	return s.reviewSubmission(ctx, command)
}

func (s *stubPlatformRepository) ListPlatformDefinitions(context.Context, uuid.UUID, PageRequest) (PlatformDefinitionPage, error) {
	return PlatformDefinitionPage{}, errors.New("unexpected ListPlatformDefinitions call")
}

func (s *stubPlatformRepository) GetPlatformDefinition(context.Context, uuid.UUID, uuid.UUID) (PlatformDefinitionDetail, bool, error) {
	return PlatformDefinitionDetail{}, false, errors.New("unexpected GetPlatformDefinition call")
}

func (s *stubPlatformRepository) ListPlatformDrafts(context.Context, uuid.UUID, PageRequest) (PlatformDraftPage, error) {
	return PlatformDraftPage{}, errors.New("unexpected ListPlatformDrafts call")
}

func (s *stubPlatformRepository) ListPlatformSubmissions(context.Context, uuid.UUID, PlatformSubmissionFilter) (PlatformSubmissionPage, error) {
	return PlatformSubmissionPage{}, errors.New("unexpected ListPlatformSubmissions call")
}

func (s *stubPlatformRepository) GetPlatformSubmission(context.Context, uuid.UUID, uuid.UUID) (PlatformAgentSubmission, bool, error) {
	return PlatformAgentSubmission{}, false, errors.New("unexpected GetPlatformSubmission call")
}

func (s *stubPlatformRepository) ListPlatformVersions(context.Context, uuid.UUID, PageRequest) (PlatformVersionPage, error) {
	return PlatformVersionPage{}, errors.New("unexpected ListPlatformVersions call")
}

func (s *stubPlatformRepository) GetPlatformVersion(context.Context, uuid.UUID, uuid.UUID) (Version, bool, error) {
	return Version{}, false, errors.New("unexpected GetPlatformVersion call")
}

func (s *stubPlatformRepository) AppendOfficialReleaseRevision(ctx context.Context, command OfficialReleaseMutationRepositoryCommand) (OfficialRelease, error) {
	s.lastMutation = command
	if s.appendRelease != nil {
		return s.appendRelease(ctx, command)
	}
	return OfficialRelease{ID: command.ReleaseID, PlatformID: command.PlatformID, HeadRevision: command.ExpectedHeadRevision + 1}, nil
}

func (s *stubPlatformRepository) GetOfficialRelease(context.Context, uuid.UUID, uuid.UUID) (OfficialRelease, bool, error) {
	return OfficialRelease{}, false, errors.New("unexpected GetOfficialRelease call")
}

func (s *stubPlatformRepository) GetOfficialEligibility(ctx context.Context, platformID uuid.UUID, releaseID uuid.UUID, principal Principal, eligibilityContext OfficialEligibilityContext) (OfficialEligibilityRecord, bool, error) {
	if s.eligibility == nil {
		return OfficialEligibilityRecord{}, false, errors.New("unexpected GetOfficialEligibility call")
	}
	return s.eligibility(ctx, platformID, releaseID, principal, eligibilityContext)
}

func platformDraftFromCreate(command CreatePlatformDraftRepositoryCommand) PlatformAgentDraft {
	return PlatformAgentDraft{
		ID: command.DraftID, PlatformID: command.PlatformID,
		DefinitionID: command.Canonical.Package.DefinitionID,
		Kind:         command.Canonical.Package.Kind, DisplayName: command.Canonical.Package.DisplayName,
		Manifest: command.Canonical.Package.Manifest, Bundle: command.Canonical.Package.Bundle,
		ManifestDigest: command.Canonical.ManifestDigest, BundleDigest: command.Canonical.BundleDigest,
		ContentDigest: command.Canonical.ContentDigest, Revision: 1, Status: PlatformDraftActive,
		LastEditorAdminID: command.Actor.AdminID, LastEditorRole: command.Actor.Role,
		CreatedAt: command.CreatedAt, UpdatedAt: command.CreatedAt,
	}
}

func TestPlatformDraftCanonicalizationPreservesDigests(t *testing.T) {
	manifest, bundle := validManifestFixture()
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: uuid.New(), Kind: PlatformDraftInitial, DisplayName: "Official Research",
		Manifest: manifest, Bundle: bundle,
	})
	if err != nil {
		t.Fatalf("CanonicalizePlatformDraft() error = %v", err)
	}
	version, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	if canonical.ManifestDigest != version.ManifestDigest || canonical.BundleDigest != version.BundleDigest ||
		canonical.ContentDigest != version.ContentDigest {
		t.Fatalf("canonical draft = %+v", canonical)
	}
}

func TestPlatformPublicationPolicyPinsModelToolRuntimeAndDependencyRules(t *testing.T) {
	policy := DefaultPlatformAgentPolicyV1()
	if policy.ModelConstraintMode != "manifest_allowlist" ||
		policy.ToolConstraintMode != "manifest_allowlist" ||
		policy.RuntimeCompatibilityMode != "strict_semver" ||
		policy.DependencyMode != "immutable_versions" {
		t.Fatalf("platform policy rules = %+v", policy)
	}
}
