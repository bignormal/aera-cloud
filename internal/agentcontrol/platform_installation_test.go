package agentcontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOfficialInstallationRejectsMixedManualAndManagedSources(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	revisionID := uuid.New()
	contextValue := OfficialEligibilityContext{
		Channel: OfficialChannelStable, DesktopVersion: "v1.0.0",
		Selector: OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: fixture.principal.PersonalSpaceID},
	}
	_, err := fixture.service.CreateInstallation(fixtureContext(), fixture.principal, CreateInstallationRequest{
		DefinitionID: uuid.New(), VersionID: uuid.New(), OfficialReleaseRevisionID: &revisionID,
		OfficialContext: &contextValue, IdempotencyKey: "mixed-installation", RequestID: "mixed-installation",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mixed official/manual request error = %v", err)
	}
}

func TestOfficialInstallationRepositoryRemainsUserOwnedAndBindsRuntimeProvenance(t *testing.T) {
	fixture, service, platformService := newOfficialInstallationFixture(t)
	principal := fixture.principal(t, 0xb1)
	_, versionID, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0xb2)
	active := fixture.activateOfficialRelease(t, release, versionID, nil, 0xb7)
	contextValue := OfficialEligibilityContext{
		Channel: OfficialChannelStable, DesktopVersion: "v1.0.0",
		Selector: OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: principal.PersonalSpaceID},
	}
	resolved, err := platformService.ResolveOfficialReleaseRevision(
		fixture.ctx, principal, release.DefinitionID, active.CurrentRevision.ID, contextValue,
	)
	if err != nil {
		t.Fatalf("ResolveOfficialReleaseRevision() error = %v", err)
	}
	if resolved.ReleaseID != release.ID || resolved.ReleaseRevisionID != active.CurrentRevision.ID ||
		resolved.DefinitionID != release.DefinitionID || resolved.VersionID != versionID {
		t.Fatalf("resolved official target = %+v", resolved)
	}
	service.officialEligibility = platformService
	created, err := service.CreateInstallation(fixture.ctx, principal, CreateInstallationRequest{
		DefinitionID: release.DefinitionID, OfficialReleaseRevisionID: &active.CurrentRevision.ID,
		OfficialContext: &contextValue, IdempotencyKey: "official-install-v1", RequestID: "official-install-v1",
	})
	if err != nil {
		t.Fatalf("CreateInstallation(official) error = %v", err)
	}
	if created.Installation.UpdatePolicy != installationUpdatePolicyManaged ||
		created.Installation.OfficialReleaseID == nil || *created.Installation.OfficialReleaseID != release.ID ||
		created.Installation.SelectedReleaseRevisionID == nil || *created.Installation.SelectedReleaseRevisionID != active.CurrentRevision.ID ||
		created.Installation.SelectedVersionID != versionID {
		t.Fatalf("managed Installation = %+v", created.Installation)
	}
	downloaded, err := service.GetVersion(
		fixture.ctx, principal, versionID, "official-installation-selected-version",
	)
	if err != nil || downloaded.ID != versionID || downloaded.DefinitionID != release.DefinitionID {
		t.Fatalf("selected official Installation version = %+v, %v", downloaded, err)
	}
	var ownerScope string
	var tenantID, ownerID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT tenant_id, owner_scope, owner_id FROM installations WHERE id = $1
	`, created.Installation.ID).Scan(&tenantID, &ownerScope, &ownerID); err != nil {
		t.Fatalf("read official Installation owner: %v", err)
	}
	if tenantID != principal.PersonalSpaceID || ownerScope != string(OwnerScopeUser) || ownerID != principal.UserID {
		t.Fatalf("official Installation owner = %s/%s/%s", tenantID, ownerScope, ownerID)
	}
	var deviceInstallationID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT installation_id FROM devices WHERE id = $1 AND user_id = $2
	`, principal.DeviceID, principal.UserID).Scan(&deviceInstallationID); err != nil {
		t.Fatalf("read official device installation identity: %v", err)
	}
	policyText := string(created.Policy.Document)
	for _, required := range []string{
		`"official_context"`, `"device_installation_id"`, release.ID.String(), active.CurrentRevision.ID.String(),
		principal.UserID.String(), deviceInstallationID.String(), created.Installation.ID.String(),
	} {
		if !strings.Contains(policyText, required) {
			t.Fatalf("official policy missing %q: %s", required, policyText)
		}
	}
	if strings.Contains(policyText, `"device_id"`) || strings.Contains(policyText, principal.DeviceID.String()) {
		t.Fatalf("official policy exposed Cloud-internal device identity: %s", policyText)
	}
	for _, forbidden := range []string{"profile_path", "memory", "session", "credential", "private_skill", "curator"} {
		if strings.Contains(strings.ToLower(policyText), forbidden) {
			t.Fatalf("official policy leaked %q: %s", forbidden, policyText)
		}
	}

	if _, err := fixture.repository.SelectInstallationVersion(fixture.ctx, principal, VersionSelectionCommand{
		InstallationID: created.Installation.ID, VersionID: versionID,
		BuildPolicy: func(int64, Version) (PolicyMaterial, error) { return PolicyMaterial{}, nil },
		Audit:       fixture.auditEvidence(0xb8), SelectedAt: active.UpdatedAt.Add(time.Minute),
	}); !errors.Is(err, ErrOfficialManagedUpdateConflict) {
		t.Fatalf("manual selection on managed Installation error = %v", err)
	}

	profileID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE installations
		SET runtime_profile_id = $2, status = 'active', activated_at = $3, updated_at = $3
		WHERE id = $1
	`, created.Installation.ID, profileID, active.UpdatedAt.Add(2*time.Minute)); err != nil {
		t.Fatalf("activate managed Installation fixture: %v", err)
	}
	revisionID := active.CurrentRevision.ID
	record, err := fixture.repository.InsertRuntimeBinding(fixture.ctx, principal, PersistRuntimeBindingCommand{
		RuntimeBindingRecordCommand: RuntimeBindingRecordCommand{
			BindingID: uuid.New(), AgentInstallationID: created.Installation.ID,
			AgentVersionID: versionID, RuntimeProfileID: profileID, RuntimeVersion: "v0.18.2-agentera.1",
			PolicySnapshotID: created.Policy.ID, ToolPermissionDigest: [32]byte{1},
			OfficialReleaseRevisionID: &revisionID,
		},
		Audit: fixture.auditEvidence(0xb9), CreatedAt: active.UpdatedAt.Add(3 * time.Minute),
	})
	if err != nil || record.OfficialReleaseRevisionID == nil || *record.OfficialReleaseRevisionID != revisionID {
		t.Fatalf("official RuntimeBinding = %+v, %v", record, err)
	}

	verificationCommand := PersistOfficialAgentDeliveryVerificationCommand{
		OfficialAgentDeliveryVerificationCommand: OfficialAgentDeliveryVerificationCommand{
			RequestID: uuid.New(), DefinitionID: release.DefinitionID, VersionID: versionID,
			ReleaseRevisionID: revisionID, ContentDigest: downloaded.ContentDigest,
			Status: OfficialDeliveryActivated, RuntimeVersion: "v0.18.2-agentera.1",
			DesktopVersion: "v1.0.0", OccurredAt: active.UpdatedAt.Add(4 * time.Minute),
		},
		Audit: fixture.auditEvidence(0xba), ReceivedAt: active.UpdatedAt.Add(5 * time.Minute),
	}
	verification, err := fixture.repository.InsertOfficialAgentDeliveryVerification(fixture.ctx, principal, verificationCommand)
	if err != nil || verification.InstallationID != created.Installation.ID || verification.Replayed {
		t.Fatalf("official delivery verification = %+v, %v", verification, err)
	}
	replayed, err := fixture.repository.InsertOfficialAgentDeliveryVerification(fixture.ctx, principal, verificationCommand)
	if err != nil || !replayed.Replayed || replayed.RequestID != verification.RequestID {
		t.Fatalf("official delivery verification replay = %+v, %v", replayed, err)
	}
	conflict := verificationCommand
	conflict.Status = OfficialDeliveryInstalled
	if _, err := fixture.repository.InsertOfficialAgentDeliveryVerification(fixture.ctx, principal, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("official delivery verification conflict error = %v", err)
	}
	wrongDigest := verificationCommand
	wrongDigest.RequestID = uuid.New()
	wrongDigest.ContentDigest = [32]byte{9}
	if _, err := fixture.repository.InsertOfficialAgentDeliveryVerification(fixture.ctx, principal, wrongDigest); !errors.Is(err, ErrOfficialReleaseRevisionConflict) {
		t.Fatalf("official delivery verification digest mismatch error = %v", err)
	}
}

func TestManagedOfficialSelectionAdvancesAndRollsBackWithoutChangingProfile(t *testing.T) {
	fixture, service, platformService := newOfficialInstallationFixture(t)
	principal := fixture.principal(t, 0xc1)
	_, v1, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0xc2)
	v1Active := fixture.activateOfficialRelease(t, release, v1, nil, 0xc7)
	contextValue := OfficialEligibilityContext{
		Channel: OfficialChannelStable, DesktopVersion: "v1.0.0",
		Selector: OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: principal.PersonalSpaceID},
	}
	service.officialEligibility = platformService
	created, err := service.CreateInstallation(fixture.ctx, principal, CreateInstallationRequest{
		DefinitionID: release.DefinitionID, OfficialReleaseRevisionID: &v1Active.CurrentRevision.ID,
		OfficialContext: &contextValue, IdempotencyKey: "managed-flow-v1", RequestID: "managed-flow-v1",
	})
	if err != nil {
		t.Fatalf("create managed Installation: %v", err)
	}
	profileID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE installations SET runtime_profile_id = $2, status = 'active', activated_at = $3, updated_at = $3 WHERE id = $1
	`, created.Installation.ID, profileID, v1Active.UpdatedAt.Add(time.Minute)); err != nil {
		t.Fatalf("activate managed fixture: %v", err)
	}

	v2 := fixture.publishNextOfficialVersion(t, release.DefinitionID, v1, 0xc8)
	v2Active := fixture.activateOfficialRelease(t, v1Active, v2, nil, 0xcb)
	available, err := service.GetManagedOfficialUpdate(fixture.ctx, principal, GetManagedOfficialUpdateRequest{
		InstallationID: created.Installation.ID, OfficialContext: contextValue, RequestID: "managed-read-v2",
	})
	if err != nil || !available.UpdateAvailable || available.InstallationID != created.Installation.ID ||
		available.ExpectedSelectedReleaseRevisionID != v1Active.CurrentRevision.ID ||
		available.Target.ReleaseRevisionID != v2Active.CurrentRevision.ID || available.Version.ID != v2 {
		t.Fatalf("managed v2 target = %+v, %v", available, err)
	}
	selected, err := service.ApplyManagedOfficialUpdate(fixture.ctx, principal, ManagedUpdateRequest{
		InstallationID: created.Installation.ID, ExpectedSelectedRevisionID: v1Active.CurrentRevision.ID,
		TargetReleaseRevisionID: v2Active.CurrentRevision.ID, OfficialContext: contextValue,
		RequestID: "managed-select-v2",
	})
	if err != nil || selected.SelectedVersionID != v2 || selected.SelectedReleaseRevisionID == nil ||
		*selected.SelectedReleaseRevisionID != v2Active.CurrentRevision.ID || selected.RuntimeProfileID == nil || *selected.RuntimeProfileID != profileID {
		t.Fatalf("managed v2 selection = %+v, %v", selected, err)
	}
	current, err := service.GetManagedOfficialUpdate(fixture.ctx, principal, GetManagedOfficialUpdateRequest{
		InstallationID: created.Installation.ID, OfficialContext: contextValue, RequestID: "managed-read-current",
	})
	if err != nil || current.UpdateAvailable {
		t.Fatalf("managed current target = %+v, %v", current, err)
	}
	if _, err := service.ApplyManagedOfficialUpdate(fixture.ctx, principal, ManagedUpdateRequest{
		InstallationID: created.Installation.ID, ExpectedSelectedRevisionID: v1Active.CurrentRevision.ID,
		TargetReleaseRevisionID: uuid.New(), OfficialContext: contextValue, RequestID: "managed-stale",
	}); !errors.Is(err, ErrOfficialManagedUpdateConflict) {
		t.Fatalf("stale managed selection error = %v", err)
	}

	rollback := fixture.rollbackOfficialRelease(t, v2Active, v1, v1Active.CurrentRevision.ID, 0xcc)
	rolledBack, err := service.ApplyManagedOfficialUpdate(fixture.ctx, principal, ManagedUpdateRequest{
		InstallationID: created.Installation.ID, ExpectedSelectedRevisionID: v2Active.CurrentRevision.ID,
		TargetReleaseRevisionID: rollback.CurrentRevision.ID, OfficialContext: contextValue,
		RequestID: "managed-rollback-v1",
	})
	if err != nil || rolledBack.SelectedVersionID != v1 || rolledBack.SelectedReleaseRevisionID == nil ||
		*rolledBack.SelectedReleaseRevisionID != rollback.CurrentRevision.ID || rolledBack.RuntimeProfileID == nil || *rolledBack.RuntimeProfileID != profileID {
		t.Fatalf("managed rollback selection = %+v, %v", rolledBack, err)
	}
}

func TestManagedOfficialUpdateRejectsAReleaseFromAnotherTrustedChannel(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	releaseID, selectedRevisionID := uuid.New(), uuid.New()
	installation := Installation{
		ID: uuid.New(), DeviceID: fixture.principal.DeviceID,
		DefinitionID: uuid.New(), UpdatePolicy: installationUpdatePolicyManaged,
		OfficialReleaseID: &releaseID, SelectedReleaseRevisionID: &selectedRevisionID,
		Status: InstallationStatusActive,
	}
	fixture.repository.findInstallation = func(
		_ context.Context,
		_ Principal,
		_ uuid.UUID,
	) (Installation, bool, error) {
		return installation, true, nil
	}
	targetVersionID := uuid.New()
	fixture.service.officialEligibility = &stubOfficialCatalogHTTPService{entry: OfficialAgentCatalogEntry{
		DefinitionID: installation.DefinitionID,
		Target: OfficialManagedTarget{
			PlatformID: uuid.New(), ReleaseID: uuid.New(), ReleaseRevisionID: uuid.New(),
			DefinitionID: installation.DefinitionID, VersionID: targetVersionID, Channel: OfficialChannelInternal,
		},
		Version: Version{ID: targetVersionID, DefinitionID: installation.DefinitionID, VersionNumber: 2},
	}}
	contextValue := OfficialEligibilityContext{
		Channel: OfficialChannelInternal, DesktopVersion: "v1.0.0",
		Selector: OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: fixture.principal.PersonalSpaceID},
	}
	_, err := fixture.service.GetManagedOfficialUpdate(context.Background(), fixture.principal, GetManagedOfficialUpdateRequest{
		InstallationID: installation.ID, OfficialContext: contextValue, RequestID: "managed-channel-mismatch",
	})
	if !errors.Is(err, ErrOfficialAgentNotEligible) {
		t.Fatalf("managed update release mismatch error = %v", err)
	}
}

func newOfficialInstallationFixture(t *testing.T) (*platformRepositoryFixture, *Service, PlatformService) {
	t.Helper()
	fixture := newPlatformRepositoryFixture(t)
	signer, _ := signingFixture(t)
	platform, err := NewPlatformService(PlatformServiceConfig{
		Repository: fixture.repository, Signer: signer, PlatformID: fixture.platformID,
		PlatformKey: "agentera_official", PlatformDisplayName: "Aera Official",
		RolloutKeyID: "rollout-v1",
		RolloutKeys:  map[string][]byte{"rollout-v1": []byte("0123456789abcdef0123456789abcdef")},
		Clock:        func() time.Time { return fixture.now.Add(30 * time.Minute) }, NewID: uuid.New,
	})
	if err != nil {
		t.Fatalf("NewPlatformService() error = %v", err)
	}
	service, err := NewService(ServiceConfig{
		Repository: fixture.repository, Signer: signer,
		OfficialEligibility: platform,
		Clock:               func() time.Time { return fixture.now.Add(31 * time.Minute) }, NewID: uuid.New,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return fixture, service, platform
}

func (fixture *platformRepositoryFixture) activateOfficialRelease(
	t *testing.T,
	release OfficialRelease,
	versionID uuid.UUID,
	audience []uuid.UUID,
	discriminator byte,
) OfficialRelease {
	t.Helper()
	command := fixture.releaseMutation(release, versionID, discriminator)
	command.RolloutBasisPoints = 10000
	command.AllowlistedUserIDs, _ = canonicalOfficialAudience(audience)
	value, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, command)
	if err != nil {
		t.Fatalf("AppendOfficialReleaseRevision(activate) error = %v", err)
	}
	return value
}

func (fixture *platformRepositoryFixture) rollbackOfficialRelease(
	t *testing.T,
	release OfficialRelease,
	targetVersionID uuid.UUID,
	targetRevisionID uuid.UUID,
	discriminator byte,
) OfficialRelease {
	t.Helper()
	value, err := fixture.repository.AppendOfficialReleaseRevision(fixture.ctx, OfficialReleaseMutationRepositoryCommand{
		RevisionID: uuid.New(), PlatformID: fixture.platformID, ReleaseID: release.ID,
		ExpectedHeadRevision: release.HeadRevision,
		Actor:                PlatformAdminActor{AdminID: uuid.New(), Role: "super_admin", RequestID: "managed-rollback"},
		Action:               OfficialReleaseActionRollback, VersionID: targetVersionID,
		TargetReleaseRevisionID: targetRevisionID, ApprovalID: uuid.New(), ReasonCode: "rollback_approved",
		Idempotency: fixture.idempotency(discriminator), Audit: fixture.auditEvidence(discriminator),
		ChangedAt: release.UpdatedAt.Add(time.Duration(discriminator) * time.Second),
	})
	if err != nil {
		t.Fatalf("AppendOfficialReleaseRevision(rollback) error = %v", err)
	}
	return value
}

func fixtureContext() context.Context { return context.Background() }
