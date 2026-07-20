package agentcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServicePublishInitialCanonicalizesSignsAndReturnsDetachedValues(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	manifest, bundle := validManifestFixture()
	icon := encodedPNG(t, 2, 2)
	var captured InitialPublicationCommand
	var capturedMaterial VersionMaterial
	fixture.repository.publishInitial = func(_ context.Context, _ Principal, command InitialPublicationCommand) (Publication, error) {
		captured = command
		material, err := command.BuildVersion()
		if err != nil {
			return Publication{}, err
		}
		capturedMaterial = material
		return publicationFromInitial(command, material), nil
	}

	result, err := fixture.service.PublishInitial(context.Background(), fixture.principal, PublishInitialRequest{
		DisplayName: "Research Agent", IconMediaType: "image/png", IconData: icon,
		Manifest: manifest, Bundle: bundle, IdempotencyKey: "publish-one", RequestID: "request-1",
	})
	if err != nil {
		t.Fatalf("PublishInitial() error = %v", err)
	}
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	if !bytes.Equal(capturedMaterial.CanonicalManifest, canonical.ManifestJSON) ||
		!bytes.Equal(capturedMaterial.Bundle, canonical.BundleJSON) ||
		capturedMaterial.ContentDigest != canonical.ContentDigest || capturedMaterial.VersionNumber != 1 {
		t.Fatalf("captured publication = %+v", captured)
	}
	if err := fixture.verifier.VerifyVersion(VersionAttestation{
		Issuer: fixture.issuer, KeyID: capturedMaterial.SigningKeyID,
		DefinitionID: captured.DefinitionID, VersionID: capturedMaterial.ID, VersionNumber: capturedMaterial.VersionNumber,
		ManifestDigest: canonical.ManifestDigest, BundleDigest: canonical.BundleDigest,
		Signature: capturedMaterial.Signature,
	}); err != nil {
		t.Fatalf("VerifyVersion() error = %v", err)
	}
	if captured.Idempotency.KeyHash != sha256.Sum256([]byte("publish-one")) ||
		captured.Idempotency.RequestHash == sha256.Sum256(nil) {
		t.Fatalf("idempotency evidence = %+v", captured.Idempotency)
	}

	result.Definition.IconData[0] ^= 0xff
	result.Version.Bundle[0] ^= 0xff
	result.Version.Signature[0] ^= 0xff
	if bytes.Equal(result.Definition.IconData, captured.IconData) || bytes.Equal(result.Version.Bundle, capturedMaterial.Bundle) ||
		bytes.Equal(result.Version.Signature, capturedMaterial.Signature) {
		t.Fatal("PublishInitial() returned aliases of repository command or result data")
	}
}

func TestServicePublishInitialProducesStableIdempotencyReplayAndRejectsChangedPayload(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	manifest, bundle := validManifestFixture()
	var storedRequest [sha256.Size]byte
	var storedKey [sha256.Size]byte
	var stored Publication
	fixture.repository.publishInitial = func(_ context.Context, _ Principal, command InitialPublicationCommand) (Publication, error) {
		if stored.Definition.ID == uuid.Nil {
			storedRequest = command.Idempotency.RequestHash
			storedKey = command.Idempotency.KeyHash
			material, err := command.BuildVersion()
			if err != nil {
				return Publication{}, err
			}
			stored = publicationFromInitial(command, material)
			return stored, nil
		}
		if command.Idempotency.KeyHash == storedKey && command.Idempotency.RequestHash != storedRequest {
			return Publication{}, ErrIdempotencyConflict
		}
		replayed := clonePublication(stored)
		replayed.Replayed = true
		return replayed, nil
	}
	request := PublishInitialRequest{
		DisplayName: "Research Agent", Manifest: manifest, Bundle: bundle,
		IdempotencyKey: "stable-key", RequestID: "request-2",
	}
	first, err := fixture.service.PublishInitial(context.Background(), fixture.principal, request)
	if err != nil {
		t.Fatalf("PublishInitial() error = %v", err)
	}
	replayed, err := fixture.service.PublishInitial(context.Background(), fixture.principal, request)
	if err != nil || !replayed.Replayed || replayed.Definition.ID != first.Definition.ID {
		t.Fatalf("PublishInitial(replay) = %+v error=%v", replayed, err)
	}
	request.DisplayName = "Changed Agent"
	if _, err := fixture.service.PublishInitial(context.Background(), fixture.principal, request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("PublishInitial(changed payload) error = %v", err)
	}
}

func TestServicePublishNextSignsOnlyInsideAuthorizedVersionBuilder(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	manifest, bundle := validManifestFixture()
	definitionID := uuid.New()
	baseVersionID := uuid.New()
	called := false
	fixture.repository.publishNext = func(_ context.Context, _ Principal, command NextPublicationCommand) (Publication, error) {
		called = true
		material, err := command.BuildVersion(4)
		if err != nil {
			return Publication{}, err
		}
		latest := material.ID
		return Publication{
			Definition: Definition{ID: definitionID, DisplayName: "Research Agent", Status: definitionStatusActive, LatestVersionID: &latest},
			Version:    versionFromMaterial(definitionID, material, fixture.now),
		}, nil
	}
	result, err := fixture.service.PublishNext(context.Background(), fixture.principal, PublishNextRequest{
		DefinitionID: definitionID, BaseVersionID: baseVersionID, Manifest: manifest, Bundle: bundle,
		IdempotencyKey: "publish-next", RequestID: "request-3",
	})
	if err != nil {
		t.Fatalf("PublishNext() error = %v", err)
	}
	if !called || result.Version.VersionNumber != 4 {
		t.Fatalf("PublishNext() = %+v called=%v", result, called)
	}
	canonical, _ := CanonicalizeVersion(manifest, bundle)
	if err := fixture.verifier.VerifyVersion(VersionAttestation{
		Issuer: fixture.issuer, KeyID: result.Version.SigningKeyID,
		DefinitionID: definitionID, VersionID: result.Version.ID, VersionNumber: 4,
		ManifestDigest: canonical.ManifestDigest, BundleDigest: canonical.BundleDigest, Signature: result.Version.Signature,
	}); err != nil {
		t.Fatalf("VerifyVersion() error = %v", err)
	}

	for name, expected := range map[string]error{
		"stale": ErrVersionConflict, "archived": ErrDefinitionArchived, "missing": ErrNotFound,
	} {
		t.Run(name, func(t *testing.T) {
			builderCalled := false
			fixture.repository.publishNext = func(_ context.Context, _ Principal, command NextPublicationCommand) (Publication, error) {
				_ = command
				return Publication{}, expected
			}
			_, err := fixture.service.PublishNext(context.Background(), fixture.principal, PublishNextRequest{
				DefinitionID: definitionID, BaseVersionID: baseVersionID, Manifest: manifest, Bundle: bundle,
				IdempotencyKey: "publish-" + name, RequestID: "request-" + name,
			})
			if !errors.Is(err, expected) || builderCalled {
				t.Fatalf("PublishNext(%s) error=%v builderCalled=%v", name, err, builderCalled)
			}
		})
	}
}

func TestServicePublishRejectsInvalidContentBeforeRepositoryAndPropagatesRollback(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	manifest, bundle := validManifestFixture()
	calls := 0
	fixture.repository.publishInitial = func(_ context.Context, _ Principal, _ InitialPublicationCommand) (Publication, error) {
		calls++
		return Publication{}, ErrServiceUnavailable
	}
	if _, err := fixture.service.PublishInitial(context.Background(), fixture.principal, PublishInitialRequest{
		DisplayName: "Research Agent", IconMediaType: "image/png", IconData: []byte("not-png"),
		Manifest: manifest, Bundle: bundle, IdempotencyKey: "invalid-icon", RequestID: "request-4",
	}); !errors.Is(err, ErrInvalidAgentContent) {
		t.Fatalf("PublishInitial(invalid icon) error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("repository calls after invalid icon = %d", calls)
	}
	if _, err := fixture.service.PublishInitial(context.Background(), fixture.principal, PublishInitialRequest{
		DisplayName: "Research Agent", Manifest: manifest, Bundle: bundle,
		IdempotencyKey: "rollback", RequestID: "request-5",
	}); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("PublishInitial(repository rollback) error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("repository calls = %d", calls)
	}
}

func TestServiceListAndGetDetachResultsAndAuditCrossOwnerNonDisclosure(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	icon := []byte{1, 2, 3}
	bundle := []byte(`{"assets":[]}`)
	signature := bytes.Repeat([]byte{7}, 64)
	definitionID := uuid.New()
	versionID := uuid.New()
	policyID := uuid.New()
	latest := versionID
	policyDocument := []byte(`{"schema_version":1}`)
	policySignature := bytes.Repeat([]byte{8}, 64)
	fixture.repository.listDefinitions = func(context.Context, Principal) ([]Definition, error) {
		return []Definition{{ID: definitionID, DisplayName: "Agent", IconData: icon, Status: definitionStatusActive, LatestVersionID: &latest}}, nil
	}
	fixture.repository.findDefinition = func(context.Context, Principal, uuid.UUID) (Definition, bool, error) {
		return Definition{}, false, nil
	}
	fixture.repository.findVersion = func(context.Context, Principal, uuid.UUID) (Version, bool, error) {
		return Version{ID: versionID, DefinitionID: definitionID, VersionNumber: 1, Bundle: bundle, Signature: signature}, true, nil
	}
	fixture.repository.findPolicySnapshot = func(context.Context, Principal, uuid.UUID) (PolicySnapshot, bool, error) {
		return PolicySnapshot{ID: policyID, Document: policyDocument, Signature: policySignature}, true, nil
	}
	fixture.repository.listVersions = func(context.Context, Principal, uuid.UUID) ([]Version, error) {
		return []Version{{ID: versionID, DefinitionID: definitionID, VersionNumber: 1, Bundle: bundle, Signature: signature}}, nil
	}
	var denied DeniedAuditCommand
	fixture.repository.recordDenied = func(_ context.Context, _ Principal, command DeniedAuditCommand) error {
		denied = command
		return nil
	}

	definitions, err := fixture.service.ListDefinitions(context.Background(), fixture.principal)
	if err != nil {
		t.Fatalf("ListDefinitions() error = %v", err)
	}
	versions, err := fixture.service.ListVersions(context.Background(), fixture.principal, definitionID, "request-6")
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}
	version, err := fixture.service.GetVersion(context.Background(), fixture.principal, versionID, "request-6-version")
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	policy, err := fixture.service.GetPolicySnapshot(context.Background(), fixture.principal, policyID, "request-6-policy")
	if err != nil {
		t.Fatalf("GetPolicySnapshot() error = %v", err)
	}
	definitions[0].IconData[0] = 9
	versions[0].Bundle[0] = 9
	versions[0].Signature[0] = 9
	version.Bundle[0] = 8
	version.Signature[0] = 8
	policy.Document[0] = '['
	policy.Signature[0] = 9
	if icon[0] != 1 || bundle[0] != '{' || signature[0] != 7 || policyDocument[0] != '{' || policySignature[0] != 8 {
		t.Fatal("list response aliases repository-owned data")
	}

	missingID := uuid.New()
	if _, err := fixture.service.GetDefinition(context.Background(), fixture.principal, missingID, "request-7"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDefinition(cross owner) error = %v", err)
	}
	if denied.ObjectID != missingID || denied.ObjectType != "agent_definition" || denied.ReasonCode != "not_found" {
		t.Fatalf("denied audit = %+v", denied)
	}
	fixture.repository.findPolicySnapshot = func(context.Context, Principal, uuid.UUID) (PolicySnapshot, bool, error) {
		return PolicySnapshot{}, false, nil
	}
	if _, err := fixture.service.GetPolicySnapshot(context.Background(), fixture.principal, missingID, "request-7-policy"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPolicySnapshot(cross owner) error = %v", err)
	}
	if denied.ObjectID != missingID || denied.ObjectType != "policy_snapshot" || denied.ReasonCode != "not_found" {
		t.Fatalf("policy denied audit = %+v", denied)
	}
}

func TestServiceRevokeVersionHashesIdempotencyAndPreservesAppendOnlyConflictSemantics(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	versionID := uuid.New()
	policyID := uuid.New()
	var first *VersionRevocationCommand
	fixture.repository.appendRevocation = func(_ context.Context, _ Principal, command VersionRevocationCommand) (VersionRevocation, error) {
		if first == nil {
			copy := command
			first = &copy
			return VersionRevocation{
				ID: command.RevocationID, VersionID: command.VersionID, ReasonCode: command.ReasonCode,
				PolicySnapshotID: command.PolicySnapshotID, CreatedAt: command.RevokedAt,
			}, nil
		}
		if command.Idempotency.KeyHash == first.Idempotency.KeyHash && command.Idempotency.RequestHash != first.Idempotency.RequestHash {
			return VersionRevocation{}, ErrIdempotencyConflict
		}
		return VersionRevocation{
			ID: first.RevocationID, VersionID: first.VersionID, ReasonCode: first.ReasonCode,
			PolicySnapshotID: first.PolicySnapshotID, CreatedAt: first.RevokedAt, Replayed: true,
		}, nil
	}
	request := RevokeVersionRequest{
		VersionID: versionID, PolicySnapshotID: policyID, ReasonCode: "owner_revoked",
		IdempotencyKey: "revoke-key", RequestID: "request-8",
	}
	created, err := fixture.service.RevokeVersion(context.Background(), fixture.principal, request)
	if err != nil {
		t.Fatalf("RevokeVersion() error = %v", err)
	}
	replayed, err := fixture.service.RevokeVersion(context.Background(), fixture.principal, request)
	if err != nil || !replayed.Replayed || replayed.ID != created.ID {
		t.Fatalf("RevokeVersion(replay) = %+v error=%v", replayed, err)
	}
	request.ReasonCode = "security_issue"
	if _, err := fixture.service.RevokeVersion(context.Background(), fixture.principal, request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("RevokeVersion(changed reason) error = %v", err)
	}
}

func TestServiceCreateInstallationSignsBoundedPolicyAfterOwnerAuthorizationAndReplays(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	definitionID := uuid.New()
	versionID := uuid.New()
	version := policyVersionFixture(t, definitionID, versionID, 1)
	latest := versionID
	fixture.repository.findDefinition = func(context.Context, Principal, uuid.UUID) (Definition, bool, error) {
		return Definition{ID: definitionID, Status: definitionStatusActive, LatestVersionID: &latest}, true, nil
	}
	fixture.repository.findVersion = func(context.Context, Principal, uuid.UUID) (Version, bool, error) {
		return version, true, nil
	}
	policyBuilds := 0
	var storedRequest [sha256.Size]byte
	var storedKey [sha256.Size]byte
	var stored InstallationCreation
	fixture.repository.createPendingInstallation = func(
		_ context.Context,
		_ Principal,
		command CreateInstallationCommand,
	) (InstallationCreation, error) {
		if stored.Installation.ID != uuid.Nil {
			if command.Idempotency.KeyHash == storedKey && command.Idempotency.RequestHash != storedRequest {
				return InstallationCreation{}, ErrIdempotencyConflict
			}
			replayed := cloneInstallationCreation(stored)
			replayed.Replayed = true
			return replayed, nil
		}
		policyBuilds++
		policy, err := command.BuildPolicy(version)
		if err != nil {
			return InstallationCreation{}, err
		}
		storedRequest = command.Idempotency.RequestHash
		storedKey = command.Idempotency.KeyHash
		policyID := policy.ID
		stored = InstallationCreation{
			Installation: Installation{
				ID: command.InstallationID, DeviceID: fixture.principal.DeviceID, DeviceInstallationID: uuid.New(),
				DefinitionID: definitionID, SelectedVersionID: versionID, PolicySnapshotID: &policyID,
				UpdatePolicy: installationUpdatePolicy, Status: InstallationStatusPending,
			},
			Policy: policySnapshotFromMaterial(policy),
		}
		return stored, nil
	}
	request := CreateInstallationRequest{
		DefinitionID: definitionID, VersionID: versionID,
		IdempotencyKey: "install-one", RequestID: "request-install-1",
	}
	created, err := fixture.service.CreateInstallation(context.Background(), fixture.principal, request)
	if err != nil {
		t.Fatalf("CreateInstallation() error = %v", err)
	}
	if created.Installation.Status != InstallationStatusPending || created.Installation.RuntimeProfileID != nil ||
		created.Installation.DeviceInstallationID == uuid.Nil || policyBuilds != 1 {
		t.Fatalf("CreateInstallation() = %+v policyBuilds=%d", created, policyBuilds)
	}
	if strings.Contains(strings.ToLower(string(created.Policy.Document)), "memory") ||
		strings.Contains(strings.ToLower(string(created.Policy.Document)), "profile_path") ||
		strings.Contains(strings.ToLower(string(created.Policy.Document)), "credential") {
		t.Fatalf("policy contains private runtime fields: %s", created.Policy.Document)
	}
	if err := fixture.verifier.VerifyPolicy(PolicyAttestation{
		Issuer: created.Policy.Issuer, KeyID: created.Policy.SigningKeyID, PolicyID: created.Policy.ID,
		PolicyVersion: created.Policy.PolicyVersion, DocumentDigest: sha256.Sum256(created.Policy.Document),
		Signature: created.Policy.Signature,
	}); err != nil {
		t.Fatalf("VerifyPolicy() error = %v", err)
	}
	replayed, err := fixture.service.CreateInstallation(context.Background(), fixture.principal, request)
	if err != nil || !replayed.Replayed || replayed.Installation.ID != created.Installation.ID || policyBuilds != 1 {
		t.Fatalf("CreateInstallation(replay) = %+v error=%v policyBuilds=%d", replayed, err, policyBuilds)
	}
}

func TestPolicyDocumentRecanonicalizesEquivalentJSONStorageBytes(t *testing.T) {
	version := policyVersionFixture(t, uuid.New(), uuid.New(), 1)
	version.CanonicalManifest = append([]byte(" \n\t"), version.CanonicalManifest...)
	version.Bundle = append([]byte("\n "), version.Bundle...)

	document, err := policyDocumentForVersion(version)
	if err != nil {
		t.Fatalf("policyDocumentForVersion(equivalent JSON) error = %v", err)
	}
	if !bytes.Contains(document, []byte(hex.EncodeToString(version.ContentDigest[:]))) {
		t.Fatalf("policy document does not retain the immutable version digest: %s", document)
	}

	tampered := version
	tampered.CanonicalManifest = bytes.Replace(
		tampered.CanonicalManifest,
		[]byte("Agent identity"),
		[]byte("Altered identity"),
		1,
	)
	if _, err := policyDocumentForVersion(tampered); !errors.Is(err, ErrInvalidAgentContent) {
		t.Fatalf("policyDocumentForVersion(tampered) error = %v", err)
	}
}

func TestServiceActivationVerifiesDeviceProofDigestProfileTimestampAndReplay(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	installationID := uuid.New()
	profileID := uuid.New()
	version := policyVersionFixture(t, uuid.New(), uuid.New(), 1)
	policyID := uuid.New()
	activationContext := InstallationActivationContext{
		Installation: Installation{
			ID: installationID, DeviceID: fixture.principal.DeviceID, DefinitionID: version.DefinitionID,
			SelectedVersionID: version.ID, PolicySnapshotID: &policyID, Status: InstallationStatusPending,
		},
		Version: version, DevicePublicKey: private.Public().(ed25519.PublicKey),
	}
	fixture.repository.loadActivationContext = func(context.Context, Principal, uuid.UUID) (InstallationActivationContext, bool, error) {
		return activationContext, true, nil
	}
	activationCalls := 0
	fixture.repository.activateInstallation = func(_ context.Context, _ Principal, command ActivationCommand) (Installation, error) {
		activationCalls++
		activated := activationContext.Installation
		activated.Status = InstallationStatusActive
		activated.RuntimeProfileID = &command.RuntimeProfileID
		return activated, nil
	}
	proofInput := ActivationProofInput{
		AgentInstallationID: installationID, RuntimeProfileID: profileID,
		VersionDigest: version.ContentDigest, Timestamp: fixture.now.Unix(),
	}
	payload, err := ActivationProofBytes(proofInput)
	if err != nil {
		t.Fatalf("ActivationProofBytes() error = %v", err)
	}
	request := ActivateInstallationRequest{
		InstallationID: installationID, RuntimeProfileID: profileID, VersionDigest: version.ContentDigest,
		Timestamp: fixture.now.Unix(), DeviceProof: ed25519.Sign(private, payload), RequestID: "request-activate-1",
	}
	activated, err := fixture.service.ActivateInstallation(context.Background(), fixture.principal, request)
	if err != nil || activated.RuntimeProfileID == nil || *activated.RuntimeProfileID != profileID {
		t.Fatalf("ActivateInstallation() = %+v error=%v", activated, err)
	}
	replayed, err := fixture.service.ActivateInstallation(context.Background(), fixture.principal, request)
	if err != nil || replayed.RuntimeProfileID == nil || *replayed.RuntimeProfileID != profileID {
		t.Fatalf("ActivateInstallation(replay) = %+v error=%v", replayed, err)
	}
	if activationCalls != 2 {
		t.Fatalf("activation calls = %d", activationCalls)
	}

	invalid := []ActivateInstallationRequest{
		withActivationRequestProfile(request, uuid.New()),
		withActivationRequestDigest(request, sha256.Sum256([]byte("wrong version"))),
		withActivationRequestTimestamp(t, request, private, fixture.now.Add(-6*time.Minute).Unix()),
	}
	for index, candidate := range invalid {
		if _, err := fixture.service.ActivateInstallation(context.Background(), fixture.principal, candidate); !errors.Is(err, ErrInvalidDeviceProof) {
			t.Fatalf("invalid activation %d error = %v", index, err)
		}
	}
	if activationCalls != 2 {
		t.Fatalf("activation calls after invalid proofs = %d", activationCalls)
	}
	activationContext.DevicePublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x56}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := fixture.service.ActivateInstallation(context.Background(), fixture.principal, request); !errors.Is(err, ErrInvalidDeviceProof) {
		t.Fatalf("ActivateInstallation(wrong device key) error = %v", err)
	}
}

func TestServiceSelectionSignsNextPolicyAndPreservesLastVersionOnFailure(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	definitionID := uuid.New()
	oldVersionID := uuid.New()
	newVersion := policyVersionFixture(t, definitionID, uuid.New(), 2)
	profileID := uuid.New()
	oldPolicyID := uuid.New()
	installation := Installation{
		ID: uuid.New(), DeviceID: fixture.principal.DeviceID, DefinitionID: definitionID,
		SelectedVersionID: oldVersionID, RuntimeProfileID: &profileID, PolicySnapshotID: &oldPolicyID,
		Status: InstallationStatusActive,
	}
	fixture.repository.findInstallation = func(context.Context, Principal, uuid.UUID) (Installation, bool, error) {
		return installation, true, nil
	}
	fixture.repository.findVersion = func(context.Context, Principal, uuid.UUID) (Version, bool, error) {
		return newVersion, true, nil
	}
	var built PolicyMaterial
	fixture.repository.selectInstallationVersion = func(
		_ context.Context,
		_ Principal,
		command VersionSelectionCommand,
	) (Installation, error) {
		policy, err := command.BuildPolicy(2, newVersion)
		if err != nil {
			return Installation{}, err
		}
		built = policy
		selected := installation
		selected.SelectedVersionID = command.VersionID
		selected.PolicySnapshotID = &policy.ID
		return selected, nil
	}
	selected, err := fixture.service.SelectInstallationVersion(context.Background(), fixture.principal, SelectInstallationVersionRequest{
		InstallationID: installation.ID, VersionID: newVersion.ID, RequestID: "request-select-1",
	})
	if err != nil || selected.SelectedVersionID != newVersion.ID || built.PolicyVersion != 2 {
		t.Fatalf("SelectInstallationVersion() = %+v policy=%+v error=%v", selected, built, err)
	}
	if err := fixture.verifier.VerifyPolicy(PolicyAttestation{
		Issuer: built.Issuer, KeyID: built.SigningKeyID, PolicyID: built.ID,
		PolicyVersion: built.PolicyVersion, DocumentDigest: built.ContentDigest, Signature: built.Signature,
	}); err != nil {
		t.Fatalf("VerifyPolicy(selection) error = %v", err)
	}
	fixture.repository.selectInstallationVersion = func(context.Context, Principal, VersionSelectionCommand) (Installation, error) {
		return Installation{}, ErrServiceUnavailable
	}
	failed, err := fixture.service.SelectInstallationVersion(context.Background(), fixture.principal, SelectInstallationVersionRequest{
		InstallationID: installation.ID, VersionID: newVersion.ID, RequestID: "request-select-2",
	})
	if !errors.Is(err, ErrServiceUnavailable) || failed.SelectedVersionID != uuid.Nil || installation.SelectedVersionID != oldVersionID {
		t.Fatalf("failed selection = %+v error=%v original=%+v", failed, err, installation)
	}
}

func TestServiceArchiveAndBindingUseMetadataOnlyCommands(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	installation := Installation{ID: uuid.New(), DeviceID: fixture.principal.DeviceID, Status: InstallationStatusActive}
	fixture.repository.archiveInstallation = func(_ context.Context, _ Principal, command ArchiveInstallationCommand) (Installation, error) {
		archived := installation
		archived.Status = InstallationStatusArchived
		archived.ArchivedAt = &command.ArchivedAt
		return archived, nil
	}
	archived, err := fixture.service.ArchiveInstallation(context.Background(), fixture.principal, ArchiveInstallationRequest{
		InstallationID: installation.ID, RequestID: "request-archive-1",
	})
	if err != nil || archived.Status != InstallationStatusArchived {
		t.Fatalf("ArchiveInstallation() = %+v error=%v", archived, err)
	}

	commandType := reflect.TypeOf(RuntimeBindingRecordCommand{})
	wantFields := []string{
		"BindingID", "AgentInstallationID", "AgentVersionID", "RuntimeProfileID",
		"RuntimeVersion", "PolicySnapshotID", "ToolPermissionDigest",
	}
	if commandType.NumField() != len(wantFields) {
		t.Fatalf("RuntimeBindingRecordCommand fields = %d, want %d", commandType.NumField(), len(wantFields))
	}
	for index, name := range wantFields {
		if commandType.Field(index).Name != name {
			t.Fatalf("RuntimeBindingRecordCommand field %d = %s, want %s", index, commandType.Field(index).Name, name)
		}
	}
	binding := RuntimeBindingRecordCommand{
		BindingID: uuid.New(), AgentInstallationID: uuid.New(), AgentVersionID: uuid.New(),
		RuntimeProfileID: uuid.New(), RuntimeVersion: "0.18.2-agentera.1", PolicySnapshotID: uuid.New(),
		ToolPermissionDigest: sha256.Sum256([]byte("tools")),
	}
	var persisted PersistRuntimeBindingCommand
	fixture.repository.insertRuntimeBinding = func(_ context.Context, _ Principal, command PersistRuntimeBindingCommand) (RuntimeBindingRecord, error) {
		persisted = command
		return runtimeBindingFromCommand(command), nil
	}
	stored, err := fixture.service.RecordRuntimeBinding(context.Background(), fixture.principal, binding, "request-binding-1")
	if err != nil || stored.ID != binding.BindingID || persisted.Audit.EventID == uuid.Nil || persisted.CreatedAt.IsZero() {
		t.Fatalf("RecordRuntimeBinding() = %+v persisted=%+v error=%v", stored, persisted, err)
	}
}

func policyVersionFixture(t *testing.T, definitionID uuid.UUID, versionID uuid.UUID, number int64) Version {
	t.Helper()
	manifest, bundle := validManifestFixture()
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	return Version{
		ID: versionID, DefinitionID: definitionID, VersionNumber: number,
		CanonicalManifest: canonical.ManifestJSON, Bundle: canonical.BundleJSON, ContentDigest: canonical.ContentDigest,
		RuntimeMinimumVersion: "v0.18.2-agentera.1",
	}
}

func withActivationRequestProfile(request ActivateInstallationRequest, profileID uuid.UUID) ActivateInstallationRequest {
	request.RuntimeProfileID = profileID
	return request
}

func withActivationRequestDigest(request ActivateInstallationRequest, digest [sha256.Size]byte) ActivateInstallationRequest {
	request.VersionDigest = digest
	return request
}

func withActivationRequestTimestamp(
	t *testing.T,
	request ActivateInstallationRequest,
	private ed25519.PrivateKey,
	timestamp int64,
) ActivateInstallationRequest {
	t.Helper()
	request.Timestamp = timestamp
	payload, err := ActivationProofBytes(ActivationProofInput{
		AgentInstallationID: request.InstallationID, RuntimeProfileID: request.RuntimeProfileID,
		VersionDigest: request.VersionDigest, Timestamp: timestamp,
	})
	if err != nil {
		t.Fatalf("ActivationProofBytes() error = %v", err)
	}
	request.DeviceProof = ed25519.Sign(private, payload)
	return request
}

type agentControlServiceFixture struct {
	service    *Service
	repository *stubServiceRepository
	principal  Principal
	verifier   *Verifier
	issuer     string
	now        time.Time
}

func newAgentControlServiceFixture(t *testing.T) *agentControlServiceFixture {
	t.Helper()
	signer, verifier := signingFixture(t)
	repository := &stubServiceRepository{}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	counter := 0
	service, err := NewService(ServiceConfig{
		Repository: repository, Signer: signer, Clock: func() time.Time { return now },
		NewID: func() uuid.UUID {
			counter++
			return uuid.NewSHA1(uuid.NameSpaceOID, []byte(strconv.Itoa(counter)))
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return &agentControlServiceFixture{
		service: service, repository: repository,
		principal: Principal{UserID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New()},
		verifier:  verifier, issuer: signer.issuer, now: now,
	}
}

type stubServiceRepository struct {
	publishInitial            func(context.Context, Principal, InitialPublicationCommand) (Publication, error)
	publishNext               func(context.Context, Principal, NextPublicationCommand) (Publication, error)
	publishWorkspaceInitial   func(context.Context, Principal, uuid.UUID, InitialPublicationCommand) (Publication, error)
	publishWorkspaceNext      func(context.Context, Principal, uuid.UUID, NextPublicationCommand) (Publication, error)
	findDefinition            func(context.Context, Principal, uuid.UUID) (Definition, bool, error)
	findWorkspaceDefinition   func(context.Context, Principal, uuid.UUID, uuid.UUID) (Definition, bool, error)
	findVersion               func(context.Context, Principal, uuid.UUID) (Version, bool, error)
	findPolicySnapshot        func(context.Context, Principal, uuid.UUID) (PolicySnapshot, bool, error)
	listDefinitions           func(context.Context, Principal) ([]Definition, error)
	listVersions              func(context.Context, Principal, uuid.UUID) ([]Version, error)
	listWorkspaceDefinitions  func(context.Context, Principal, uuid.UUID) ([]Definition, error)
	listWorkspaceVersions     func(context.Context, Principal, uuid.UUID, uuid.UUID) ([]Version, error)
	appendRevocation          func(context.Context, Principal, VersionRevocationCommand) (VersionRevocation, error)
	recordDenied              func(context.Context, Principal, DeniedAuditCommand) error
	createPendingInstallation func(context.Context, Principal, CreateInstallationCommand) (InstallationCreation, error)
	findInstallation          func(context.Context, Principal, uuid.UUID) (Installation, bool, error)
	loadActivationContext     func(context.Context, Principal, uuid.UUID) (InstallationActivationContext, bool, error)
	activateInstallation      func(context.Context, Principal, ActivationCommand) (Installation, error)
	selectInstallationVersion func(context.Context, Principal, VersionSelectionCommand) (Installation, error)
	archiveInstallation       func(context.Context, Principal, ArchiveInstallationCommand) (Installation, error)
	insertRuntimeBinding      func(context.Context, Principal, PersistRuntimeBindingCommand) (RuntimeBindingRecord, error)
}

func (s *stubServiceRepository) PublishInitial(ctx context.Context, principal Principal, command InitialPublicationCommand) (Publication, error) {
	if s.publishInitial == nil {
		return Publication{}, errors.New("unexpected PublishInitial call")
	}
	return s.publishInitial(ctx, principal, command)
}

func (s *stubServiceRepository) PublishNext(ctx context.Context, principal Principal, command NextPublicationCommand) (Publication, error) {
	if s.publishNext == nil {
		return Publication{}, errors.New("unexpected PublishNext call")
	}
	return s.publishNext(ctx, principal, command)
}

func (s *stubServiceRepository) PublishWorkspaceInitial(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	command InitialPublicationCommand,
) (Publication, error) {
	if s.publishWorkspaceInitial == nil {
		return Publication{}, errors.New("unexpected PublishWorkspaceInitial call")
	}
	return s.publishWorkspaceInitial(ctx, principal, workspaceID, command)
}

func (s *stubServiceRepository) PublishWorkspaceNext(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	command NextPublicationCommand,
) (Publication, error) {
	if s.publishWorkspaceNext == nil {
		return Publication{}, errors.New("unexpected PublishWorkspaceNext call")
	}
	return s.publishWorkspaceNext(ctx, principal, workspaceID, command)
}

func (s *stubServiceRepository) FindDefinition(ctx context.Context, principal Principal, id uuid.UUID) (Definition, bool, error) {
	if s.findDefinition == nil {
		return Definition{}, false, errors.New("unexpected FindDefinition call")
	}
	return s.findDefinition(ctx, principal, id)
}

func (s *stubServiceRepository) FindWorkspaceDefinition(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	id uuid.UUID,
) (Definition, bool, error) {
	if s.findWorkspaceDefinition == nil {
		return Definition{}, false, errors.New("unexpected FindWorkspaceDefinition call")
	}
	return s.findWorkspaceDefinition(ctx, principal, workspaceID, id)
}

func (s *stubServiceRepository) FindVersion(ctx context.Context, principal Principal, id uuid.UUID) (Version, bool, error) {
	if s.findVersion == nil {
		return Version{}, false, errors.New("unexpected FindVersion call")
	}
	return s.findVersion(ctx, principal, id)
}

func (s *stubServiceRepository) FindPolicySnapshot(ctx context.Context, principal Principal, id uuid.UUID) (PolicySnapshot, bool, error) {
	if s.findPolicySnapshot == nil {
		return PolicySnapshot{}, false, errors.New("unexpected FindPolicySnapshot call")
	}
	return s.findPolicySnapshot(ctx, principal, id)
}

func (s *stubServiceRepository) ListDefinitions(ctx context.Context, principal Principal) ([]Definition, error) {
	if s.listDefinitions == nil {
		return nil, errors.New("unexpected ListDefinitions call")
	}
	return s.listDefinitions(ctx, principal)
}

func (s *stubServiceRepository) ListVersions(ctx context.Context, principal Principal, id uuid.UUID) ([]Version, error) {
	if s.listVersions == nil {
		return nil, errors.New("unexpected ListVersions call")
	}
	return s.listVersions(ctx, principal, id)
}

func (s *stubServiceRepository) ListWorkspaceDefinitions(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]Definition, error) {
	if s.listWorkspaceDefinitions == nil {
		return nil, errors.New("unexpected ListWorkspaceDefinitions call")
	}
	return s.listWorkspaceDefinitions(ctx, principal, workspaceID)
}

func (s *stubServiceRepository) ListWorkspaceVersions(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
) ([]Version, error) {
	if s.listWorkspaceVersions == nil {
		return nil, errors.New("unexpected ListWorkspaceVersions call")
	}
	return s.listWorkspaceVersions(ctx, principal, workspaceID, definitionID)
}

func (s *stubServiceRepository) AppendVersionRevocation(ctx context.Context, principal Principal, command VersionRevocationCommand) (VersionRevocation, error) {
	if s.appendRevocation == nil {
		return VersionRevocation{}, errors.New("unexpected AppendVersionRevocation call")
	}
	return s.appendRevocation(ctx, principal, command)
}

func (s *stubServiceRepository) RecordDenied(ctx context.Context, principal Principal, command DeniedAuditCommand) error {
	if s.recordDenied == nil {
		return nil
	}
	return s.recordDenied(ctx, principal, command)
}

func (s *stubServiceRepository) CreatePendingInstallation(ctx context.Context, principal Principal, command CreateInstallationCommand) (InstallationCreation, error) {
	if s.createPendingInstallation == nil {
		return InstallationCreation{}, errors.New("unexpected CreatePendingInstallation call")
	}
	return s.createPendingInstallation(ctx, principal, command)
}

func (s *stubServiceRepository) FindInstallation(ctx context.Context, principal Principal, id uuid.UUID) (Installation, bool, error) {
	if s.findInstallation == nil {
		return Installation{}, false, errors.New("unexpected FindInstallation call")
	}
	return s.findInstallation(ctx, principal, id)
}

func (s *stubServiceRepository) LoadActivationContext(ctx context.Context, principal Principal, id uuid.UUID) (InstallationActivationContext, bool, error) {
	if s.loadActivationContext == nil {
		return InstallationActivationContext{}, false, errors.New("unexpected LoadActivationContext call")
	}
	return s.loadActivationContext(ctx, principal, id)
}

func (s *stubServiceRepository) ActivateInstallation(ctx context.Context, principal Principal, command ActivationCommand) (Installation, error) {
	if s.activateInstallation == nil {
		return Installation{}, errors.New("unexpected ActivateInstallation call")
	}
	return s.activateInstallation(ctx, principal, command)
}

func (s *stubServiceRepository) SelectInstallationVersion(ctx context.Context, principal Principal, command VersionSelectionCommand) (Installation, error) {
	if s.selectInstallationVersion == nil {
		return Installation{}, errors.New("unexpected SelectInstallationVersion call")
	}
	return s.selectInstallationVersion(ctx, principal, command)
}

func (s *stubServiceRepository) ArchiveInstallation(ctx context.Context, principal Principal, command ArchiveInstallationCommand) (Installation, error) {
	if s.archiveInstallation == nil {
		return Installation{}, errors.New("unexpected ArchiveInstallation call")
	}
	return s.archiveInstallation(ctx, principal, command)
}

func (s *stubServiceRepository) InsertRuntimeBinding(ctx context.Context, principal Principal, command PersistRuntimeBindingCommand) (RuntimeBindingRecord, error) {
	if s.insertRuntimeBinding == nil {
		return RuntimeBindingRecord{}, errors.New("unexpected InsertRuntimeBinding call")
	}
	return s.insertRuntimeBinding(ctx, principal, command)
}

func publicationFromInitial(command InitialPublicationCommand, material VersionMaterial) Publication {
	latest := material.ID
	return Publication{
		Definition: Definition{
			ID: command.DefinitionID, DisplayName: command.DisplayName, IconMediaType: command.IconMediaType,
			IconData: command.IconData, Status: definitionStatusActive, LatestVersionID: &latest,
			CreatedAt: command.PublishedAt, UpdatedAt: command.PublishedAt,
		},
		Version: versionFromMaterial(command.DefinitionID, material, command.PublishedAt),
	}
}

func versionFromMaterial(definitionID uuid.UUID, material VersionMaterial, publishedAt time.Time) Version {
	return Version{
		ID: material.ID, DefinitionID: definitionID, VersionNumber: material.VersionNumber,
		CanonicalManifest: material.CanonicalManifest, Bundle: material.Bundle, ContentDigest: material.ContentDigest,
		SigningKeyID: material.SigningKeyID, Signature: material.Signature,
		RuntimeMinimumVersion:          material.RuntimeMinimumVersion,
		RuntimeMaximumVersionExclusive: material.RuntimeMaximumVersionExclusive, PublishedAt: publishedAt,
	}
}
