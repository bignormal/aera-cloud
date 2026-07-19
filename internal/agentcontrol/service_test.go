package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
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
	latest := versionID
	fixture.repository.listDefinitions = func(context.Context, Principal) ([]Definition, error) {
		return []Definition{{ID: definitionID, DisplayName: "Agent", IconData: icon, Status: definitionStatusActive, LatestVersionID: &latest}}, nil
	}
	fixture.repository.findDefinition = func(context.Context, Principal, uuid.UUID) (Definition, bool, error) {
		return Definition{}, false, nil
	}
	fixture.repository.findVersion = func(context.Context, Principal, uuid.UUID) (Version, bool, error) {
		return Version{ID: versionID, DefinitionID: definitionID, VersionNumber: 1, Bundle: bundle, Signature: signature}, true, nil
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
	definitions[0].IconData[0] = 9
	versions[0].Bundle[0] = 9
	versions[0].Signature[0] = 9
	version.Bundle[0] = 8
	version.Signature[0] = 8
	if icon[0] != 1 || bundle[0] != '{' || signature[0] != 7 {
		t.Fatal("list response aliases repository-owned data")
	}

	missingID := uuid.New()
	if _, err := fixture.service.GetDefinition(context.Background(), fixture.principal, missingID, "request-7"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDefinition(cross owner) error = %v", err)
	}
	if denied.ObjectID != missingID || denied.ObjectType != "agent_definition" || denied.ReasonCode != "not_found" {
		t.Fatalf("denied audit = %+v", denied)
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
	publishInitial   func(context.Context, Principal, InitialPublicationCommand) (Publication, error)
	publishNext      func(context.Context, Principal, NextPublicationCommand) (Publication, error)
	findDefinition   func(context.Context, Principal, uuid.UUID) (Definition, bool, error)
	findVersion      func(context.Context, Principal, uuid.UUID) (Version, bool, error)
	listDefinitions  func(context.Context, Principal) ([]Definition, error)
	listVersions     func(context.Context, Principal, uuid.UUID) ([]Version, error)
	appendRevocation func(context.Context, Principal, VersionRevocationCommand) (VersionRevocation, error)
	recordDenied     func(context.Context, Principal, DeniedAuditCommand) error
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

func (s *stubServiceRepository) FindDefinition(ctx context.Context, principal Principal, id uuid.UUID) (Definition, bool, error) {
	if s.findDefinition == nil {
		return Definition{}, false, errors.New("unexpected FindDefinition call")
	}
	return s.findDefinition(ctx, principal, id)
}

func (s *stubServiceRepository) FindVersion(ctx context.Context, principal Principal, id uuid.UUID) (Version, bool, error) {
	if s.findVersion == nil {
		return Version{}, false, errors.New("unexpected FindVersion call")
	}
	return s.findVersion(ctx, principal, id)
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
