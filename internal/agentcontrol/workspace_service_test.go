package agentcontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServicePublishWorkspaceInitialCanonicalizesAndDispatchesExactWorkspace(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	manifest, bundle := validManifestFixture()
	workspaceID := uuid.New()
	var capturedWorkspaceID uuid.UUID
	var captured InitialPublicationCommand
	fixture.repository.publishWorkspaceInitial = func(
		_ context.Context,
		_ Principal,
		gotWorkspaceID uuid.UUID,
		command InitialPublicationCommand,
	) (Publication, error) {
		capturedWorkspaceID = gotWorkspaceID
		captured = command
		material, err := command.BuildVersion()
		if err != nil {
			return Publication{}, err
		}
		return publicationFromInitial(command, material), nil
	}

	result, err := fixture.service.PublishWorkspaceInitial(
		context.Background(),
		fixture.principal,
		workspaceID,
		PublishInitialRequest{
			DisplayName: "Workspace Research Agent", Manifest: manifest, Bundle: bundle,
			IdempotencyKey: "workspace-publish-one", RequestID: "workspace-request-1",
		},
	)
	if err != nil {
		t.Fatalf("PublishWorkspaceInitial() error = %v", err)
	}
	if capturedWorkspaceID != workspaceID || captured.DefinitionID == uuid.Nil || result.Version.ID == uuid.Nil {
		t.Fatalf("workspace publication dispatch = workspace:%s command:%+v result:%+v", capturedWorkspaceID, captured, result)
	}
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	if result.Version.ContentDigest != canonical.ContentDigest {
		t.Fatalf("content digest = %x, want %x", result.Version.ContentDigest, canonical.ContentDigest)
	}
}

func TestServicePublishWorkspaceInitialPreservesAuthorizationFailures(t *testing.T) {
	manifest, bundle := validManifestFixture()
	for name, expected := range map[string]error{
		"member":            ErrWorkspaceForbidden,
		"outsider":          ErrNotFound,
		"archived":          ErrWorkspaceArchived,
		"owner unavailable": ErrWorkspaceOwnerUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newAgentControlServiceFixture(t)
			fixture.repository.publishWorkspaceInitial = func(
				context.Context,
				Principal,
				uuid.UUID,
				InitialPublicationCommand,
			) (Publication, error) {
				return Publication{}, expected
			}
			_, err := fixture.service.PublishWorkspaceInitial(
				context.Background(), fixture.principal, uuid.New(),
				PublishInitialRequest{
					DisplayName: "Workspace Agent", Manifest: manifest, Bundle: bundle,
					IdempotencyKey: "workspace-permission-" + name, RequestID: "workspace-permission-request",
				},
			)
			if !errors.Is(err, expected) {
				t.Fatalf("PublishWorkspaceInitial() error = %v, want %v", err, expected)
			}
		})
	}
}

func TestServiceWorkspaceDiscoveryUsesExactWorkspaceAndDetachesValues(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	workspaceID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	latest := versionID
	icon := []byte{1, 2, 3}
	bundle := []byte(`{"assets":[]}`)
	fixture.repository.listWorkspaceDefinitions = func(
		_ context.Context,
		_ Principal,
		gotWorkspaceID uuid.UUID,
	) ([]Definition, error) {
		if gotWorkspaceID != workspaceID {
			t.Fatalf("workspace ID = %s, want %s", gotWorkspaceID, workspaceID)
		}
		return []Definition{{
			ID: definitionID, DisplayName: "Workspace Agent", IconData: icon,
			Status: definitionStatusActive, LatestVersionID: &latest,
		}}, nil
	}
	fixture.repository.listWorkspaceVersions = func(
		_ context.Context,
		_ Principal,
		gotWorkspaceID uuid.UUID,
		gotDefinitionID uuid.UUID,
	) ([]Version, error) {
		if gotWorkspaceID != workspaceID || gotDefinitionID != definitionID {
			t.Fatalf("workspace/definition = %s/%s", gotWorkspaceID, gotDefinitionID)
		}
		return []Version{{
			ID: versionID, DefinitionID: definitionID, VersionNumber: 1, Bundle: bundle,
		}}, nil
	}

	definitions, err := fixture.service.ListWorkspaceDefinitions(context.Background(), fixture.principal, workspaceID)
	if err != nil {
		t.Fatalf("ListWorkspaceDefinitions() error = %v", err)
	}
	versions, err := fixture.service.ListWorkspaceVersions(
		context.Background(), fixture.principal, workspaceID, definitionID, "workspace-list-request",
	)
	if err != nil {
		t.Fatalf("ListWorkspaceVersions() error = %v", err)
	}
	definitions[0].IconData[0] = 9
	versions[0].Bundle[0] = '['
	if icon[0] != 1 || bundle[0] != '{' {
		t.Fatal("Workspace discovery returned repository-owned byte aliases")
	}
}

func TestServiceCreateInstallationBindsWorkspaceSourceIntoRequestHashAndCommand(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	workspaceID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	var captured CreateInstallationCommand
	fixture.repository.createPendingInstallation = func(
		_ context.Context,
		_ Principal,
		command CreateInstallationCommand,
	) (InstallationCreation, error) {
		captured = command
		return InstallationCreation{Installation: Installation{
			ID: command.InstallationID, DefinitionID: command.DefinitionID,
			SelectedVersionID: command.VersionID, Status: InstallationStatusPending,
		}}, nil
	}

	_, err := fixture.service.CreateInstallation(context.Background(), fixture.principal, CreateInstallationRequest{
		DefinitionID: definitionID, VersionID: versionID, SourceWorkspaceID: &workspaceID,
		IdempotencyKey: "workspace-install", RequestID: "workspace-install-request",
	})
	if err != nil {
		t.Fatalf("CreateInstallation() error = %v", err)
	}
	if captured.SourceWorkspaceID == nil || *captured.SourceWorkspaceID != workspaceID {
		t.Fatalf("SourceWorkspaceID = %v, want %s", captured.SourceWorkspaceID, workspaceID)
	}
	workspaceRequestHash := captured.Idempotency.RequestHash

	_, err = fixture.service.CreateInstallation(context.Background(), fixture.principal, CreateInstallationRequest{
		DefinitionID: definitionID, VersionID: versionID,
		IdempotencyKey: "user-install", RequestID: "user-install-request",
	})
	if err != nil {
		t.Fatalf("CreateInstallation(USER) error = %v", err)
	}
	if captured.SourceWorkspaceID != nil {
		t.Fatalf("USER SourceWorkspaceID = %v, want nil", captured.SourceWorkspaceID)
	}
	if captured.Idempotency.RequestHash == workspaceRequestHash {
		t.Fatal("Workspace source was absent from the idempotency request hash")
	}
}
