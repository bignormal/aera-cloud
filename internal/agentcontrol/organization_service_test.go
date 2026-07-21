package agentcontrol

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
)

func TestServiceOrganizationDiscoveryUsesExactScopeAndDetachesValues(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	organizationID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	latest := versionID
	icon := []byte{1, 2, 3}
	bundle := []byte(`{"assets":[]}`)
	fixture.repository.listOrganizationDefinitions = func(
		_ context.Context,
		_ Principal,
		gotOrganizationID uuid.UUID,
	) ([]Definition, error) {
		if gotOrganizationID != organizationID {
			t.Fatalf("Organization ID = %s, want %s", gotOrganizationID, organizationID)
		}
		return []Definition{{
			ID: definitionID, DisplayName: "Organization Agent", IconData: icon,
			Status: definitionStatusActive, LatestVersionID: &latest,
		}}, nil
	}
	fixture.repository.findOrganizationDefinition = func(
		_ context.Context,
		_ Principal,
		gotOrganizationID uuid.UUID,
		gotDefinitionID uuid.UUID,
	) (Definition, bool, error) {
		return Definition{ID: gotDefinitionID, IconData: icon},
			gotOrganizationID == organizationID && gotDefinitionID == definitionID, nil
	}
	fixture.repository.listOrganizationVersions = func(
		_ context.Context,
		_ Principal,
		gotOrganizationID uuid.UUID,
		gotDefinitionID uuid.UUID,
	) ([]Version, error) {
		if gotOrganizationID != organizationID || gotDefinitionID != definitionID {
			t.Fatalf("Organization/Definition = %s/%s", gotOrganizationID, gotDefinitionID)
		}
		return []Version{{ID: versionID, DefinitionID: definitionID, Bundle: bundle}}, nil
	}

	definitions, err := fixture.service.ListOrganizationDefinitions(
		context.Background(), fixture.principal, organizationID,
	)
	if err != nil {
		t.Fatalf("ListOrganizationDefinitions() error = %v", err)
	}
	detail, err := fixture.service.GetOrganizationDefinition(
		context.Background(), fixture.principal, organizationID, definitionID, "organization-get-definition",
	)
	if err != nil {
		t.Fatalf("GetOrganizationDefinition() error = %v", err)
	}
	versions, err := fixture.service.ListOrganizationVersions(
		context.Background(), fixture.principal, organizationID, definitionID, "organization-list-versions",
	)
	if err != nil {
		t.Fatalf("ListOrganizationVersions() error = %v", err)
	}
	definitions[0].IconData[0] = 9
	detail.IconData[0] = 8
	versions[0].Bundle[0] = '['
	if icon[0] != 1 || bundle[0] != '{' {
		t.Fatal("Organization discovery aliases repository storage")
	}
}

func TestServiceCreateInstallationBindsExclusiveOrganizationSourceAndNarrowedPolicy(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	organizationID := uuid.New()
	workspaceID := uuid.New()
	definitionID := uuid.New()
	version := policyVersionFixture(t, definitionID, uuid.New(), 1)
	var captured CreateInstallationCommand
	fixture.repository.createPendingInstallation = func(
		_ context.Context,
		_ Principal,
		command CreateInstallationCommand,
	) (InstallationCreation, error) {
		captured = command
		if command.BuildOrganizationPolicy == nil {
			t.Fatal("Organization policy builder is nil")
		}
		policy, err := command.BuildOrganizationPolicy(version, EffectiveOrganizationAgentPolicy{
			AgentPolicyConstraints: AgentPolicyConstraints{
				AllowedProviders: []string{"openai"}, AllowedModels: []string{"gpt-5.6"},
				AllowedTools: []string{"files.read"},
			},
			AllowedModelPairs: []organization.ModelIdentifier{{Provider: "openai", Model: "gpt-5.6"}},
		})
		if err != nil {
			return InstallationCreation{}, err
		}
		if !bytes.Contains(policy.Document, []byte(`"allowed_providers":["openai"]`)) ||
			!bytes.Contains(policy.Document, []byte(`"allowed":["files.read"]`)) {
			t.Fatalf("Organization policy was not narrowed: %s", policy.Document)
		}
		return InstallationCreation{Installation: Installation{
			ID: command.InstallationID, DefinitionID: command.DefinitionID,
			SelectedVersionID: command.VersionID, Status: InstallationStatusPending,
		}, Policy: PolicySnapshot{ID: policy.ID}}, nil
	}

	_, err := fixture.service.CreateInstallation(context.Background(), fixture.principal, CreateInstallationRequest{
		DefinitionID: definitionID, VersionID: version.ID, OrganizationID: &organizationID,
		IdempotencyKey: "organization-install", RequestID: "organization-install-request",
	})
	if err != nil {
		t.Fatalf("CreateInstallation(Organization) error = %v", err)
	}
	if captured.SourceOrganizationID == nil || *captured.SourceOrganizationID != organizationID ||
		captured.SourceWorkspaceID != nil {
		t.Fatalf("captured source = Workspace:%v Organization:%v", captured.SourceWorkspaceID, captured.SourceOrganizationID)
	}

	called := false
	fixture.repository.createPendingInstallation = func(
		context.Context,
		Principal,
		CreateInstallationCommand,
	) (InstallationCreation, error) {
		called = true
		return InstallationCreation{}, nil
	}
	if _, err := fixture.service.CreateInstallation(context.Background(), fixture.principal, CreateInstallationRequest{
		DefinitionID: definitionID, VersionID: version.ID,
		SourceWorkspaceID: &workspaceID, OrganizationID: &organizationID,
		IdempotencyKey: "ambiguous-install", RequestID: "ambiguous-install-request",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ambiguous source error = %v, want ErrInvalidRequest", err)
	}
	if called {
		t.Fatal("repository called for ambiguous installation source")
	}
}

func TestOrganizationPolicyDocumentRejectsCartesianModelBroadening(t *testing.T) {
	definitionID := uuid.New()
	version := policyVersionFixture(t, definitionID, uuid.New(), 1)
	_, err := policyDocumentForOrganizationVersion(version, EffectiveOrganizationAgentPolicy{
		AgentPolicyConstraints: AgentPolicyConstraints{
			AllowedProviders: []string{"anthropic", "openai"},
			AllowedModels:    []string{"claude-opus-5", "gpt-5.6"},
			AllowedTools:     []string{"files.read"},
		},
		AllowedModelPairs: []organization.ModelIdentifier{
			{Provider: "anthropic", Model: "claude-opus-5"},
			{Provider: "openai", Model: "gpt-5.6"},
		},
	})
	if !errors.Is(err, ErrOrganizationPublicationPolicyBlocked) {
		t.Fatalf("non-rectangular policy error = %v, want policy blocked", err)
	}
}

func TestOrganizationPolicyDocumentPreservesEmptyAllowedToolsArray(t *testing.T) {
	definitionID := uuid.New()
	version := policyVersionFixture(t, definitionID, uuid.New(), 1)
	document, err := policyDocumentForOrganizationVersion(version, EffectiveOrganizationAgentPolicy{
		AgentPolicyConstraints: AgentPolicyConstraints{
			AllowedProviders: []string{"openai"},
			AllowedModels:    []string{"gpt-5.6"},
			AllowedTools:     []string{},
		},
		AllowedModelPairs: []organization.ModelIdentifier{{Provider: "openai", Model: "gpt-5.6"}},
	})
	if err != nil {
		t.Fatalf("policyDocumentForOrganizationVersion() error = %v", err)
	}
	if !bytes.Contains(document, []byte(`"allowed":[]`)) {
		t.Fatalf("Organization policy document = %s, want an empty allowed tools array", document)
	}
}
