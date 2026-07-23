package officialquality

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/google/uuid"
)

func TestAgentControlDraftClonerCopiesVerifiedImmutableVersionFromDatabaseNormalizedJSON(t *testing.T) {
	manifest, bundle := qualityClonerManifest(t)
	canonical, err := agentcontrol.CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	platformID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	draftID := uuid.New()
	adminID := uuid.New()
	service := &platformDraftServiceStub{
		version: agentcontrol.Version{
			ID: versionID, DefinitionID: definitionID,
			CanonicalManifest: databaseNormalizedJSON(t, canonical.ManifestJSON),
			Bundle:            databaseNormalizedJSON(t, canonical.BundleJSON),
			ContentDigest:     canonical.ContentDigest,
		},
		definition: agentcontrol.PlatformDefinitionDetail{
			PlatformID: platformID,
			Definition: agentcontrol.Definition{ID: definitionID, DisplayName: "Official Research"},
		},
		drafts: agentcontrol.PlatformDraftPage{Items: []agentcontrol.PlatformAgentDraft{{
			ID: draftID, PlatformID: platformID, DefinitionID: definitionID,
			Kind: agentcontrol.PlatformDraftInitial, DisplayName: "Official Research",
			Manifest: manifest, Bundle: bundle, ContentDigest: canonical.ContentDigest,
			Revision: 4, Status: agentcontrol.PlatformDraftActive,
		}}},
	}
	cloner, err := NewAgentControlDraftCloner(service)
	if err != nil {
		t.Fatalf("NewAgentControlDraftCloner() error = %v", err)
	}

	result, err := cloner.CloneApprovedProposal(context.Background(), CloneApprovedProposalCommand{
		ProposalID: uuid.New(), PlatformID: platformID, DefinitionID: definitionID,
		BaseVersionID: versionID, ActorAdminID: adminID, ActorRole: QualityRoleDeveloper,
		RequestID: "req-quality-clone", IdempotencyKey: "quality-proposal-clone",
	})
	if err != nil || result != draftID {
		t.Fatalf("CloneApprovedProposal() = %s error=%v", result, err)
	}
	if service.updateCalls != 1 || service.update.Kind != agentcontrol.PlatformDraftNext ||
		service.update.BaseVersionID != versionID || service.update.ExpectedRevision != 4 ||
		service.update.DisplayName != "Official Research" ||
		service.update.Manifest.Identity.SystemPrompt != manifest.Identity.SystemPrompt ||
		service.update.Bundle.Assets[0].Content != bundle.Assets[0].Content {
		t.Fatalf("UpdateDraft() command = %+v calls=%d", service.update, service.updateCalls)
	}
}

func databaseNormalizedJSON(t *testing.T, canonical []byte) []byte {
	t.Helper()
	var normalized bytes.Buffer
	if err := json.Indent(&normalized, canonical, "", "  "); err != nil {
		t.Fatalf("normalize canonical JSON like PostgreSQL jsonb: %v", err)
	}
	if bytes.Equal(normalized.Bytes(), canonical) {
		t.Fatal("database-normalized JSON fixture must differ at the byte level")
	}
	return normalized.Bytes()
}

func TestAgentControlDraftClonerRefusesToOverwriteEditedDraft(t *testing.T) {
	manifest, bundle := qualityClonerManifest(t)
	canonical, err := agentcontrol.CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}
	platformID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	service := &platformDraftServiceStub{
		version: agentcontrol.Version{
			ID: versionID, DefinitionID: definitionID,
			CanonicalManifest: canonical.ManifestJSON, Bundle: canonical.BundleJSON,
			ContentDigest: canonical.ContentDigest,
		},
		definition: agentcontrol.PlatformDefinitionDetail{
			PlatformID: platformID,
			Definition: agentcontrol.Definition{ID: definitionID, DisplayName: "Official Research"},
		},
		drafts: agentcontrol.PlatformDraftPage{Items: []agentcontrol.PlatformAgentDraft{{
			ID: uuid.New(), PlatformID: platformID, DefinitionID: definitionID,
			ContentDigest: sha256.Sum256([]byte("edited-content")),
			Revision:      5, Status: agentcontrol.PlatformDraftActive,
		}}},
	}
	cloner, err := NewAgentControlDraftCloner(service)
	if err != nil {
		t.Fatalf("NewAgentControlDraftCloner() error = %v", err)
	}

	_, err = cloner.CloneApprovedProposal(context.Background(), CloneApprovedProposalCommand{
		ProposalID: uuid.New(), PlatformID: platformID, DefinitionID: definitionID,
		BaseVersionID: versionID, ActorAdminID: uuid.New(), ActorRole: QualityRoleDeveloper,
		RequestID: "req-quality-edited", IdempotencyKey: "quality-proposal-edited",
	})
	if err == nil || service.updateCalls != 0 {
		t.Fatalf("CloneApprovedProposal(edited) error=%v update_calls=%d", err, service.updateCalls)
	}
}

type platformDraftServiceStub struct {
	version     agentcontrol.Version
	definition  agentcontrol.PlatformDefinitionDetail
	drafts      agentcontrol.PlatformDraftPage
	update      agentcontrol.UpdatePlatformDraftCommand
	updateCalls int
}

func (stub *platformDraftServiceStub) GetVersion(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.Version, error) {
	return stub.version, nil
}

func (stub *platformDraftServiceStub) GetDefinition(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.PlatformDefinitionDetail, error) {
	return stub.definition, nil
}

func (stub *platformDraftServiceStub) ListDrafts(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.PageRequest) (agentcontrol.PlatformDraftPage, error) {
	return stub.drafts, nil
}

func (stub *platformDraftServiceStub) UpdateDraft(_ context.Context, _ agentcontrol.PlatformAdminActor, command agentcontrol.UpdatePlatformDraftCommand) (agentcontrol.PlatformAgentDraft, error) {
	stub.updateCalls++
	stub.update = command
	return agentcontrol.PlatformAgentDraft{ID: command.DraftID}, nil
}

func qualityClonerManifest(t *testing.T) (agentcontrol.AgentManifestV1, agentcontrol.VersionBundleV1) {
	t.Helper()
	content := "Use the approved public research procedure."
	digest := sha256.Sum256([]byte(content))
	return agentcontrol.AgentManifestV1{
			SchemaVersion: 1,
			Identity:      agentcontrol.AgentIdentityV1{SystemPrompt: "Perform careful public research."},
			ModelConstraints: agentcontrol.ModelConstraintsV1{
				AllowedProviders: []string{"openai"}, AllowedModels: []string{"gpt-5"},
			},
			Tools:        agentcontrol.ToolPolicyV1{Allowed: []string{}, Denied: []string{}},
			Dependencies: []agentcontrol.AgentDependencyV1{},
			Assets: []agentcontrol.ManifestAssetV1{{
				Path: "knowledge/research.md", Kind: agentcontrol.AssetKindKnowledge,
				MediaType: "text/markdown", SHA256: stringHex(digest[:]),
			}},
			RuntimeCompatibility: agentcontrol.RuntimeCompatibilityV1{MinimumVersion: "1.0.0"},
		}, agentcontrol.VersionBundleV1{Assets: []agentcontrol.BundleAssetV1{{
			Path: "knowledge/research.md", Content: content,
		}}}
}

func stringHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&0x0f]
	}
	return string(result)
}
