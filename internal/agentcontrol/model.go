package agentcontrol

import (
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

const (
	MaxAssetCount    = 128
	MaxAssetBytes    = 256 * 1024
	MaxBundleBytes   = 2 * 1024 * 1024
	MaxManifestBytes = 256 * 1024
	MaxIconBytes     = 512 * 1024
	MaxIconDimension = 1024
)

var (
	ErrInvalidAgentContent = errors.New("Agent content is invalid")
	ErrInvalidSignature    = errors.New("Agent signature is invalid")
	ErrRuntimeIncompatible = errors.New("Agent Runtime compatibility is invalid")
)

type OwnerScope string

const (
	OwnerScopeUser         OwnerScope = "USER"
	OwnerScopeWorkspace    OwnerScope = "WORKSPACE"
	OwnerScopeOrganization OwnerScope = "ORGANIZATION"
	OwnerScopePlatform     OwnerScope = "PLATFORM"
)

type AssetOwner struct {
	Scope           OwnerScope
	PersonalSpaceID uuid.UUID
	UserID          uuid.UUID
	WorkspaceID     uuid.UUID
	OrganizationID  uuid.UUID
	PlatformID      uuid.UUID
}

func (o AssetOwner) Validate() error {
	switch o.Scope {
	case OwnerScopeUser:
		if o.PersonalSpaceID == uuid.Nil || o.UserID == uuid.Nil ||
			o.WorkspaceID != uuid.Nil || o.OrganizationID != uuid.Nil || o.PlatformID != uuid.Nil {
			return ErrInvalidAgentContent
		}
	case OwnerScopeWorkspace:
		if o.PersonalSpaceID != uuid.Nil || o.UserID != uuid.Nil ||
			o.WorkspaceID == uuid.Nil || o.OrganizationID != uuid.Nil || o.PlatformID != uuid.Nil {
			return ErrInvalidAgentContent
		}
	case OwnerScopeOrganization:
		if o.PersonalSpaceID != uuid.Nil || o.UserID != uuid.Nil ||
			o.WorkspaceID != uuid.Nil || o.OrganizationID == uuid.Nil || o.PlatformID != uuid.Nil {
			return ErrInvalidAgentContent
		}
	case OwnerScopePlatform:
		if o.PersonalSpaceID != uuid.Nil || o.UserID != uuid.Nil ||
			o.WorkspaceID != uuid.Nil || o.OrganizationID != uuid.Nil || o.PlatformID == uuid.Nil {
			return ErrInvalidAgentContent
		}
	default:
		return ErrInvalidAgentContent
	}
	return nil
}

func (o AssetOwner) Key() uuid.UUID {
	switch o.Scope {
	case OwnerScopeWorkspace:
		return o.WorkspaceID
	case OwnerScopeOrganization:
		return o.OrganizationID
	case OwnerScopePlatform:
		return o.PlatformID
	default:
		return o.UserID
	}
}

type Owner struct {
	TenantID uuid.UUID
	Scope    OwnerScope
	OwnerID  uuid.UUID
}

type AssetKind string

const (
	AssetKindSkill     AssetKind = "skill"
	AssetKindSOP       AssetKind = "sop"
	AssetKindKnowledge AssetKind = "knowledge"
)

type MediaType string

const (
	MediaTypeTextMarkdown MediaType = "text/markdown"
	MediaTypeTextPlain    MediaType = "text/plain"
)

type AgentManifest struct {
	SchemaVersion        int                    `json:"schema_version"`
	Identity             AgentIdentityV1        `json:"identity"`
	Assets               []ManifestAssetV1      `json:"assets"`
	ModelConstraints     ModelConstraintsV1     `json:"-"`
	ModelPolicy          ModelPolicyV2          `json:"-"`
	Tools                ToolPolicyV1           `json:"tools"`
	Dependencies         []AgentDependencyV1    `json:"dependencies"`
	RuntimeCompatibility RuntimeCompatibilityV1 `json:"runtime_compatibility"`
}

// AgentManifestV1 remains an alias so existing V1 call sites and fixtures keep
// their source compatibility while the wire decoder accepts both immutable
// manifest schema versions.
type AgentManifestV1 = AgentManifest

type AgentIdentityV1 struct {
	SystemPrompt string `json:"system_prompt"`
}

type ManifestAssetV1 struct {
	Path      string    `json:"path"`
	Kind      AssetKind `json:"kind"`
	MediaType MediaType `json:"media_type"`
	SHA256    string    `json:"sha256"`
}

type ModelConstraintsV1 struct {
	AllowedProviders []string `json:"allowed_providers"`
	AllowedModels    []string `json:"allowed_models"`
}

type ModelSelectionMode string

const (
	ModelSelectionUserSelect ModelSelectionMode = "user_select"
	ModelSelectionAllowlist  ModelSelectionMode = "allowlist"
	ModelSelectionFixed      ModelSelectionMode = "fixed"
)

type ModelPolicyV2 struct {
	Mode             ModelSelectionMode `json:"mode"`
	AllowedProviders []string           `json:"allowed_providers"`
	AllowedModels    []string           `json:"allowed_models"`
}

type agentManifestV1Wire struct {
	SchemaVersion        int                    `json:"schema_version"`
	Identity             AgentIdentityV1        `json:"identity"`
	Assets               []ManifestAssetV1      `json:"assets"`
	ModelConstraints     ModelConstraintsV1     `json:"model_constraints"`
	Tools                ToolPolicyV1           `json:"tools"`
	Dependencies         []AgentDependencyV1    `json:"dependencies"`
	RuntimeCompatibility RuntimeCompatibilityV1 `json:"runtime_compatibility"`
}

type agentManifestV2Wire struct {
	SchemaVersion        int                    `json:"schema_version"`
	Identity             AgentIdentityV1        `json:"identity"`
	Assets               []ManifestAssetV1      `json:"assets"`
	ModelPolicy          ModelPolicyV2          `json:"model_policy"`
	Tools                ToolPolicyV1           `json:"tools"`
	Dependencies         []AgentDependencyV1    `json:"dependencies"`
	RuntimeCompatibility RuntimeCompatibilityV1 `json:"runtime_compatibility"`
}

func (manifest AgentManifest) MarshalJSON() ([]byte, error) {
	switch manifest.SchemaVersion {
	case 0, 1:
		return json.Marshal(agentManifestV1Wire{
			SchemaVersion: manifest.SchemaVersion, Identity: manifest.Identity, Assets: manifest.Assets,
			ModelConstraints: manifest.ModelConstraints, Tools: manifest.Tools, Dependencies: manifest.Dependencies,
			RuntimeCompatibility: manifest.RuntimeCompatibility,
		})
	case 2:
		return json.Marshal(agentManifestV2Wire{
			SchemaVersion: manifest.SchemaVersion, Identity: manifest.Identity, Assets: manifest.Assets,
			ModelPolicy: manifest.ModelPolicy, Tools: manifest.Tools, Dependencies: manifest.Dependencies,
			RuntimeCompatibility: manifest.RuntimeCompatibility,
		})
	default:
		return nil, errors.New("unsupported Agent manifest schema version")
	}
}

func (manifest *AgentManifest) UnmarshalJSON(raw []byte) error {
	if manifest == nil || rejectDuplicateJSONKeys(raw) != nil {
		return errors.New("invalid Agent manifest")
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return err
	}
	switch header.SchemaVersion {
	case 1:
		var value agentManifestV1Wire
		if err := decodeStrictJSON(raw, &value); err != nil {
			return err
		}
		*manifest = AgentManifest{
			SchemaVersion: value.SchemaVersion, Identity: value.Identity, Assets: value.Assets,
			ModelConstraints: value.ModelConstraints, Tools: value.Tools, Dependencies: value.Dependencies,
			RuntimeCompatibility: value.RuntimeCompatibility,
		}
		return nil
	case 2:
		var value agentManifestV2Wire
		if err := decodeStrictJSON(raw, &value); err != nil {
			return err
		}
		*manifest = AgentManifest{
			SchemaVersion: value.SchemaVersion, Identity: value.Identity, Assets: value.Assets,
			ModelPolicy: value.ModelPolicy, Tools: value.Tools, Dependencies: value.Dependencies,
			RuntimeCompatibility: value.RuntimeCompatibility,
		}
		return nil
	default:
		return errors.New("unsupported Agent manifest schema version")
	}
}

type ToolPolicyV1 struct {
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

type AgentDependencyV1 struct {
	AgentDefinitionID uuid.UUID `json:"agent_definition_id"`
	AgentVersionID    uuid.UUID `json:"agent_version_id"`
}

type RuntimeCompatibilityV1 struct {
	MinimumVersion          string `json:"minimum_version"`
	MaximumVersionExclusive string `json:"maximum_version_exclusive,omitempty"`
}

type VersionBundleV1 struct {
	Assets []BundleAssetV1 `json:"assets"`
}

type BundleAssetV1 struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type CanonicalVersion struct {
	ManifestJSON   []byte
	BundleJSON     []byte
	ManifestDigest [32]byte
	BundleDigest   [32]byte
	ContentDigest  [32]byte
}
