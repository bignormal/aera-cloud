package agentcontrol

import (
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
)

type AssetOwner struct {
	Scope           OwnerScope
	PersonalSpaceID uuid.UUID
	UserID          uuid.UUID
	WorkspaceID     uuid.UUID
	OrganizationID  uuid.UUID
}

func (o AssetOwner) Validate() error {
	switch o.Scope {
	case OwnerScopeUser:
		if o.PersonalSpaceID == uuid.Nil || o.UserID == uuid.Nil ||
			o.WorkspaceID != uuid.Nil || o.OrganizationID != uuid.Nil {
			return ErrInvalidAgentContent
		}
	case OwnerScopeWorkspace:
		if o.PersonalSpaceID != uuid.Nil || o.UserID != uuid.Nil ||
			o.WorkspaceID == uuid.Nil || o.OrganizationID != uuid.Nil {
			return ErrInvalidAgentContent
		}
	case OwnerScopeOrganization:
		if o.PersonalSpaceID != uuid.Nil || o.UserID != uuid.Nil ||
			o.WorkspaceID != uuid.Nil || o.OrganizationID == uuid.Nil {
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

type AgentManifestV1 struct {
	SchemaVersion        int                    `json:"schema_version"`
	Identity             AgentIdentityV1        `json:"identity"`
	Assets               []ManifestAssetV1      `json:"assets"`
	ModelConstraints     ModelConstraintsV1     `json:"model_constraints"`
	Tools                ToolPolicyV1           `json:"tools"`
	Dependencies         []AgentDependencyV1    `json:"dependencies"`
	RuntimeCompatibility RuntimeCompatibilityV1 `json:"runtime_compatibility"`
}

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
