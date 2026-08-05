package agentcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
)

var ErrInvalidRequest = errors.New("Agent control request is invalid")

const idempotencyLifetime = 24 * time.Hour

type AgentPolicyConstraints struct {
	ModelMode        ModelSelectionMode
	AllowedProviders []string
	AllowedModels    []string
	AllowedTools     []string
}

type EffectiveOrganizationAgentPolicy struct {
	AgentPolicyConstraints
	AllowedModelPairs []organization.ModelIdentifier
}

func IntersectOrganizationAgentPolicy(
	platformPolicy organization.PolicyDocument,
	organizationPolicy organization.PolicyDocument,
	versionConstraints AgentPolicyConstraints,
) (EffectiveOrganizationAgentPolicy, error) {
	platform, err := organization.CanonicalizePolicy(platformPolicy)
	if err != nil {
		return EffectiveOrganizationAgentPolicy{}, ErrOrganizationPublicationPolicyBlocked
	}
	currentOrganization, err := organization.CanonicalizePolicy(organizationPolicy)
	if err != nil {
		return EffectiveOrganizationAgentPolicy{}, ErrOrganizationPublicationPolicyBlocked
	}
	mode := versionConstraints.ModelMode
	if mode == "" {
		mode = ModelSelectionAllowlist
	}
	providers, err := canonicalStringSet(versionConstraints.AllowedProviders, true)
	if err != nil {
		return EffectiveOrganizationAgentPolicy{}, ErrOrganizationPublicationPolicyBlocked
	}
	models, err := canonicalStringSet(versionConstraints.AllowedModels, true)
	if err != nil || !validModelPolicyV2(mode, providers, models) {
		return EffectiveOrganizationAgentPolicy{}, ErrOrganizationPublicationPolicyBlocked
	}
	tools, err := canonicalStringSet(versionConstraints.AllowedTools, true)
	if err != nil {
		return EffectiveOrganizationAgentPolicy{}, ErrOrganizationPublicationPolicyBlocked
	}

	pairs := make([]organization.ModelIdentifier, 0, len(providers)*len(models))
	providerSet := make(map[string]struct{}, len(providers))
	modelSet := make(map[string]struct{}, len(models))
	if mode == ModelSelectionUserSelect {
		pairs = intersectOrganizationModelAllowlists(
			platform.Document.Models.Allowlist,
			currentOrganization.Document.Models.Allowlist,
		)
		for _, pair := range pairs {
			providerSet[pair.Provider] = struct{}{}
			modelSet[pair.Model] = struct{}{}
		}
		if pairs != nil {
			mode = ModelSelectionAllowlist
		}
	} else {
		for _, provider := range providers {
			for _, model := range models {
				pair := organization.ModelIdentifier{Provider: provider, Model: model}
				if !modelPairAllowed(pair, platform.Document.Models.Allowlist) ||
					!modelPairAllowed(pair, currentOrganization.Document.Models.Allowlist) {
					continue
				}
				pairs = append(pairs, pair)
				providerSet[provider] = struct{}{}
				modelSet[model] = struct{}{}
			}
		}
	}
	if mode != ModelSelectionUserSelect && len(pairs) == 0 {
		return EffectiveOrganizationAgentPolicy{}, ErrOrganizationPublicationPolicyBlocked
	}

	effectiveTools := organization.IntersectStringAllowlists(
		tools,
		platform.Document.Tools.Allowlist,
		currentOrganization.Document.Tools.Allowlist,
	)
	if len(tools) > 0 && len(effectiveTools) == 0 {
		return EffectiveOrganizationAgentPolicy{}, ErrOrganizationPublicationPolicyBlocked
	}

	return EffectiveOrganizationAgentPolicy{
		AgentPolicyConstraints: AgentPolicyConstraints{
			ModelMode:        mode,
			AllowedProviders: sortedPolicyKeys(providerSet),
			AllowedModels:    sortedPolicyKeys(modelSet),
			AllowedTools:     cloneOrganizationSlice(effectiveTools),
		},
		AllowedModelPairs: append([]organization.ModelIdentifier(nil), pairs...),
	}, nil
}

func intersectOrganizationModelAllowlists(
	left []organization.ModelIdentifier,
	right []organization.ModelIdentifier,
) []organization.ModelIdentifier {
	if left == nil && right == nil {
		return nil
	}
	candidates := left
	if candidates == nil {
		candidates = right
	}
	result := make([]organization.ModelIdentifier, 0, len(candidates))
	for _, pair := range candidates {
		if modelPairAllowed(pair, left) && modelPairAllowed(pair, right) {
			result = append(result, pair)
		}
	}
	return result
}

func agentPolicyConstraintsForManifest(manifest AgentManifest) AgentPolicyConstraints {
	constraints := AgentPolicyConstraints{AllowedTools: cloneOrganizationSlice(manifest.Tools.Allowed)}
	if manifest.SchemaVersion == 2 {
		constraints.ModelMode = manifest.ModelPolicy.Mode
		constraints.AllowedProviders = cloneOrganizationSlice(manifest.ModelPolicy.AllowedProviders)
		constraints.AllowedModels = cloneOrganizationSlice(manifest.ModelPolicy.AllowedModels)
		return constraints
	}
	constraints.AllowedProviders = cloneOrganizationSlice(manifest.ModelConstraints.AllowedProviders)
	constraints.AllowedModels = cloneOrganizationSlice(manifest.ModelConstraints.AllowedModels)
	return constraints
}

func effectiveOrganizationAgentPolicyForVersion(
	version Version,
	organizationPolicy organization.PolicyDocument,
) (EffectiveOrganizationAgentPolicy, error) {
	if version.ID == uuid.Nil || version.DefinitionID == uuid.Nil || zeroDigest(version.ContentDigest) {
		return EffectiveOrganizationAgentPolicy{}, ErrInvalidAgentContent
	}
	manifest, err := DecodeManifest(version.CanonicalManifest)
	if err != nil {
		return EffectiveOrganizationAgentPolicy{}, ErrInvalidAgentContent
	}
	bundle, err := DecodeBundle(version.Bundle)
	if err != nil {
		return EffectiveOrganizationAgentPolicy{}, ErrInvalidAgentContent
	}
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil || canonical.ContentDigest != version.ContentDigest {
		return EffectiveOrganizationAgentPolicy{}, ErrInvalidAgentContent
	}
	effective, err := IntersectOrganizationAgentPolicy(
		organization.DefaultPolicyDocument(),
		organizationPolicy,
		agentPolicyConstraintsForManifest(manifest),
	)
	if err != nil {
		return EffectiveOrganizationAgentPolicy{}, err
	}
	return effective, nil
}

func modelPairAllowed(pair organization.ModelIdentifier, allowlist []organization.ModelIdentifier) bool {
	if allowlist == nil {
		return true
	}
	for _, allowed := range allowlist {
		if allowed == pair {
			return true
		}
	}
	return false
}

func sortedPolicyKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

type ServiceRepository interface {
	PublishInitial(context.Context, Principal, InitialPublicationCommand) (Publication, error)
	PublishNext(context.Context, Principal, NextPublicationCommand) (Publication, error)
	PublishWorkspaceInitial(context.Context, Principal, uuid.UUID, InitialPublicationCommand) (Publication, error)
	PublishWorkspaceNext(context.Context, Principal, uuid.UUID, NextPublicationCommand) (Publication, error)
	FindDefinition(context.Context, Principal, uuid.UUID) (Definition, bool, error)
	FindWorkspaceDefinition(context.Context, Principal, uuid.UUID, uuid.UUID) (Definition, bool, error)
	FindOrganizationDefinition(context.Context, Principal, uuid.UUID, uuid.UUID) (Definition, bool, error)
	FindVersion(context.Context, Principal, uuid.UUID) (Version, bool, error)
	FindPolicySnapshot(context.Context, Principal, uuid.UUID) (PolicySnapshot, bool, error)
	ListDefinitions(context.Context, Principal) ([]Definition, error)
	ListVersions(context.Context, Principal, uuid.UUID) ([]Version, error)
	ListWorkspaceDefinitions(context.Context, Principal, uuid.UUID) ([]Definition, error)
	ListWorkspaceVersions(context.Context, Principal, uuid.UUID, uuid.UUID) ([]Version, error)
	ListOrganizationDefinitions(context.Context, Principal, uuid.UUID) ([]Definition, error)
	ListOrganizationVersions(context.Context, Principal, uuid.UUID, uuid.UUID) ([]Version, error)
	AppendVersionRevocation(context.Context, Principal, VersionRevocationCommand) (VersionRevocation, error)
	RecordDenied(context.Context, Principal, DeniedAuditCommand) error
	CreatePendingInstallation(context.Context, Principal, CreateInstallationCommand) (InstallationCreation, error)
	FindInstallation(context.Context, Principal, uuid.UUID) (Installation, bool, error)
	LoadActivationContext(context.Context, Principal, uuid.UUID) (InstallationActivationContext, bool, error)
	ActivateInstallation(context.Context, Principal, ActivationCommand) (Installation, error)
	SelectInstallationVersion(context.Context, Principal, VersionSelectionCommand) (Installation, error)
	ApplyManagedOfficialSelection(context.Context, Principal, ManagedOfficialSelectionCommand) (Installation, error)
	ArchiveInstallation(context.Context, Principal, ArchiveInstallationCommand) (Installation, error)
	InsertRuntimeBinding(context.Context, Principal, PersistRuntimeBindingCommand) (RuntimeBindingRecord, error)
	SubmitExperienceCandidate(context.Context, Principal, SubmitExperienceCandidateCommand) (ExperienceCandidate, bool, error)
	ListOwnExperienceCandidates(context.Context, Principal, uuid.UUID) ([]ExperienceCandidate, error)
	ListWorkspaceExperienceCandidates(context.Context, Principal, uuid.UUID) ([]ExperienceCandidate, error)
	FindExperienceCandidate(context.Context, Principal, uuid.UUID, uuid.UUID, AuditEvidence, time.Time) (ExperienceCandidate, bool, error)
	ReviewExperienceCandidate(context.Context, Principal, ReviewExperienceCandidateCommand) (ExperienceCandidate, bool, error)
	SubmitOrganizationExperienceCandidate(context.Context, Principal, SubmitOrganizationExperienceCandidateCommand) (OrganizationExperienceCandidate, bool, error)
	ListOwnOrganizationExperienceCandidates(context.Context, Principal, uuid.UUID) ([]OrganizationExperienceCandidate, error)
	ListOrganizationExperienceCandidates(context.Context, Principal, uuid.UUID) ([]OrganizationExperienceCandidate, error)
	FindOrganizationExperienceCandidate(context.Context, Principal, uuid.UUID, uuid.UUID, AuditEvidence, time.Time) (OrganizationExperienceCandidate, bool, error)
	ReviewOrganizationExperienceCandidate(context.Context, Principal, ReviewOrganizationExperienceCandidateCommand) (OrganizationExperienceCandidate, bool, error)
	SubmitOrganizationAgent(context.Context, SubmitOrganizationAgentCommand) (OrganizationAgentSubmission, error)
	ListOrganizationAgentSubmissions(context.Context, Principal, uuid.UUID) ([]OrganizationAgentSubmission, error)
	FindOrganizationAgentSubmission(context.Context, Principal, uuid.UUID, uuid.UUID) (OrganizationAgentSubmission, bool, error)
	WithdrawOrganizationAgentSubmission(context.Context, WithdrawOrganizationAgentCommand) (OrganizationAgentSubmission, error)
	ReviewOrganizationAgentSubmission(context.Context, ReviewOrganizationAgentCommand) (OrganizationAgentSubmission, error)
}

type OfficialEligibilityEvaluator interface {
	GetOfficialAgent(context.Context, Principal, uuid.UUID, OfficialEligibilityContext) (OfficialAgentCatalogEntry, error)
	ResolveOfficialReleaseRevision(context.Context, Principal, uuid.UUID, uuid.UUID, OfficialEligibilityContext) (OfficialManagedTarget, error)
	EvaluateOfficialEligibilityRecord(Principal, OfficialEligibilityContext, OfficialEligibilityRecord, bool) (OfficialManagedTarget, error)
}

type ServiceConfig struct {
	Repository          ServiceRepository
	Signer              *Signer
	OfficialEligibility OfficialEligibilityEvaluator
	Clock               func() time.Time
	NewID               func() uuid.UUID
}

type Service struct {
	repository          ServiceRepository
	signer              *Signer
	officialEligibility OfficialEligibilityEvaluator
	clock               func() time.Time
	newID               func() uuid.UUID
}

type PublishInitialRequest struct {
	DisplayName    string
	IconMediaType  string
	IconData       []byte
	Manifest       AgentManifestV1
	Bundle         VersionBundleV1
	IdempotencyKey string
	RequestID      string
}

type PublishNextRequest struct {
	DefinitionID   uuid.UUID
	BaseVersionID  uuid.UUID
	DisplayName    *string
	Manifest       AgentManifestV1
	Bundle         VersionBundleV1
	IdempotencyKey string
	RequestID      string
}

type RevokeVersionRequest struct {
	VersionID            uuid.UUID
	ReasonCode           string
	PolicySnapshotID     uuid.UUID
	SupersedingVersionID *uuid.UUID
	IdempotencyKey       string
	RequestID            string
}

type CreateInstallationRequest struct {
	DefinitionID              uuid.UUID
	VersionID                 uuid.UUID
	SourceWorkspaceID         *uuid.UUID
	OrganizationID            *uuid.UUID
	OfficialReleaseRevisionID *uuid.UUID
	OfficialContext           *OfficialEligibilityContext
	IdempotencyKey            string
	RequestID                 string
}

type ActivateInstallationRequest struct {
	InstallationID   uuid.UUID
	RuntimeProfileID uuid.UUID
	VersionDigest    [sha256.Size]byte
	Timestamp        int64
	DeviceProof      []byte
	RequestID        string
}

type SelectInstallationVersionRequest struct {
	InstallationID uuid.UUID
	VersionID      uuid.UUID
	RequestID      string
}

type GetManagedOfficialUpdateRequest struct {
	InstallationID  uuid.UUID
	OfficialContext OfficialEligibilityContext
	RequestID       string
}

type ManagedUpdateRequest struct {
	InstallationID             uuid.UUID
	ExpectedSelectedRevisionID uuid.UUID
	TargetReleaseRevisionID    uuid.UUID
	OfficialContext            OfficialEligibilityContext
	RequestID                  string
}

type ArchiveInstallationRequest struct {
	InstallationID uuid.UUID
	RequestID      string
}

type DeniedAuditCommand struct {
	EventID    uuid.UUID
	ObjectType string
	ObjectID   uuid.UUID
	ReasonCode string
	RequestID  string
	OccurredAt time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.Signer == nil {
		return nil, errors.New("Agent control service configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	newID := config.NewID
	if newID == nil {
		newID = uuid.New
	}
	return &Service{
		repository: config.Repository, signer: config.Signer,
		officialEligibility: config.OfficialEligibility, clock: clock, newID: newID,
	}, nil
}

func (s *Service) PublishInitial(
	ctx context.Context,
	principal Principal,
	request PublishInitialRequest,
) (Publication, error) {
	return s.publishInitial(ctx, principal, nil, request, s.repository.PublishInitial)
}

func (s *Service) PublishWorkspaceInitial(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	request PublishInitialRequest,
) (Publication, error) {
	if workspaceID == uuid.Nil {
		return Publication{}, ErrInvalidRequest
	}
	return s.publishInitial(
		ctx,
		principal,
		&workspaceID,
		request,
		func(ctx context.Context, principal Principal, command InitialPublicationCommand) (Publication, error) {
			return s.repository.PublishWorkspaceInitial(ctx, principal, workspaceID, command)
		},
	)
}

func (s *Service) publishInitial(
	ctx context.Context,
	principal Principal,
	workspaceID *uuid.UUID,
	request PublishInitialRequest,
	publish func(context.Context, Principal, InitialPublicationCommand) (Publication, error),
) (Publication, error) {
	if s == nil || !validPrincipal(principal) ||
		publish == nil || !validPublicationEnvelope(request.DisplayName, request.IdempotencyKey, request.RequestID) {
		return Publication{}, ErrInvalidRequest
	}
	if (request.IconMediaType == "") != (len(request.IconData) == 0) ||
		(request.IconMediaType != "" && ValidateIcon(request.IconMediaType, request.IconData) != nil) {
		return Publication{}, ErrInvalidAgentContent
	}
	canonical, minimum, maximum, err := canonicalizePublication(request.Manifest, request.Bundle)
	if err != nil {
		return Publication{}, err
	}
	requestHash, err := hashRequest(struct {
		Operation     string          `json:"operation"`
		DisplayName   string          `json:"display_name"`
		IconMediaType string          `json:"icon_media_type"`
		IconDigest    string          `json:"icon_digest"`
		Manifest      json.RawMessage `json:"manifest"`
		Bundle        json.RawMessage `json:"bundle"`
		WorkspaceID   *string         `json:"workspace_id,omitempty"`
	}{
		Operation: operationPublishInitial, DisplayName: request.DisplayName, IconMediaType: request.IconMediaType,
		IconDigest: digestHex(request.IconData), Manifest: canonical.ManifestJSON, Bundle: canonical.BundleJSON,
		WorkspaceID: uuidStringPointer(workspaceID),
	})
	if err != nil {
		return Publication{}, ErrInvalidAgentContent
	}
	now := s.clock().UTC()
	definitionID, versionID, idempotencyID, auditID := s.newID(), s.newID(), s.newID(), s.newID()
	if definitionID == uuid.Nil || versionID == uuid.Nil || idempotencyID == uuid.Nil || auditID == uuid.Nil {
		return Publication{}, ErrServiceUnavailable
	}
	publication, err := publish(ctx, principal, InitialPublicationCommand{
		DefinitionID: definitionID, DisplayName: request.DisplayName,
		IconMediaType: request.IconMediaType, IconData: append([]byte(nil), request.IconData...),
		BuildVersion: func() (VersionMaterial, error) {
			attestation, signErr := s.signer.SignVersion(VersionSignatureInput{
				DefinitionID: definitionID, VersionID: versionID, VersionNumber: 1,
				ManifestDigest: canonical.ManifestDigest, BundleDigest: canonical.BundleDigest,
			})
			if signErr != nil {
				return VersionMaterial{}, ErrServiceUnavailable
			}
			return VersionMaterial{
				ID: versionID, VersionNumber: 1,
				CanonicalManifest: append([]byte(nil), canonical.ManifestJSON...), Bundle: append([]byte(nil), canonical.BundleJSON...),
				ContentDigest: canonical.ContentDigest, SigningKeyID: attestation.KeyID,
				Signature: append([]byte(nil), attestation.Signature...), RuntimeMinimumVersion: minimum,
				RuntimeMaximumVersionExclusive: maximum,
			}, nil
		},
		Idempotency: IdempotencyEvidence{
			ID: idempotencyID, KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, PublishedAt: now,
	})
	if err != nil {
		return Publication{}, err
	}
	return clonePublication(publication), nil
}

func (s *Service) PublishNext(
	ctx context.Context,
	principal Principal,
	request PublishNextRequest,
) (Publication, error) {
	return s.publishNext(ctx, principal, nil, request, s.repository.PublishNext)
}

func (s *Service) PublishWorkspaceNext(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	request PublishNextRequest,
) (Publication, error) {
	if workspaceID == uuid.Nil {
		return Publication{}, ErrInvalidRequest
	}
	return s.publishNext(
		ctx,
		principal,
		&workspaceID,
		request,
		func(ctx context.Context, principal Principal, command NextPublicationCommand) (Publication, error) {
			return s.repository.PublishWorkspaceNext(ctx, principal, workspaceID, command)
		},
	)
}

func (s *Service) publishNext(
	ctx context.Context,
	principal Principal,
	workspaceID *uuid.UUID,
	request PublishNextRequest,
	publish func(context.Context, Principal, NextPublicationCommand) (Publication, error),
) (Publication, error) {
	if s == nil || !validPrincipal(principal) || request.DefinitionID == uuid.Nil || request.BaseVersionID == uuid.Nil ||
		publish == nil || !validOptionalAgentDisplayName(request.DisplayName) ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) {
		return Publication{}, ErrInvalidRequest
	}
	canonical, minimum, maximum, err := canonicalizePublication(request.Manifest, request.Bundle)
	if err != nil {
		return Publication{}, err
	}
	requestHash, err := hashRequest(struct {
		Operation     string          `json:"operation"`
		DefinitionID  string          `json:"definition_id"`
		BaseVersionID string          `json:"base_version_id"`
		DisplayName   *string         `json:"display_name,omitempty"`
		Manifest      json.RawMessage `json:"manifest"`
		Bundle        json.RawMessage `json:"bundle"`
		WorkspaceID   *string         `json:"workspace_id,omitempty"`
	}{
		Operation: operationPublishNext, DefinitionID: request.DefinitionID.String(),
		BaseVersionID: request.BaseVersionID.String(), DisplayName: request.DisplayName,
		Manifest: canonical.ManifestJSON, Bundle: canonical.BundleJSON,
		WorkspaceID: uuidStringPointer(workspaceID),
	})
	if err != nil {
		return Publication{}, ErrInvalidAgentContent
	}
	now := s.clock().UTC()
	versionID, idempotencyID, auditID := s.newID(), s.newID(), s.newID()
	if versionID == uuid.Nil || idempotencyID == uuid.Nil || auditID == uuid.Nil {
		return Publication{}, ErrServiceUnavailable
	}
	publication, err := publish(ctx, principal, NextPublicationCommand{
		DefinitionID: request.DefinitionID, BaseVersionID: request.BaseVersionID,
		DisplayName: cloneStringPointer(request.DisplayName),
		BuildVersion: func(versionNumber int64) (VersionMaterial, error) {
			attestation, signErr := s.signer.SignVersion(VersionSignatureInput{
				DefinitionID: request.DefinitionID, VersionID: versionID, VersionNumber: versionNumber,
				ManifestDigest: canonical.ManifestDigest, BundleDigest: canonical.BundleDigest,
			})
			if signErr != nil {
				return VersionMaterial{}, ErrServiceUnavailable
			}
			return VersionMaterial{
				ID: versionID, VersionNumber: versionNumber,
				CanonicalManifest: append([]byte(nil), canonical.ManifestJSON...), Bundle: append([]byte(nil), canonical.BundleJSON...),
				ContentDigest: canonical.ContentDigest, SigningKeyID: attestation.KeyID,
				Signature: append([]byte(nil), attestation.Signature...), RuntimeMinimumVersion: minimum,
				RuntimeMaximumVersionExclusive: maximum,
			}, nil
		},
		Idempotency: IdempotencyEvidence{
			ID: idempotencyID, KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, PublishedAt: now,
	})
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_definition", request.DefinitionID, request.RequestID); auditErr != nil {
			return Publication{}, auditErr
		}
	}
	if err != nil {
		return Publication{}, err
	}
	return clonePublication(publication), nil
}

func (s *Service) ListDefinitions(ctx context.Context, principal Principal) ([]Definition, error) {
	if s == nil || !validPrincipal(principal) {
		return nil, ErrInvalidRequest
	}
	definitions, err := s.repository.ListDefinitions(ctx, principal)
	if err != nil {
		return nil, err
	}
	return cloneDefinitions(definitions), nil
}

func (s *Service) ListWorkspaceDefinitions(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]Definition, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	definitions, err := s.repository.ListWorkspaceDefinitions(ctx, principal, workspaceID)
	if err != nil {
		return nil, err
	}
	return cloneDefinitions(definitions), nil
}

func (s *Service) ListOrganizationDefinitions(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
) ([]Definition, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	definitions, err := s.repository.ListOrganizationDefinitions(ctx, principal, organizationID)
	if err != nil {
		return nil, err
	}
	return cloneDefinitions(definitions), nil
}

func (s *Service) GetDefinition(
	ctx context.Context,
	principal Principal,
	definitionID uuid.UUID,
	requestID string,
) (Definition, error) {
	if s == nil || !validPrincipal(principal) || definitionID == uuid.Nil || !validRequestID(requestID) {
		return Definition{}, ErrInvalidRequest
	}
	definition, found, err := s.repository.FindDefinition(ctx, principal, definitionID)
	if err != nil {
		return Definition{}, err
	}
	if !found {
		if err := s.recordDenied(ctx, principal, "agent_definition", definitionID, requestID); err != nil {
			return Definition{}, err
		}
		return Definition{}, ErrNotFound
	}
	return cloneDefinition(definition), nil
}

func (s *Service) GetWorkspaceDefinition(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
	requestID string,
) (Definition, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil || definitionID == uuid.Nil ||
		!validRequestID(requestID) {
		return Definition{}, ErrInvalidRequest
	}
	definition, found, err := s.repository.FindWorkspaceDefinition(ctx, principal, workspaceID, definitionID)
	if err != nil {
		return Definition{}, err
	}
	if !found {
		if err := s.recordDenied(ctx, principal, "agent_definition", definitionID, requestID); err != nil {
			return Definition{}, err
		}
		return Definition{}, ErrNotFound
	}
	return cloneDefinition(definition), nil
}

func (s *Service) GetOrganizationDefinition(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	definitionID uuid.UUID,
	requestID string,
) (Definition, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil || definitionID == uuid.Nil ||
		!validRequestID(requestID) {
		return Definition{}, ErrInvalidRequest
	}
	definition, found, err := s.repository.FindOrganizationDefinition(
		ctx, principal, organizationID, definitionID,
	)
	if err != nil {
		return Definition{}, err
	}
	if !found {
		return Definition{}, ErrOrganizationAgentNotFound
	}
	return cloneDefinition(definition), nil
}

func (s *Service) ListVersions(
	ctx context.Context,
	principal Principal,
	definitionID uuid.UUID,
	requestID string,
) ([]Version, error) {
	if s == nil || !validPrincipal(principal) || definitionID == uuid.Nil || !validRequestID(requestID) {
		return nil, ErrInvalidRequest
	}
	versions, err := s.repository.ListVersions(ctx, principal, definitionID)
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_definition", definitionID, requestID); auditErr != nil {
			return nil, auditErr
		}
	}
	if err != nil {
		return nil, err
	}
	return cloneVersions(versions), nil
}

func (s *Service) ListWorkspaceVersions(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
	requestID string,
) ([]Version, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil || definitionID == uuid.Nil ||
		!validRequestID(requestID) {
		return nil, ErrInvalidRequest
	}
	versions, err := s.repository.ListWorkspaceVersions(ctx, principal, workspaceID, definitionID)
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_definition", definitionID, requestID); auditErr != nil {
			return nil, auditErr
		}
	}
	if err != nil {
		return nil, err
	}
	return cloneVersions(versions), nil
}

func (s *Service) ListOrganizationVersions(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	definitionID uuid.UUID,
	requestID string,
) ([]Version, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil || definitionID == uuid.Nil ||
		!validRequestID(requestID) {
		return nil, ErrInvalidRequest
	}
	versions, err := s.repository.ListOrganizationVersions(ctx, principal, organizationID, definitionID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrOrganizationAgentNotFound
	}
	if err != nil {
		return nil, err
	}
	return cloneVersions(versions), nil
}

func (s *Service) GetVersion(
	ctx context.Context,
	principal Principal,
	versionID uuid.UUID,
	requestID string,
) (Version, error) {
	if s == nil || !validPrincipal(principal) || versionID == uuid.Nil || !validRequestID(requestID) {
		return Version{}, ErrInvalidRequest
	}
	version, found, err := s.repository.FindVersion(ctx, principal, versionID)
	if err != nil {
		return Version{}, err
	}
	if !found {
		if err := s.recordDenied(ctx, principal, "agent_version", versionID, requestID); err != nil {
			return Version{}, err
		}
		return Version{}, ErrNotFound
	}
	return cloneVersion(version), nil
}

func (s *Service) GetPolicySnapshot(
	ctx context.Context,
	principal Principal,
	policySnapshotID uuid.UUID,
	requestID string,
) (PolicySnapshot, error) {
	if s == nil || !validPrincipal(principal) || policySnapshotID == uuid.Nil || !validRequestID(requestID) {
		return PolicySnapshot{}, ErrInvalidRequest
	}
	policy, found, err := s.repository.FindPolicySnapshot(ctx, principal, policySnapshotID)
	if err != nil {
		return PolicySnapshot{}, err
	}
	if !found {
		if err := s.recordDenied(ctx, principal, "policy_snapshot", policySnapshotID, requestID); err != nil {
			return PolicySnapshot{}, err
		}
		return PolicySnapshot{}, ErrNotFound
	}
	return clonePolicySnapshot(policy), nil
}

func (s *Service) RevokeVersion(
	ctx context.Context,
	principal Principal,
	request RevokeVersionRequest,
) (VersionRevocation, error) {
	if s == nil || !validPrincipal(principal) || request.VersionID == uuid.Nil || request.PolicySnapshotID == uuid.Nil ||
		!validToken(request.ReasonCode, 64) || (request.SupersedingVersionID != nil &&
		(*request.SupersedingVersionID == uuid.Nil || *request.SupersedingVersionID == request.VersionID)) ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) {
		return VersionRevocation{}, ErrInvalidRequest
	}
	requestHash, err := hashRequest(struct {
		Operation            string  `json:"operation"`
		VersionID            string  `json:"version_id"`
		ReasonCode           string  `json:"reason_code"`
		PolicySnapshotID     string  `json:"policy_snapshot_id"`
		SupersedingVersionID *string `json:"superseding_version_id"`
	}{
		Operation: "revoke_version", VersionID: request.VersionID.String(), ReasonCode: request.ReasonCode,
		PolicySnapshotID: request.PolicySnapshotID.String(), SupersedingVersionID: uuidStringPointer(request.SupersedingVersionID),
	})
	if err != nil {
		return VersionRevocation{}, ErrInvalidRequest
	}
	now := s.clock().UTC()
	revocationID, idempotencyID, auditID := s.newID(), s.newID(), s.newID()
	if revocationID == uuid.Nil || idempotencyID == uuid.Nil || auditID == uuid.Nil {
		return VersionRevocation{}, ErrServiceUnavailable
	}
	revocation, err := s.repository.AppendVersionRevocation(ctx, principal, VersionRevocationCommand{
		RevocationID: revocationID, VersionID: request.VersionID, ReasonCode: request.ReasonCode,
		PolicySnapshotID: request.PolicySnapshotID, SupersedingVersionID: cloneUUIDPointer(request.SupersedingVersionID),
		Idempotency: IdempotencyEvidence{
			ID: idempotencyID, KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, RevokedAt: now,
	})
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_version", request.VersionID, request.RequestID); auditErr != nil {
			return VersionRevocation{}, auditErr
		}
	}
	if err != nil {
		return VersionRevocation{}, err
	}
	return cloneVersionRevocation(revocation), nil
}

func (s *Service) CreateInstallation(
	ctx context.Context,
	principal Principal,
	request CreateInstallationRequest,
) (InstallationCreation, error) {
	if s == nil || !validPrincipal(principal) || request.DefinitionID == uuid.Nil ||
		(request.SourceWorkspaceID != nil && *request.SourceWorkspaceID == uuid.Nil) ||
		(request.OrganizationID != nil && *request.OrganizationID == uuid.Nil) ||
		(request.SourceWorkspaceID != nil && request.OrganizationID != nil) ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) {
		return InstallationCreation{}, ErrInvalidRequest
	}
	official := request.OfficialReleaseRevisionID != nil || request.OfficialContext != nil
	if official {
		if s.officialEligibility == nil || request.VersionID != uuid.Nil || request.SourceWorkspaceID != nil || request.OrganizationID != nil ||
			request.OfficialReleaseRevisionID == nil || *request.OfficialReleaseRevisionID == uuid.Nil || request.OfficialContext == nil ||
			!validOfficialEligibilityContext(principal, *request.OfficialContext) {
			return InstallationCreation{}, ErrInvalidRequest
		}
	} else if request.VersionID == uuid.Nil {
		return InstallationCreation{}, ErrInvalidRequest
	}
	var officialTarget OfficialManagedTarget
	var err error
	if official {
		officialTarget, err = s.officialEligibility.ResolveOfficialReleaseRevision(
			ctx, principal, request.DefinitionID, *request.OfficialReleaseRevisionID, *request.OfficialContext,
		)
		if err != nil {
			return InstallationCreation{}, err
		}
	}
	requestHash, err := hashRequest(struct {
		Operation                 string                      `json:"operation"`
		DefinitionID              string                      `json:"definition_id"`
		VersionID                 string                      `json:"version_id,omitempty"`
		WorkspaceID               *string                     `json:"workspace_id,omitempty"`
		OrganizationID            *string                     `json:"organization_id,omitempty"`
		OfficialReleaseRevisionID *string                     `json:"official_release_revision_id,omitempty"`
		OfficialContext           *OfficialEligibilityContext `json:"official_context,omitempty"`
	}{
		Operation: operationCreateInstallation, DefinitionID: request.DefinitionID.String(), VersionID: request.VersionID.String(),
		WorkspaceID: uuidStringPointer(request.SourceWorkspaceID), OrganizationID: uuidStringPointer(request.OrganizationID),
		OfficialReleaseRevisionID: uuidStringPointer(request.OfficialReleaseRevisionID),
		OfficialContext:           cloneOfficialEligibilityContextPointer(request.OfficialContext),
	})
	if err != nil {
		return InstallationCreation{}, ErrInvalidRequest
	}
	now := s.clock().UTC()
	installationID, policyID, idempotencyID, auditID := s.newID(), s.newID(), s.newID(), s.newID()
	if installationID == uuid.Nil || policyID == uuid.Nil || idempotencyID == uuid.Nil || auditID == uuid.Nil {
		return InstallationCreation{}, ErrServiceUnavailable
	}
	command := CreateInstallationCommand{
		InstallationID: installationID, DefinitionID: request.DefinitionID, VersionID: request.VersionID,
		SourceWorkspaceID:    cloneUUIDPointer(request.SourceWorkspaceID),
		SourceOrganizationID: cloneUUIDPointer(request.OrganizationID),
		BuildPolicy: func(version Version) (PolicyMaterial, error) {
			return s.buildPolicy(installationID, policyID, version, 1, now)
		},
		BuildOrganizationPolicy: func(
			version Version,
			effective EffectiveOrganizationAgentPolicy,
		) (PolicyMaterial, error) {
			return s.buildOrganizationPolicy(installationID, policyID, version, 1, effective, now)
		},
		Idempotency: IdempotencyEvidence{
			ID: idempotencyID, KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, CreatedAt: now,
	}
	if official {
		releaseID, releaseRevisionID := officialTarget.ReleaseID, officialTarget.ReleaseRevisionID
		contextValue := *cloneOfficialEligibilityContextPointer(request.OfficialContext)
		command.OfficialPlatformID = officialTarget.PlatformID
		command.OfficialReleaseID = &releaseID
		command.OfficialReleaseRevisionID = &releaseRevisionID
		command.OfficialContext = &contextValue
		command.EvaluateOfficial = func(record OfficialEligibilityRecord) (OfficialManagedTarget, error) {
			return s.officialEligibility.EvaluateOfficialEligibilityRecord(principal, contextValue, record, false)
		}
		command.BuildOfficialPolicy = func(
			version Version,
			target OfficialManagedTarget,
			deviceInstallationID uuid.UUID,
		) (PolicyMaterial, error) {
			return s.buildOfficialPolicy(
				installationID, policyID, deviceInstallationID, principal, version, target, contextValue, 1, now,
			)
		}
	}
	created, err := s.repository.CreatePendingInstallation(ctx, principal, command)
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_definition", request.DefinitionID, request.RequestID); auditErr != nil {
			return InstallationCreation{}, auditErr
		}
	}
	if err != nil {
		return InstallationCreation{}, err
	}
	return cloneInstallationCreation(created), nil
}

func (s *Service) ActivateInstallation(
	ctx context.Context,
	principal Principal,
	request ActivateInstallationRequest,
) (Installation, error) {
	if s == nil || !validPrincipal(principal) || request.InstallationID == uuid.Nil || request.RuntimeProfileID == uuid.Nil ||
		zeroDigest(request.VersionDigest) || request.Timestamp <= 0 || len(request.DeviceProof) != 64 ||
		!validRequestID(request.RequestID) {
		return Installation{}, ErrInvalidRequest
	}
	activationContext, found, err := s.repository.LoadActivationContext(ctx, principal, request.InstallationID)
	if err != nil {
		return Installation{}, err
	}
	if !found || activationContext.Installation.DeviceID != principal.DeviceID {
		if err := s.recordDenied(ctx, principal, "agent_installation", request.InstallationID, request.RequestID); err != nil {
			return Installation{}, err
		}
		return Installation{}, ErrNotFound
	}
	if activationContext.Installation.PolicySnapshotID == nil {
		return Installation{}, ErrServiceUnavailable
	}
	if activationContext.Version.ID != activationContext.Installation.SelectedVersionID ||
		activationContext.Version.ContentDigest != request.VersionDigest {
		return Installation{}, ErrInvalidDeviceProof
	}
	now := s.clock().UTC()
	if err := VerifyActivationProof(activationContext.DevicePublicKey, ActivationProofInput{
		AgentInstallationID: request.InstallationID, RuntimeProfileID: request.RuntimeProfileID,
		VersionDigest: request.VersionDigest, Timestamp: request.Timestamp,
	}, request.DeviceProof, now); err != nil {
		return Installation{}, err
	}
	auditID := s.newID()
	if auditID == uuid.Nil {
		return Installation{}, ErrServiceUnavailable
	}
	installation, err := s.repository.ActivateInstallation(ctx, principal, ActivationCommand{
		InstallationID: request.InstallationID, RuntimeProfileID: request.RuntimeProfileID,
		AgentVersionID: activationContext.Version.ID, PolicySnapshotID: *activationContext.Installation.PolicySnapshotID,
		VersionDigest: request.VersionDigest,
		Audit:         AuditEvidence{EventID: auditID, RequestID: request.RequestID}, ActivatedAt: now,
	})
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_installation", request.InstallationID, request.RequestID); auditErr != nil {
			return Installation{}, auditErr
		}
	}
	if err != nil {
		return Installation{}, err
	}
	return cloneInstallation(installation), nil
}

func (s *Service) SelectInstallationVersion(
	ctx context.Context,
	principal Principal,
	request SelectInstallationVersionRequest,
) (Installation, error) {
	if s == nil || !validPrincipal(principal) || request.InstallationID == uuid.Nil || request.VersionID == uuid.Nil ||
		!validRequestID(request.RequestID) {
		return Installation{}, ErrInvalidRequest
	}
	policyID, auditID := s.newID(), s.newID()
	if policyID == uuid.Nil || auditID == uuid.Nil {
		return Installation{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	selected, err := s.repository.SelectInstallationVersion(ctx, principal, VersionSelectionCommand{
		InstallationID: request.InstallationID, VersionID: request.VersionID,
		BuildPolicy: func(policyVersion int64, version Version) (PolicyMaterial, error) {
			return s.buildPolicy(request.InstallationID, policyID, version, policyVersion, now)
		},
		BuildOrganizationPolicy: func(
			policyVersion int64,
			version Version,
			effective EffectiveOrganizationAgentPolicy,
		) (PolicyMaterial, error) {
			return s.buildOrganizationPolicy(
				request.InstallationID, policyID, version, policyVersion, effective, now,
			)
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, SelectedAt: now,
	})
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_installation", request.InstallationID, request.RequestID); auditErr != nil {
			return Installation{}, auditErr
		}
	}
	if err != nil {
		return Installation{}, err
	}
	return cloneInstallation(selected), nil
}

func (s *Service) ApplyManagedOfficialUpdate(
	ctx context.Context,
	principal Principal,
	request ManagedUpdateRequest,
) (Installation, error) {
	if s == nil || s.officialEligibility == nil || !validPrincipal(principal) ||
		request.InstallationID == uuid.Nil || request.ExpectedSelectedRevisionID == uuid.Nil ||
		request.TargetReleaseRevisionID == uuid.Nil || !validOfficialEligibilityContext(principal, request.OfficialContext) ||
		!validRequestID(request.RequestID) {
		return Installation{}, ErrInvalidRequest
	}
	policyID, auditID := s.newID(), s.newID()
	if policyID == uuid.Nil || auditID == uuid.Nil {
		return Installation{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	selected, err := s.repository.ApplyManagedOfficialSelection(ctx, principal, ManagedOfficialSelectionCommand{
		InstallationID:             request.InstallationID,
		ExpectedSelectedRevisionID: request.ExpectedSelectedRevisionID,
		TargetReleaseRevisionID:    request.TargetReleaseRevisionID,
		OfficialContext:            request.OfficialContext,
		EvaluateOfficial: func(record OfficialEligibilityRecord) (OfficialManagedTarget, error) {
			return s.officialEligibility.EvaluateOfficialEligibilityRecord(
				principal, request.OfficialContext, record, true,
			)
		},
		BuildPolicy: func(
			policyVersion int64,
			version Version,
			target OfficialManagedTarget,
			deviceInstallationID uuid.UUID,
		) (PolicyMaterial, error) {
			return s.buildOfficialPolicy(
				request.InstallationID, policyID, deviceInstallationID, principal, version, target,
				request.OfficialContext, policyVersion, now,
			)
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, SelectedAt: now,
	})
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_installation", request.InstallationID, request.RequestID); auditErr != nil {
			return Installation{}, auditErr
		}
	}
	if err != nil {
		return Installation{}, err
	}
	return cloneInstallation(selected), nil
}

func (s *Service) GetManagedOfficialUpdate(
	ctx context.Context,
	principal Principal,
	request GetManagedOfficialUpdateRequest,
) (OfficialManagedUpdate, error) {
	if s == nil || s.officialEligibility == nil || !validPrincipal(principal) ||
		request.InstallationID == uuid.Nil || !validOfficialEligibilityContext(principal, request.OfficialContext) ||
		!validRequestID(request.RequestID) {
		return OfficialManagedUpdate{}, ErrInvalidRequest
	}
	installation, found, err := s.repository.FindInstallation(ctx, principal, request.InstallationID)
	if err != nil {
		return OfficialManagedUpdate{}, err
	}
	if !found || installation.DeviceID != principal.DeviceID {
		if auditErr := s.recordDenied(ctx, principal, "agent_installation", request.InstallationID, request.RequestID); auditErr != nil {
			return OfficialManagedUpdate{}, auditErr
		}
		return OfficialManagedUpdate{}, ErrNotFound
	}
	if installation.UpdatePolicy != installationUpdatePolicyManaged || installation.OfficialReleaseID == nil ||
		installation.SelectedReleaseRevisionID == nil {
		return OfficialManagedUpdate{}, ErrOfficialManagedUpdateConflict
	}
	if installation.Status == InstallationStatusArchived {
		return OfficialManagedUpdate{}, ErrInstallationArchived
	}
	if installation.Status != InstallationStatusActive {
		return OfficialManagedUpdate{}, ErrActivationConflict
	}
	agent, err := s.officialEligibility.GetOfficialAgent(
		ctx, principal, installation.DefinitionID, request.OfficialContext,
	)
	if err != nil {
		return OfficialManagedUpdate{}, err
	}
	if agent.Target.ReleaseID != *installation.OfficialReleaseID {
		return OfficialManagedUpdate{}, ErrOfficialAgentNotEligible
	}
	if agent.Target.DefinitionID != installation.DefinitionID || agent.Target.VersionID != agent.Version.ID {
		return OfficialManagedUpdate{}, ErrCloudUnavailable
	}
	if *installation.SelectedReleaseRevisionID == agent.Target.ReleaseRevisionID {
		return OfficialManagedUpdate{UpdateAvailable: false}, nil
	}
	return OfficialManagedUpdate{
		UpdateAvailable: true, InstallationID: installation.ID,
		ExpectedSelectedReleaseRevisionID: *installation.SelectedReleaseRevisionID,
		Target:                            agent.Target, Version: cloneVersion(agent.Version),
	}, nil
}

func (s *Service) ArchiveInstallation(
	ctx context.Context,
	principal Principal,
	request ArchiveInstallationRequest,
) (Installation, error) {
	if s == nil || !validPrincipal(principal) || request.InstallationID == uuid.Nil || !validRequestID(request.RequestID) {
		return Installation{}, ErrInvalidRequest
	}
	auditID := s.newID()
	if auditID == uuid.Nil {
		return Installation{}, ErrServiceUnavailable
	}
	installation, err := s.repository.ArchiveInstallation(ctx, principal, ArchiveInstallationCommand{
		InstallationID: request.InstallationID, Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID},
		ArchivedAt: s.clock().UTC(),
	})
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_installation", request.InstallationID, request.RequestID); auditErr != nil {
			return Installation{}, auditErr
		}
	}
	if err != nil {
		return Installation{}, err
	}
	return cloneInstallation(installation), nil
}

func (s *Service) RecordRuntimeBinding(
	ctx context.Context,
	principal Principal,
	command RuntimeBindingRecordCommand,
	requestID string,
) (RuntimeBindingRecord, error) {
	if s == nil || !validPrincipal(principal) || !validRuntimeBinding(command) || !validRequestID(requestID) {
		return RuntimeBindingRecord{}, ErrInvalidRequest
	}
	auditID := s.newID()
	if auditID == uuid.Nil {
		return RuntimeBindingRecord{}, ErrServiceUnavailable
	}
	record, err := s.repository.InsertRuntimeBinding(ctx, principal, PersistRuntimeBindingCommand{
		RuntimeBindingRecordCommand: command,
		Audit:                       AuditEvidence{EventID: auditID, RequestID: requestID}, CreatedAt: s.clock().UTC(),
	})
	if errors.Is(err, ErrNotFound) {
		if auditErr := s.recordDenied(ctx, principal, "agent_installation", command.AgentInstallationID, requestID); auditErr != nil {
			return RuntimeBindingRecord{}, auditErr
		}
	}
	if err != nil {
		return RuntimeBindingRecord{}, err
	}
	return record, nil
}

func (s *Service) buildPolicy(
	installationID uuid.UUID,
	policyID uuid.UUID,
	version Version,
	policyVersion int64,
	createdAt time.Time,
) (PolicyMaterial, error) {
	document, err := policyDocumentForVersion(version)
	if err != nil {
		return PolicyMaterial{}, err
	}
	digest := sha256.Sum256(document)
	attestation, err := s.signer.SignPolicy(PolicySignatureInput{
		PolicyID: policyID, PolicyVersion: policyVersion, DocumentDigest: digest,
	})
	if err != nil {
		return PolicyMaterial{}, ErrServiceUnavailable
	}
	return PolicyMaterial{
		ID: policyID, InstallationID: installationID, AgentVersionID: version.ID, PolicyVersion: policyVersion,
		Document: document, ContentDigest: digest, Issuer: attestation.Issuer, SigningKeyID: attestation.KeyID,
		Signature: append([]byte(nil), attestation.Signature...), CreatedAt: createdAt.UTC(),
	}, nil
}

func (s *Service) buildOrganizationPolicy(
	installationID uuid.UUID,
	policyID uuid.UUID,
	version Version,
	policyVersion int64,
	effective EffectiveOrganizationAgentPolicy,
	createdAt time.Time,
) (PolicyMaterial, error) {
	document, err := policyDocumentForOrganizationVersion(version, effective)
	if err != nil {
		return PolicyMaterial{}, err
	}
	digest := sha256.Sum256(document)
	attestation, err := s.signer.SignPolicy(PolicySignatureInput{
		PolicyID: policyID, PolicyVersion: policyVersion, DocumentDigest: digest,
	})
	if err != nil {
		return PolicyMaterial{}, ErrServiceUnavailable
	}
	return PolicyMaterial{
		ID: policyID, InstallationID: installationID, AgentVersionID: version.ID, PolicyVersion: policyVersion,
		Document: document, ContentDigest: digest, Issuer: attestation.Issuer, SigningKeyID: attestation.KeyID,
		Signature: append([]byte(nil), attestation.Signature...), CreatedAt: createdAt.UTC(),
	}, nil
}

func (s *Service) buildOfficialPolicy(
	installationID uuid.UUID,
	policyID uuid.UUID,
	deviceInstallationID uuid.UUID,
	principal Principal,
	version Version,
	target OfficialManagedTarget,
	eligibilityContext OfficialEligibilityContext,
	policyVersion int64,
	createdAt time.Time,
) (PolicyMaterial, error) {
	document, err := policyDocumentForOfficialVersion(
		installationID, deviceInstallationID, principal, version, target, eligibilityContext,
	)
	if err != nil {
		return PolicyMaterial{}, err
	}
	digest := sha256.Sum256(document)
	attestation, err := s.signer.SignPolicy(PolicySignatureInput{
		PolicyID: policyID, PolicyVersion: policyVersion, DocumentDigest: digest,
	})
	if err != nil {
		return PolicyMaterial{}, ErrServiceUnavailable
	}
	return PolicyMaterial{
		ID: policyID, InstallationID: installationID, AgentVersionID: version.ID, PolicyVersion: policyVersion,
		Document: document, ContentDigest: digest, Issuer: attestation.Issuer, SigningKeyID: attestation.KeyID,
		Signature: append([]byte(nil), attestation.Signature...), CreatedAt: createdAt.UTC(),
	}, nil
}

func (s *Service) recordDenied(
	ctx context.Context,
	principal Principal,
	objectType string,
	objectID uuid.UUID,
	requestID string,
) error {
	eventID := s.newID()
	if eventID == uuid.Nil {
		return ErrServiceUnavailable
	}
	if err := s.repository.RecordDenied(ctx, principal, DeniedAuditCommand{
		EventID: eventID, ObjectType: objectType, ObjectID: objectID, ReasonCode: "not_found",
		RequestID: requestID, OccurredAt: s.clock().UTC(),
	}); err != nil {
		return err
	}
	return nil
}

func canonicalizePublication(
	manifest AgentManifestV1,
	bundle VersionBundleV1,
) (CanonicalVersion, string, string, error) {
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		return CanonicalVersion{}, "", "", err
	}
	minimum, _, err := parseSemanticVersion(manifest.RuntimeCompatibility.MinimumVersion)
	if err != nil {
		return CanonicalVersion{}, "", "", ErrRuntimeIncompatible
	}
	maximum := ""
	if manifest.RuntimeCompatibility.MaximumVersionExclusive != "" {
		maximum, _, err = parseSemanticVersion(manifest.RuntimeCompatibility.MaximumVersionExclusive)
		if err != nil {
			return CanonicalVersion{}, "", "", ErrRuntimeIncompatible
		}
	}
	return canonical, minimum, maximum, nil
}

func validPublicationEnvelope(displayName string, key string, requestID string) bool {
	if !validAgentDisplayName(displayName) ||
		!validIdempotencyKey(key) || !validRequestID(requestID) {
		return false
	}
	return true
}

func validOptionalAgentDisplayName(displayName *string) bool {
	return displayName == nil || validAgentDisplayName(*displayName)
}

func validAgentDisplayName(displayName string) bool {
	trimmed := strings.TrimSpace(displayName)
	return trimmed != "" && trimmed == displayName && utf8.ValidString(displayName) && len([]rune(displayName)) <= 100
}

func validIdempotencyKey(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) && len([]byte(value)) <= 256 &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func validRequestID(value string) bool {
	return validAuditEvidence(AuditEvidence{EventID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), RequestID: value})
}

func hashRequest(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

type policyDocumentV1 struct {
	SchemaVersion        int                           `json:"schema_version"`
	AgentDefinitionID    string                        `json:"agent_definition_id"`
	AgentVersionID       string                        `json:"agent_version_id"`
	VersionDigest        string                        `json:"version_digest"`
	ModelConstraints     canonicalModelConstraints     `json:"model_constraints"`
	Tools                canonicalTools                `json:"tools"`
	RuntimeCompatibility canonicalRuntimeCompatibility `json:"runtime_compatibility"`
	PublicationAllowed   bool                          `json:"publication_allowed"`
	DenyRules            []string                      `json:"deny_rules"`
	OfficialContext      *officialPolicyContextV1      `json:"official_context,omitempty"`
}

type policyDocumentV2 struct {
	SchemaVersion        int                           `json:"schema_version"`
	AgentDefinitionID    string                        `json:"agent_definition_id"`
	AgentVersionID       string                        `json:"agent_version_id"`
	VersionDigest        string                        `json:"version_digest"`
	ModelPolicy          canonicalModelPolicyV2        `json:"model_policy"`
	Tools                canonicalTools                `json:"tools"`
	RuntimeCompatibility canonicalRuntimeCompatibility `json:"runtime_compatibility"`
	PublicationAllowed   bool                          `json:"publication_allowed"`
	DenyRules            []string                      `json:"deny_rules"`
	OfficialContext      *officialPolicyContextV1      `json:"official_context,omitempty"`
}

type officialPolicyContextV1 struct {
	PlatformID           string     `json:"platform_id"`
	ReleaseID            string     `json:"release_id"`
	ReleaseRevisionID    string     `json:"release_revision_id"`
	UserID               string     `json:"user_id"`
	DeviceInstallationID string     `json:"device_installation_id"`
	InstallationID       string     `json:"installation_id"`
	ProductScope         OwnerScope `json:"product_scope"`
	ProductContextID     string     `json:"product_context_id"`
}

func policyDocumentForVersion(version Version) ([]byte, error) {
	return policyDocumentForVersionWithConstraints(version, nil)
}

func policyDocumentForOrganizationVersion(
	version Version,
	effective EffectiveOrganizationAgentPolicy,
) ([]byte, error) {
	if effective.ModelMode != ModelSelectionUserSelect &&
		(len(effective.AllowedProviders) == 0 || len(effective.AllowedModels) == 0) {
		return nil, ErrOrganizationPublicationPolicyBlocked
	}
	if effective.ModelMode == ModelSelectionUserSelect &&
		(len(effective.AllowedProviders) != 0 || len(effective.AllowedModels) != 0 || effective.AllowedModelPairs != nil) {
		return nil, ErrOrganizationPublicationPolicyBlocked
	}
	allowedPairs := make(map[string]struct{}, len(effective.AllowedModelPairs))
	for _, pair := range effective.AllowedModelPairs {
		allowedPairs[pair.Provider+"\x00"+pair.Model] = struct{}{}
	}
	for _, provider := range effective.AllowedProviders {
		for _, model := range effective.AllowedModels {
			if _, allowed := allowedPairs[provider+"\x00"+model]; !allowed {
				return nil, ErrOrganizationPublicationPolicyBlocked
			}
		}
	}
	return policyDocumentForVersionWithConstraints(version, &effective.AgentPolicyConstraints)
}

func policyDocumentForOfficialVersion(
	installationID uuid.UUID,
	deviceInstallationID uuid.UUID,
	principal Principal,
	version Version,
	target OfficialManagedTarget,
	eligibilityContext OfficialEligibilityContext,
) ([]byte, error) {
	if installationID == uuid.Nil || deviceInstallationID == uuid.Nil || !validPrincipal(principal) || target.PlatformID == uuid.Nil ||
		target.ReleaseID == uuid.Nil || target.ReleaseRevisionID == uuid.Nil || target.DefinitionID != version.DefinitionID ||
		target.VersionID != version.ID || !validOfficialEligibilityContext(principal, eligibilityContext) {
		return nil, ErrInvalidAgentContent
	}
	base, err := policyDocumentForVersion(version)
	if err != nil {
		return nil, err
	}
	contextID := eligibilityContext.Selector.PersonalSpaceID
	switch eligibilityContext.Selector.Scope {
	case OwnerScopeWorkspace:
		contextID = eligibilityContext.Selector.WorkspaceID
	case OwnerScopeOrganization:
		contextID = eligibilityContext.Selector.OrganizationID
	}
	if contextID == uuid.Nil {
		return nil, ErrInvalidAgentContent
	}
	officialContext := &officialPolicyContextV1{
		PlatformID: target.PlatformID.String(), ReleaseID: target.ReleaseID.String(),
		ReleaseRevisionID: target.ReleaseRevisionID.String(), UserID: principal.UserID.String(),
		DeviceInstallationID: deviceInstallationID.String(), InstallationID: installationID.String(),
		ProductScope: eligibilityContext.Selector.Scope, ProductContextID: contextID.String(),
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(base, &header); err != nil {
		return nil, ErrInvalidAgentContent
	}
	var document any
	switch header.SchemaVersion {
	case 2:
		var value policyDocumentV2
		if err := decodeStrictJSON(base, &value); err != nil {
			return nil, ErrInvalidAgentContent
		}
		value.OfficialContext = officialContext
		document = value
	case 1:
		var value policyDocumentV1
		if err := decodeStrictJSON(base, &value); err != nil {
			return nil, ErrInvalidAgentContent
		}
		value.OfficialContext = officialContext
		document = value
	default:
		return nil, ErrInvalidAgentContent
	}
	encoded, err := marshalCanonical(document)
	if err != nil || len(encoded) > MaxManifestBytes {
		return nil, ErrInvalidAgentContent
	}
	return encoded, nil
}

func policyDocumentForVersionWithConstraints(
	version Version,
	effective *AgentPolicyConstraints,
) ([]byte, error) {
	if version.ID == uuid.Nil || version.DefinitionID == uuid.Nil || zeroDigest(version.ContentDigest) ||
		len(version.CanonicalManifest) == 0 || len(version.CanonicalManifest) > MaxManifestBytes ||
		len(version.Bundle) == 0 || len(version.Bundle) > MaxBundleBytes {
		return nil, ErrInvalidAgentContent
	}
	manifestValue, err := DecodeManifest(version.CanonicalManifest)
	if err != nil {
		return nil, ErrInvalidAgentContent
	}
	bundleValue, err := DecodeBundle(version.Bundle)
	if err != nil {
		return nil, ErrInvalidAgentContent
	}
	canonical, err := CanonicalizeVersion(manifestValue, bundleValue)
	if err != nil || canonical.ContentDigest != version.ContentDigest {
		return nil, ErrInvalidAgentContent
	}
	var document []byte
	switch manifestValue.SchemaVersion {
	case 1:
		var manifest canonicalManifest
		if err := decodeStrictJSON(canonical.ManifestJSON, &manifest); err != nil || manifest.SchemaVersion != 1 {
			return nil, ErrInvalidAgentContent
		}
		if effective != nil {
			manifest.ModelConstraints.AllowedProviders = cloneOrganizationSlice(effective.AllowedProviders)
			manifest.ModelConstraints.AllowedModels = cloneOrganizationSlice(effective.AllowedModels)
			manifest.Tools.Allowed = cloneOrganizationSlice(effective.AllowedTools)
		}
		document, err = marshalCanonical(policyDocumentV1{
			SchemaVersion: 1, AgentDefinitionID: version.DefinitionID.String(), AgentVersionID: version.ID.String(),
			VersionDigest: hex.EncodeToString(version.ContentDigest[:]), ModelConstraints: manifest.ModelConstraints,
			Tools: manifest.Tools, RuntimeCompatibility: manifest.RuntimeCompatibility,
			PublicationAllowed: false, DenyRules: []string{},
		})
	case 2:
		var manifest canonicalManifestV2
		if err := decodeStrictJSON(canonical.ManifestJSON, &manifest); err != nil || manifest.SchemaVersion != 2 {
			return nil, ErrInvalidAgentContent
		}
		if effective != nil {
			manifest.ModelPolicy = canonicalModelPolicyV2{
				Mode:             effective.ModelMode,
				AllowedProviders: cloneOrganizationSlice(effective.AllowedProviders),
				AllowedModels:    cloneOrganizationSlice(effective.AllowedModels),
			}
			manifest.Tools.Allowed = cloneOrganizationSlice(effective.AllowedTools)
		}
		if !validModelPolicyV2(
			manifest.ModelPolicy.Mode,
			manifest.ModelPolicy.AllowedProviders,
			manifest.ModelPolicy.AllowedModels,
		) {
			return nil, ErrInvalidAgentContent
		}
		document, err = marshalCanonical(policyDocumentV2{
			SchemaVersion: 2, AgentDefinitionID: version.DefinitionID.String(), AgentVersionID: version.ID.String(),
			VersionDigest: hex.EncodeToString(version.ContentDigest[:]), ModelPolicy: manifest.ModelPolicy,
			Tools: manifest.Tools, RuntimeCompatibility: manifest.RuntimeCompatibility,
			PublicationAllowed: false, DenyRules: []string{},
		})
	default:
		return nil, ErrInvalidAgentContent
	}
	if err != nil || len(document) > MaxManifestBytes {
		return nil, ErrInvalidAgentContent
	}
	return document, nil
}

func clonePublication(value Publication) Publication {
	value.Definition = cloneDefinition(value.Definition)
	value.Version = cloneVersion(value.Version)
	return value
}

func cloneDefinitions(values []Definition) []Definition {
	if values == nil {
		return nil
	}
	cloned := make([]Definition, len(values))
	for index, value := range values {
		cloned[index] = cloneDefinition(value)
	}
	return cloned
}

func cloneDefinition(value Definition) Definition {
	value.IconData = append([]byte(nil), value.IconData...)
	value.LatestVersionID = cloneUUIDPointer(value.LatestVersionID)
	return value
}

func cloneVersions(values []Version) []Version {
	if values == nil {
		return nil
	}
	cloned := make([]Version, len(values))
	for index, value := range values {
		cloned[index] = cloneVersion(value)
	}
	return cloned
}

func cloneVersion(value Version) Version {
	value.CanonicalManifest = append([]byte(nil), value.CanonicalManifest...)
	value.Bundle = append([]byte(nil), value.Bundle...)
	value.Signature = append([]byte(nil), value.Signature...)
	return value
}

func cloneOfficialAgentCatalog(values []OfficialAgentCatalogEntry) []OfficialAgentCatalogEntry {
	if values == nil {
		return nil
	}
	result := make([]OfficialAgentCatalogEntry, len(values))
	for index, value := range values {
		result[index] = cloneOfficialAgentCatalogEntry(value)
	}
	return result
}

func cloneOfficialAgentCatalogEntry(value OfficialAgentCatalogEntry) OfficialAgentCatalogEntry {
	value.IconData = append([]byte(nil), value.IconData...)
	value.Version = cloneVersion(value.Version)
	return value
}

func cloneVersionRevocation(value VersionRevocation) VersionRevocation {
	value.SupersedingVersionID = cloneUUIDPointer(value.SupersedingVersionID)
	return value
}

func cloneInstallationCreation(value InstallationCreation) InstallationCreation {
	value.Installation = cloneInstallation(value.Installation)
	value.Policy = clonePolicySnapshot(value.Policy)
	return value
}

func cloneInstallation(value Installation) Installation {
	value.RuntimeProfileID = cloneUUIDPointer(value.RuntimeProfileID)
	value.PolicySnapshotID = cloneUUIDPointer(value.PolicySnapshotID)
	value.OfficialReleaseID = cloneUUIDPointer(value.OfficialReleaseID)
	value.SelectedReleaseRevisionID = cloneUUIDPointer(value.SelectedReleaseRevisionID)
	value.ActivatedAt = cloneTimePointer(value.ActivatedAt)
	value.ArchivedAt = cloneTimePointer(value.ArchivedAt)
	return value
}

func cloneOfficialEligibilityContextPointer(value *OfficialEligibilityContext) *OfficialEligibilityContext {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func clonePolicySnapshot(value PolicySnapshot) PolicySnapshot {
	value.Document = append([]byte(nil), value.Document...)
	value.Signature = append([]byte(nil), value.Signature...)
	return value
}

func policySnapshotFromMaterial(material PolicyMaterial) PolicySnapshot {
	return PolicySnapshot{
		ID: material.ID, InstallationID: material.InstallationID, AgentVersionID: material.AgentVersionID,
		PolicyVersion: material.PolicyVersion, Document: append([]byte(nil), material.Document...),
		ContentDigest: material.ContentDigest, Issuer: material.Issuer, SigningKeyID: material.SigningKeyID,
		Signature: append([]byte(nil), material.Signature...), CreatedAt: material.CreatedAt,
	}
}

func runtimeBindingFromCommand(command PersistRuntimeBindingCommand) RuntimeBindingRecord {
	return RuntimeBindingRecord{
		ID: command.BindingID, AgentInstallationID: command.AgentInstallationID,
		AgentVersionID: command.AgentVersionID, RuntimeProfileID: command.RuntimeProfileID,
		RuntimeVersion: command.RuntimeVersion, PolicySnapshotID: command.PolicySnapshotID,
		ToolPermissionDigest: command.ToolPermissionDigest, CreatedAt: command.CreatedAt.UTC(),
	}
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func uuidStringPointer(value *uuid.UUID) *string {
	if value == nil {
		return nil
	}
	text := value.String()
	return &text
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
