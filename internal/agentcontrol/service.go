package agentcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrInvalidRequest = errors.New("Agent control request is invalid")

const idempotencyLifetime = 24 * time.Hour

type ServiceRepository interface {
	PublishInitial(context.Context, Principal, InitialPublicationCommand) (Publication, error)
	PublishNext(context.Context, Principal, NextPublicationCommand) (Publication, error)
	FindDefinition(context.Context, Principal, uuid.UUID) (Definition, bool, error)
	FindVersion(context.Context, Principal, uuid.UUID) (Version, bool, error)
	ListDefinitions(context.Context, Principal) ([]Definition, error)
	ListVersions(context.Context, Principal, uuid.UUID) ([]Version, error)
	AppendVersionRevocation(context.Context, Principal, VersionRevocationCommand) (VersionRevocation, error)
	RecordDenied(context.Context, Principal, DeniedAuditCommand) error
}

type ServiceConfig struct {
	Repository ServiceRepository
	Signer     *Signer
	Clock      func() time.Time
	NewID      func() uuid.UUID
}

type Service struct {
	repository ServiceRepository
	signer     *Signer
	clock      func() time.Time
	newID      func() uuid.UUID
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
	return &Service{repository: config.Repository, signer: config.Signer, clock: clock, newID: newID}, nil
}

func (s *Service) PublishInitial(
	ctx context.Context,
	principal Principal,
	request PublishInitialRequest,
) (Publication, error) {
	if s == nil || !validPrincipal(principal) ||
		!validPublicationEnvelope(request.DisplayName, request.IdempotencyKey, request.RequestID) {
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
	}{
		Operation: operationPublishInitial, DisplayName: request.DisplayName, IconMediaType: request.IconMediaType,
		IconDigest: digestHex(request.IconData), Manifest: canonical.ManifestJSON, Bundle: canonical.BundleJSON,
	})
	if err != nil {
		return Publication{}, ErrInvalidAgentContent
	}
	now := s.clock().UTC()
	definitionID, versionID, idempotencyID, auditID := s.newID(), s.newID(), s.newID(), s.newID()
	if definitionID == uuid.Nil || versionID == uuid.Nil || idempotencyID == uuid.Nil || auditID == uuid.Nil {
		return Publication{}, ErrServiceUnavailable
	}
	publication, err := s.repository.PublishInitial(ctx, principal, InitialPublicationCommand{
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
	if s == nil || !validPrincipal(principal) || request.DefinitionID == uuid.Nil || request.BaseVersionID == uuid.Nil ||
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
		Manifest      json.RawMessage `json:"manifest"`
		Bundle        json.RawMessage `json:"bundle"`
	}{
		Operation: operationPublishNext, DefinitionID: request.DefinitionID.String(),
		BaseVersionID: request.BaseVersionID.String(), Manifest: canonical.ManifestJSON, Bundle: canonical.BundleJSON,
	})
	if err != nil {
		return Publication{}, ErrInvalidAgentContent
	}
	now := s.clock().UTC()
	versionID, idempotencyID, auditID := s.newID(), s.newID(), s.newID()
	if versionID == uuid.Nil || idempotencyID == uuid.Nil || auditID == uuid.Nil {
		return Publication{}, ErrServiceUnavailable
	}
	publication, err := s.repository.PublishNext(ctx, principal, NextPublicationCommand{
		DefinitionID: request.DefinitionID, BaseVersionID: request.BaseVersionID,
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
	trimmed := strings.TrimSpace(displayName)
	if trimmed == "" || trimmed != displayName || !utf8.ValidString(displayName) || len([]rune(displayName)) > 100 ||
		!validIdempotencyKey(key) || !validRequestID(requestID) {
		return false
	}
	return true
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

func cloneVersionRevocation(value VersionRevocation) VersionRevocation {
	value.SupersedingVersionID = cloneUUIDPointer(value.SupersedingVersionID)
	return value
}

func uuidStringPointer(value *uuid.UUID) *string {
	if value == nil {
		return nil
	}
	text := value.String()
	return &text
}
