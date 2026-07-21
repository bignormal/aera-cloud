package agentcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var organizationReviewReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type SubmitOrganizationAgentRequest struct {
	Package        OrganizationSubmissionPackage
	IdempotencyKey string
	RequestID      string
}

type WithdrawOrganizationAgentRequest struct {
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type ReviewOrganizationAgentRequest struct {
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	Decision         OrganizationReviewDecision
	ReasonCode       string
	SafeNote         string
	IdempotencyKey   string
	RequestID        string
}

type OrganizationPublicationDLPError struct {
	Findings []ExperienceCandidateFinding
}

func (err *OrganizationPublicationDLPError) Error() string {
	return ErrOrganizationPublicationDLPBlocked.Error()
}

func (err *OrganizationPublicationDLPError) Unwrap() error {
	return ErrOrganizationPublicationDLPBlocked
}

func (s *Service) SubmitOrganizationAgent(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	request SubmitOrganizationAgentRequest,
) (OrganizationAgentSubmission, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}

	input := request.Package
	identifierCount := 3
	if input.Kind == OrganizationSubmissionInitial {
		if input.DefinitionID != uuid.Nil || input.BaseVersionID != uuid.Nil {
			return OrganizationAgentSubmission{}, ErrInvalidRequest
		}
		identifierCount = 4
	} else if input.Kind != OrganizationSubmissionNext || input.DefinitionID == uuid.Nil || input.BaseVersionID == uuid.Nil {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}
	identifiers, ok := s.newOrganizationSubmissionIDs(identifierCount)
	if !ok {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	input.DefinitionID = identifiers[1]
	if input.Kind == OrganizationSubmissionNext {
		input.DefinitionID = request.Package.DefinitionID
	}
	canonical, err := CanonicalizeOrganizationSubmission(input)
	if err != nil {
		return OrganizationAgentSubmission{}, ErrInvalidAgentContent
	}
	findings := ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle))
	if len(findings) != 0 {
		return OrganizationAgentSubmission{}, &OrganizationPublicationDLPError{
			Findings: cloneExperienceCandidateFindings(findings),
		}
	}
	if err := validateOrganizationPublicationPolicy(canonical.Package.Manifest, canonical.Package.Bundle); err != nil {
		return OrganizationAgentSubmission{}, err
	}

	requestHash, err := hashRequest(struct {
		Operation      string                     `json:"operation"`
		ActorUserID    string                     `json:"actor_user_id"`
		OrganizationID string                     `json:"organization_id"`
		Kind           OrganizationSubmissionKind `json:"kind"`
		DefinitionID   string                     `json:"definition_id,omitempty"`
		BaseVersionID  string                     `json:"base_version_id,omitempty"`
		DisplayName    string                     `json:"display_name,omitempty"`
		IconMediaType  string                     `json:"icon_media_type,omitempty"`
		IconDigest     string                     `json:"icon_digest,omitempty"`
		ContentDigest  string                     `json:"content_digest"`
		DLPVersion     string                     `json:"dlp_version"`
	}{
		Operation: "submit_organization_agent", ActorUserID: principal.UserID.String(),
		OrganizationID: organizationID.String(), Kind: request.Package.Kind,
		DefinitionID: request.Package.DefinitionID.String(), BaseVersionID: request.Package.BaseVersionID.String(),
		DisplayName: canonical.Package.DisplayName, IconMediaType: canonical.Package.IconMediaType,
		IconDigest: digestHex(canonical.Package.IconData), ContentDigest: digestArrayHex(canonical.ContentDigest),
		DLPVersion: AgentPublicationDLPVersion,
	})
	if err != nil {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}
	now := s.clock().UTC()
	idempotencyIndex := 2
	auditIndex := 3
	if input.Kind == OrganizationSubmissionNext {
		idempotencyIndex = 1
		auditIndex = 2
	}
	result, err := s.repository.SubmitOrganizationAgent(ctx, SubmitOrganizationAgentCommand{
		SubmissionID: identifiers[0], OrganizationID: organizationID, Principal: principal,
		Canonical: canonical,
		Idempotency: IdempotencyEvidence{
			ID: identifiers[idempotencyIndex], KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit:       AuditEvidence{EventID: identifiers[auditIndex], RequestID: request.RequestID},
		SubmittedAt: now,
	})
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return cloneOrganizationAgentSubmission(result), nil
}

func (s *Service) ListOrganizationAgentSubmissions(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
) ([]OrganizationAgentSubmission, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	values, err := s.repository.ListOrganizationAgentSubmissions(ctx, principal, organizationID)
	if err != nil {
		return nil, err
	}
	return cloneOrganizationAgentSubmissions(values), nil
}

func (s *Service) GetOrganizationAgentSubmission(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	submissionID uuid.UUID,
) (OrganizationAgentSubmission, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil || submissionID == uuid.Nil {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}
	value, found, err := s.repository.FindOrganizationAgentSubmission(ctx, principal, organizationID, submissionID)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if !found {
		return OrganizationAgentSubmission{}, ErrOrganizationAgentNotFound
	}
	return cloneOrganizationAgentSubmission(value), nil
}

func (s *Service) WithdrawOrganizationAgentSubmission(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	request WithdrawOrganizationAgentRequest,
) (OrganizationAgentSubmission, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil || request.SubmissionID == uuid.Nil ||
		request.ExpectedRevision <= 0 || !validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}
	requestHash, err := hashRequest(struct {
		Operation        string `json:"operation"`
		ActorUserID      string `json:"actor_user_id"`
		OrganizationID   string `json:"organization_id"`
		SubmissionID     string `json:"submission_id"`
		ExpectedRevision int64  `json:"expected_revision"`
	}{
		Operation: "withdraw_organization_agent", ActorUserID: principal.UserID.String(),
		OrganizationID: organizationID.String(), SubmissionID: request.SubmissionID.String(),
		ExpectedRevision: request.ExpectedRevision,
	})
	if err != nil {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}
	identifiers, ok := s.newOrganizationSubmissionIDs(2)
	if !ok {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	result, err := s.repository.WithdrawOrganizationAgentSubmission(ctx, WithdrawOrganizationAgentCommand{
		OrganizationID: organizationID, SubmissionID: request.SubmissionID,
		ExpectedRevision: request.ExpectedRevision, Principal: principal,
		Idempotency: IdempotencyEvidence{
			ID: identifiers[0], KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: identifiers[1], RequestID: request.RequestID}, WithdrawnAt: now,
	})
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return cloneOrganizationAgentSubmission(result), nil
}

func (s *Service) ReviewOrganizationAgentSubmission(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	request ReviewOrganizationAgentRequest,
) (OrganizationAgentSubmission, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil || request.SubmissionID == uuid.Nil ||
		request.ExpectedRevision <= 0 || !validOrganizationReviewRequest(request) ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}
	requestHash, err := hashRequest(struct {
		Operation        string                     `json:"operation"`
		ActorUserID      string                     `json:"actor_user_id"`
		OrganizationID   string                     `json:"organization_id"`
		SubmissionID     string                     `json:"submission_id"`
		ExpectedRevision int64                      `json:"expected_revision"`
		Decision         OrganizationReviewDecision `json:"decision"`
		ReasonCode       string                     `json:"reason_code"`
		SafeNote         string                     `json:"safe_note,omitempty"`
	}{
		Operation: "review_organization_agent", ActorUserID: principal.UserID.String(),
		OrganizationID: organizationID.String(), SubmissionID: request.SubmissionID.String(),
		ExpectedRevision: request.ExpectedRevision, Decision: request.Decision,
		ReasonCode: request.ReasonCode, SafeNote: request.SafeNote,
	})
	if err != nil {
		return OrganizationAgentSubmission{}, ErrInvalidRequest
	}
	identifierCount := 3
	if request.Decision == OrganizationReviewApprove {
		identifierCount = 4
	}
	identifiers, ok := s.newOrganizationSubmissionIDs(identifierCount)
	if !ok {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	idempotencyIndex := 1
	auditIndex := 2
	var buildVersion func(CanonicalOrganizationSubmission, int64) (VersionMaterial, error)
	if request.Decision == OrganizationReviewApprove {
		versionID := identifiers[1]
		idempotencyIndex = 2
		auditIndex = 3
		buildVersion = func(
			canonical CanonicalOrganizationSubmission,
			versionNumber int64,
		) (VersionMaterial, error) {
			version, minimum, maximum, err := canonicalizePublication(
				canonical.Package.Manifest, canonical.Package.Bundle,
			)
			if err != nil || version.ManifestDigest != canonical.ManifestDigest ||
				version.BundleDigest != canonical.BundleDigest || version.ContentDigest != canonical.ContentDigest {
				return VersionMaterial{}, ErrInvalidAgentContent
			}
			attestation, err := s.signer.SignVersion(VersionSignatureInput{
				DefinitionID: canonical.Package.DefinitionID, VersionID: versionID,
				VersionNumber: versionNumber, ManifestDigest: canonical.ManifestDigest,
				BundleDigest: canonical.BundleDigest,
			})
			if err != nil {
				return VersionMaterial{}, ErrServiceUnavailable
			}
			return VersionMaterial{
				ID: versionID, VersionNumber: versionNumber,
				CanonicalManifest: append([]byte(nil), version.ManifestJSON...),
				Bundle:            append([]byte(nil), version.BundleJSON...), ContentDigest: version.ContentDigest,
				SigningKeyID: attestation.KeyID, Signature: append([]byte(nil), attestation.Signature...),
				RuntimeMinimumVersion: minimum, RuntimeMaximumVersionExclusive: maximum,
			}, nil
		}
	}
	result, err := s.repository.ReviewOrganizationAgentSubmission(ctx, ReviewOrganizationAgentCommand{
		ReviewID: identifiers[0], OrganizationID: organizationID, SubmissionID: request.SubmissionID,
		ExpectedRevision: request.ExpectedRevision, Principal: principal, Decision: request.Decision,
		ReasonCode: request.ReasonCode, SafeNote: request.SafeNote, BuildVersion: buildVersion,
		Idempotency: IdempotencyEvidence{
			ID: identifiers[idempotencyIndex], KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: identifiers[auditIndex], RequestID: request.RequestID}, ReviewedAt: now,
	})
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return cloneOrganizationAgentSubmission(result), nil
}

func validOrganizationReviewRequest(request ReviewOrganizationAgentRequest) bool {
	switch request.Decision {
	case OrganizationReviewApprove:
		return request.ReasonCode == "" && request.SafeNote == ""
	case OrganizationReviewReject:
		return organizationReviewReasonPattern.MatchString(request.ReasonCode) &&
			(request.SafeNote == "" || validOrganizationReviewNote(request.SafeNote))
	default:
		return false
	}
}

func validateOrganizationPublicationPolicy(manifest AgentManifestV1, bundle VersionBundleV1) error {
	if _, err := CanonicalizeVersion(manifest, bundle); err != nil {
		return ErrOrganizationPublicationPolicyBlocked
	}
	return nil
}

func validOrganizationReviewNote(value string) bool {
	if !validToken(value, 500) || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, rule := range publicationDLPRules {
		if rule.pattern.MatchString(value) {
			return false
		}
	}
	return true
}

func (s *Service) newOrganizationSubmissionIDs(count int) ([]uuid.UUID, bool) {
	return s.newExperienceCandidateIDs(count)
}

func digestArrayHex(value [sha256.Size]byte) string {
	return hex.EncodeToString(value[:])
}
