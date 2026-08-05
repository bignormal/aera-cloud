package agentcontrol

import (
	"context"
	"crypto/sha256"

	"github.com/google/uuid"
)

type SubmitOrganizationExperienceCandidateRequest struct {
	DefinitionID       uuid.UUID
	SourceVersionID    uuid.UUID
	SkillName          string
	SchemaVersion      int
	DLPContractVersion string
	Bundle             ExperienceCandidateBundleV1
	IdempotencyKey     string
	RequestID          string
}

type ReviewOrganizationExperienceCandidateRequest struct {
	CandidateID    uuid.UUID
	Decision       ExperienceCandidateDecision
	ReasonCode     string
	SafeNote       string
	IdempotencyKey string
	RequestID      string
}

func (s *Service) SubmitOrganizationExperienceCandidate(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	request SubmitOrganizationExperienceCandidateRequest,
) (OrganizationExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil ||
		request.DefinitionID == uuid.Nil || request.SourceVersionID == uuid.Nil ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) {
		return OrganizationExperienceCandidate{}, ErrInvalidRequest
	}
	canonical, err := CanonicalizeExperienceCandidate(request.Bundle)
	if err != nil || request.SchemaVersion != ExperienceCandidateSchemaVersion ||
		request.DLPContractVersion != ExperienceCandidateDLPVersion ||
		request.SkillName != canonical.Bundle.SkillName || request.SchemaVersion != canonical.Bundle.SchemaVersion {
		return OrganizationExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	if findings := ScanExperienceCandidate(canonical); len(findings) != 0 {
		return OrganizationExperienceCandidate{}, &ExperienceCandidateDLPError{
			Findings: cloneExperienceCandidateFindings(findings),
		}
	}
	requestHash, err := hashRequest(struct {
		Operation          string `json:"operation"`
		OrganizationID     string `json:"organization_id"`
		DefinitionID       string `json:"definition_id"`
		SourceVersionID    string `json:"source_version_id"`
		SkillName          string `json:"skill_name"`
		SchemaVersion      int    `json:"schema_version"`
		DLPContractVersion string `json:"dlp_contract_version"`
		ContentDigest      string `json:"content_digest"`
	}{
		Operation:      operationSubmitOrganizationExperienceCandidate,
		OrganizationID: organizationID.String(), DefinitionID: request.DefinitionID.String(),
		SourceVersionID: request.SourceVersionID.String(), SkillName: request.SkillName,
		SchemaVersion: request.SchemaVersion, DLPContractVersion: request.DLPContractVersion,
		ContentDigest: digestArrayHex(canonical.ContentDigest),
	})
	if err != nil {
		return OrganizationExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	identifiers, ok := s.newExperienceCandidateIDs(3)
	if !ok {
		return OrganizationExperienceCandidate{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	candidate, _, err := s.repository.SubmitOrganizationExperienceCandidate(
		ctx,
		principal,
		SubmitOrganizationExperienceCandidateCommand{
			CandidateID: identifiers[0], OrganizationID: organizationID,
			DefinitionID: request.DefinitionID, SourceVersionID: request.SourceVersionID,
			SkillName: request.SkillName, Canonical: canonical, DLPVersion: request.DLPContractVersion,
			Idempotency: IdempotencyEvidence{
				ID: identifiers[1], KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
				RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
			},
			Audit: AuditEvidence{EventID: identifiers[2], RequestID: request.RequestID}, CreatedAt: now,
		},
	)
	if err != nil {
		return OrganizationExperienceCandidate{}, err
	}
	return cloneOrganizationExperienceCandidate(candidate), nil
}

func (s *Service) ListOwnOrganizationExperienceCandidates(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
) ([]OrganizationExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	candidates, err := s.repository.ListOwnOrganizationExperienceCandidates(ctx, principal, organizationID)
	if err != nil {
		return nil, err
	}
	return cloneOrganizationExperienceCandidates(candidates), nil
}

func (s *Service) ListOrganizationExperienceCandidates(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
) ([]OrganizationExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	candidates, err := s.repository.ListOrganizationExperienceCandidates(ctx, principal, organizationID)
	if err != nil {
		return nil, err
	}
	return cloneOrganizationExperienceCandidates(candidates), nil
}

func (s *Service) GetOrganizationExperienceCandidate(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	candidateID uuid.UUID,
	requestID string,
) (OrganizationExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil || candidateID == uuid.Nil ||
		!validRequestID(requestID) {
		return OrganizationExperienceCandidate{}, ErrInvalidRequest
	}
	auditID, ok := s.newExperienceCandidateID()
	if !ok {
		return OrganizationExperienceCandidate{}, ErrServiceUnavailable
	}
	candidate, found, err := s.repository.FindOrganizationExperienceCandidate(
		ctx, principal, organizationID, candidateID,
		AuditEvidence{EventID: auditID, RequestID: requestID}, s.clock().UTC(),
	)
	if err != nil {
		return OrganizationExperienceCandidate{}, err
	}
	if !found {
		return OrganizationExperienceCandidate{}, ErrOrganizationAgentNotFound
	}
	return cloneOrganizationExperienceCandidate(candidate), nil
}

func (s *Service) ReviewOrganizationExperienceCandidate(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	request ReviewOrganizationExperienceCandidateRequest,
) (OrganizationExperienceCandidate, error) {
	workspaceRequest := ReviewExperienceCandidateRequest{
		CandidateID: request.CandidateID, Decision: request.Decision,
		ReasonCode: request.ReasonCode, SafeNote: request.SafeNote,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
	}
	if s == nil || !validPrincipal(principal) || organizationID == uuid.Nil || request.CandidateID == uuid.Nil ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) ||
		!validExperienceCandidateReview(workspaceRequest) {
		return OrganizationExperienceCandidate{}, ErrInvalidRequest
	}
	requestHash, err := hashRequest(struct {
		Operation      string                      `json:"operation"`
		OrganizationID string                      `json:"organization_id"`
		CandidateID    string                      `json:"candidate_id"`
		Decision       ExperienceCandidateDecision `json:"decision"`
		ReasonCode     string                      `json:"reason_code,omitempty"`
		SafeNote       string                      `json:"safe_note,omitempty"`
	}{
		Operation:      operationReviewOrganizationExperienceCandidate,
		OrganizationID: organizationID.String(), CandidateID: request.CandidateID.String(),
		Decision: request.Decision, ReasonCode: request.ReasonCode, SafeNote: request.SafeNote,
	})
	if err != nil {
		return OrganizationExperienceCandidate{}, ErrInvalidRequest
	}
	identifiers, ok := s.newExperienceCandidateIDs(3)
	if !ok {
		return OrganizationExperienceCandidate{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	candidate, _, err := s.repository.ReviewOrganizationExperienceCandidate(
		ctx,
		principal,
		ReviewOrganizationExperienceCandidateCommand{
			OrganizationID: organizationID, CandidateID: request.CandidateID, ReviewID: identifiers[0],
			Decision: request.Decision, ReasonCode: request.ReasonCode, SafeNote: request.SafeNote,
			Idempotency: IdempotencyEvidence{
				ID: identifiers[1], KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
				RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
			},
			Audit: AuditEvidence{EventID: identifiers[2], RequestID: request.RequestID}, ReviewedAt: now,
		},
	)
	if err != nil {
		return OrganizationExperienceCandidate{}, err
	}
	return cloneOrganizationExperienceCandidate(candidate), nil
}

func cloneOrganizationExperienceCandidates(values []OrganizationExperienceCandidate) []OrganizationExperienceCandidate {
	if values == nil {
		return nil
	}
	cloned := make([]OrganizationExperienceCandidate, len(values))
	for index, candidate := range values {
		cloned[index] = cloneOrganizationExperienceCandidate(candidate)
	}
	return cloned
}

func cloneOrganizationExperienceCandidate(value OrganizationExperienceCandidate) OrganizationExperienceCandidate {
	value.SubmittedByUserID = cloneUUIDPointer(value.SubmittedByUserID)
	value.SubmittedFromDeviceID = cloneUUIDPointer(value.SubmittedFromDeviceID)
	assets := make([]ExperienceCandidateAssetV1, len(value.Bundle.Assets))
	copy(assets, value.Bundle.Assets)
	value.Bundle.Assets = assets
	if value.Review != nil {
		review := *value.Review
		review.ReviewedByUserID = cloneUUIDPointer(review.ReviewedByUserID)
		value.Review = &review
	}
	return value
}
