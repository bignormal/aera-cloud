package agentcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

type SubmitExperienceCandidateRequest struct {
	DefinitionID    uuid.UUID
	SourceVersionID uuid.UUID
	Bundle          ExperienceCandidateBundleV1
	ContentDigest   string
	IdempotencyKey  string
	RequestID       string
}

type ReviewExperienceCandidateRequest struct {
	CandidateID    uuid.UUID
	Decision       ExperienceCandidateDecision
	ReasonCode     string
	SafeNote       string
	IdempotencyKey string
	RequestID      string
}

type ExperienceCandidateDLPError struct {
	Findings []ExperienceCandidateFinding
}

func (e *ExperienceCandidateDLPError) Error() string {
	return "ExperienceCandidate content was blocked"
}

func (s *Service) SubmitExperienceCandidate(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	request SubmitExperienceCandidateRequest,
) (ExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil || request.DefinitionID == uuid.Nil ||
		request.SourceVersionID == uuid.Nil || !validIdempotencyKey(request.IdempotencyKey) ||
		!validRequestID(request.RequestID) {
		return ExperienceCandidate{}, ErrInvalidRequest
	}
	canonical, err := CanonicalizeExperienceCandidate(request.Bundle)
	if err != nil {
		return ExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	providedDigest, ok := decodeExperienceCandidateDigest(request.ContentDigest)
	if !ok || subtle.ConstantTimeCompare(providedDigest[:], canonical.ContentDigest[:]) != 1 {
		return ExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	if findings := ScanExperienceCandidate(canonical); len(findings) != 0 {
		return ExperienceCandidate{}, &ExperienceCandidateDLPError{Findings: cloneExperienceCandidateFindings(findings)}
	}
	requestHash, err := hashRequest(struct {
		Operation          string `json:"operation"`
		WorkspaceID        string `json:"workspace_id"`
		DefinitionID       string `json:"definition_id"`
		SourceVersionID    string `json:"source_version_id"`
		ContentDigest      string `json:"content_digest"`
		DLPContractVersion string `json:"dlp_contract_version"`
	}{
		Operation: operationSubmitExperienceCandidate, WorkspaceID: workspaceID.String(),
		DefinitionID: request.DefinitionID.String(), SourceVersionID: request.SourceVersionID.String(),
		ContentDigest: request.ContentDigest, DLPContractVersion: ExperienceCandidateDLPVersion,
	})
	if err != nil {
		return ExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	identifiers, ok := s.newExperienceCandidateIDs(3)
	if !ok {
		return ExperienceCandidate{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	candidate, _, err := s.repository.SubmitExperienceCandidate(ctx, principal, SubmitExperienceCandidateCommand{
		CandidateID: identifiers[0], WorkspaceID: workspaceID, DefinitionID: request.DefinitionID,
		SourceVersionID: request.SourceVersionID, SkillName: canonical.Bundle.SkillName,
		Canonical: canonical, DLPVersion: ExperienceCandidateDLPVersion,
		Idempotency: IdempotencyEvidence{
			ID: identifiers[1], KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: identifiers[2], RequestID: request.RequestID}, CreatedAt: now,
	})
	if err != nil {
		return ExperienceCandidate{}, err
	}
	return cloneExperienceCandidate(candidate), nil
}

func (s *Service) ListOwnExperienceCandidates(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]ExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	candidates, err := s.repository.ListOwnExperienceCandidates(ctx, principal, workspaceID)
	if err != nil {
		return nil, err
	}
	return cloneExperienceCandidates(candidates), nil
}

func (s *Service) ListWorkspaceExperienceCandidates(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]ExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	candidates, err := s.repository.ListWorkspaceExperienceCandidates(ctx, principal, workspaceID)
	if err != nil {
		return nil, err
	}
	return cloneExperienceCandidates(candidates), nil
}

func (s *Service) GetExperienceCandidate(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	candidateID uuid.UUID,
	requestID string,
) (ExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil || candidateID == uuid.Nil ||
		!validRequestID(requestID) {
		return ExperienceCandidate{}, ErrInvalidRequest
	}
	auditID, ok := s.newExperienceCandidateID()
	if !ok {
		return ExperienceCandidate{}, ErrServiceUnavailable
	}
	candidate, found, err := s.repository.FindExperienceCandidate(
		ctx, principal, workspaceID, candidateID,
		AuditEvidence{EventID: auditID, RequestID: requestID}, s.clock().UTC(),
	)
	if err != nil {
		return ExperienceCandidate{}, err
	}
	if !found {
		return ExperienceCandidate{}, ErrNotFound
	}
	return cloneExperienceCandidate(candidate), nil
}

func (s *Service) ReviewExperienceCandidate(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	request ReviewExperienceCandidateRequest,
) (ExperienceCandidate, error) {
	if s == nil || !validPrincipal(principal) || workspaceID == uuid.Nil || request.CandidateID == uuid.Nil ||
		!validIdempotencyKey(request.IdempotencyKey) || !validRequestID(request.RequestID) ||
		!validExperienceCandidateReview(request) {
		return ExperienceCandidate{}, ErrInvalidRequest
	}
	requestHash, err := hashRequest(struct {
		Operation   string                      `json:"operation"`
		WorkspaceID string                      `json:"workspace_id"`
		CandidateID string                      `json:"candidate_id"`
		Decision    ExperienceCandidateDecision `json:"decision"`
		ReasonCode  string                      `json:"reason_code,omitempty"`
		SafeNote    string                      `json:"safe_note,omitempty"`
	}{
		Operation: operationReviewExperienceCandidate, WorkspaceID: workspaceID.String(),
		CandidateID: request.CandidateID.String(), Decision: request.Decision,
		ReasonCode: request.ReasonCode, SafeNote: request.SafeNote,
	})
	if err != nil {
		return ExperienceCandidate{}, ErrInvalidRequest
	}
	identifiers, ok := s.newExperienceCandidateIDs(3)
	if !ok {
		return ExperienceCandidate{}, ErrServiceUnavailable
	}
	now := s.clock().UTC()
	candidate, _, err := s.repository.ReviewExperienceCandidate(ctx, principal, ReviewExperienceCandidateCommand{
		ReviewID: identifiers[0], WorkspaceID: workspaceID, CandidateID: request.CandidateID,
		Decision: request.Decision, ReasonCode: request.ReasonCode, SafeNote: request.SafeNote,
		Idempotency: IdempotencyEvidence{
			ID: identifiers[1], KeyHash: sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestHash: requestHash, ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: identifiers[2], RequestID: request.RequestID}, ReviewedAt: now,
	})
	if err != nil {
		return ExperienceCandidate{}, err
	}
	return cloneExperienceCandidate(candidate), nil
}

func validExperienceCandidateReview(request ReviewExperienceCandidateRequest) bool {
	switch request.Decision {
	case ExperienceCandidateApproved:
		return request.ReasonCode == "" && request.SafeNote == ""
	case ExperienceCandidateRejected:
		return experienceCandidateReasonPattern.MatchString(request.ReasonCode) &&
			(request.SafeNote == "" || validExperienceCandidateReviewNote(request.SafeNote))
	default:
		return false
	}
}

func validExperienceCandidateReviewNote(value string) bool {
	if !validToken(value, 240) || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, rule := range publicationDLPRules {
		if rule.pattern.MatchString(value) {
			return false
		}
	}
	return true
}

func decodeExperienceCandidateDigest(value string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return digest, false
	}
	copy(digest[:], decoded)
	return digest, true
}

func (s *Service) newExperienceCandidateID() (uuid.UUID, bool) {
	if s == nil || s.newID == nil {
		return uuid.Nil, false
	}
	identifier := s.newID()
	return identifier, identifier != uuid.Nil
}

func (s *Service) newExperienceCandidateIDs(count int) ([]uuid.UUID, bool) {
	if count <= 0 {
		return nil, false
	}
	identifiers := make([]uuid.UUID, 0, count)
	seen := make(map[uuid.UUID]struct{}, count)
	for len(identifiers) < count {
		identifier, ok := s.newExperienceCandidateID()
		if !ok {
			return nil, false
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, false
		}
		seen[identifier] = struct{}{}
		identifiers = append(identifiers, identifier)
	}
	return identifiers, true
}

func cloneExperienceCandidateFindings(values []ExperienceCandidateFinding) []ExperienceCandidateFinding {
	if values == nil {
		return nil
	}
	return append([]ExperienceCandidateFinding(nil), values...)
}

func cloneExperienceCandidates(values []ExperienceCandidate) []ExperienceCandidate {
	if values == nil {
		return nil
	}
	cloned := make([]ExperienceCandidate, len(values))
	for index, candidate := range values {
		cloned[index] = cloneExperienceCandidate(candidate)
	}
	return cloned
}

func cloneExperienceCandidate(value ExperienceCandidate) ExperienceCandidate {
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
