package agentcontrol

import (
	"bytes"
	"crypto/sha256"
	"strings"

	"github.com/google/uuid"
)

type OrganizationSubmissionKind string

const (
	OrganizationSubmissionInitial OrganizationSubmissionKind = "initial"
	OrganizationSubmissionNext    OrganizationSubmissionKind = "next"
)

type OrganizationSubmissionStatus string

const (
	OrganizationSubmissionPending    OrganizationSubmissionStatus = "pending"
	OrganizationSubmissionApproved   OrganizationSubmissionStatus = "approved"
	OrganizationSubmissionRejected   OrganizationSubmissionStatus = "rejected"
	OrganizationSubmissionWithdrawn  OrganizationSubmissionStatus = "withdrawn"
	OrganizationSubmissionSuperseded OrganizationSubmissionStatus = "superseded"
)

type OrganizationReviewDecision string

const (
	OrganizationReviewApprove OrganizationReviewDecision = "approve"
	OrganizationReviewReject  OrganizationReviewDecision = "reject"
)

type OrganizationSubmissionPackage struct {
	Kind          OrganizationSubmissionKind
	DefinitionID  uuid.UUID
	BaseVersionID uuid.UUID
	DisplayName   string
	IconMediaType string
	IconData      []byte
	Manifest      AgentManifestV1
	Bundle        VersionBundleV1
}

type CanonicalOrganizationSubmission struct {
	Package        OrganizationSubmissionPackage
	ManifestDigest [sha256.Size]byte
	BundleDigest   [sha256.Size]byte
	ContentDigest  [sha256.Size]byte
}

func CanonicalizeOrganizationSubmission(
	input OrganizationSubmissionPackage,
) (CanonicalOrganizationSubmission, error) {
	displayName := strings.TrimSpace(input.DisplayName)
	if input.DefinitionID == uuid.Nil {
		return CanonicalOrganizationSubmission{}, ErrInvalidAgentContent
	}
	switch input.Kind {
	case OrganizationSubmissionInitial:
		if input.BaseVersionID != uuid.Nil || !validText(displayName, 1, 100) ||
			(input.IconMediaType == "") != (len(input.IconData) == 0) ||
			(input.IconMediaType != "" && ValidateIcon(input.IconMediaType, input.IconData) != nil) {
			return CanonicalOrganizationSubmission{}, ErrInvalidAgentContent
		}
	case OrganizationSubmissionNext:
		if input.BaseVersionID == uuid.Nil || input.DisplayName != "" ||
			input.IconMediaType != "" || len(input.IconData) != 0 {
			return CanonicalOrganizationSubmission{}, ErrInvalidAgentContent
		}
	default:
		return CanonicalOrganizationSubmission{}, ErrInvalidAgentContent
	}

	version, err := CanonicalizeVersion(input.Manifest, input.Bundle)
	if err != nil {
		return CanonicalOrganizationSubmission{}, err
	}
	var manifest AgentManifestV1
	if err := decodeStrictJSON(version.ManifestJSON, &manifest); err != nil {
		return CanonicalOrganizationSubmission{}, ErrInvalidAgentContent
	}
	var bundle VersionBundleV1
	if err := decodeStrictJSON(version.BundleJSON, &bundle); err != nil {
		return CanonicalOrganizationSubmission{}, ErrInvalidAgentContent
	}

	return CanonicalOrganizationSubmission{
		Package: OrganizationSubmissionPackage{
			Kind:          input.Kind,
			DefinitionID:  input.DefinitionID,
			BaseVersionID: input.BaseVersionID,
			DisplayName:   displayName,
			IconMediaType: input.IconMediaType,
			IconData:      bytes.Clone(input.IconData),
			Manifest:      manifest,
			Bundle:        bundle,
		},
		ManifestDigest: version.ManifestDigest,
		BundleDigest:   version.BundleDigest,
		ContentDigest:  version.ContentDigest,
	}, nil
}
