package agentcontrol

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"time"

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

type OrganizationAgentReview struct {
	ID                           uuid.UUID
	OrganizationID               uuid.UUID
	SubmissionID                 uuid.UUID
	ReviewerUserID               uuid.UUID
	Decision                     OrganizationReviewDecision
	ReasonCode                   string
	SafeNote                     string
	OrganizationPolicySnapshotID uuid.UUID
	OrganizationPolicyVersion    int64
	ReviewedContentDigest        [sha256.Size]byte
	ReviewedAt                   time.Time
}

type OrganizationAgentSubmission struct {
	ID                uuid.UUID
	OrganizationID    uuid.UUID
	Kind              OrganizationSubmissionKind
	DefinitionID      uuid.UUID
	BaseVersionID     uuid.UUID
	DisplayName       string
	IconMediaType     string
	IconData          []byte
	Manifest          AgentManifestV1
	Bundle            VersionBundleV1
	ManifestDigest    [sha256.Size]byte
	BundleDigest      [sha256.Size]byte
	ContentDigest     [sha256.Size]byte
	SubmittedByUserID uuid.UUID
	Status            OrganizationSubmissionStatus
	Revision          int64
	SubmittedAt       time.Time
	TerminalAt        *time.Time
	UpdatedAt         time.Time
	Review            *OrganizationAgentReview
	Replayed          bool
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

func publicationTextAssets(bundle VersionBundleV1) []PublicationTextAsset {
	assets := make([]PublicationTextAsset, len(bundle.Assets))
	for index, asset := range bundle.Assets {
		assets[index] = PublicationTextAsset{Path: asset.Path, Content: asset.Content}
	}
	return assets
}

func cloneOrganizationAgentSubmissions(values []OrganizationAgentSubmission) []OrganizationAgentSubmission {
	if values == nil {
		return nil
	}
	cloned := make([]OrganizationAgentSubmission, len(values))
	for index, value := range values {
		cloned[index] = cloneOrganizationAgentSubmission(value)
	}
	return cloned
}

func cloneOrganizationAgentSubmission(value OrganizationAgentSubmission) OrganizationAgentSubmission {
	value.IconData = bytes.Clone(value.IconData)
	value.Manifest = cloneAgentManifest(value.Manifest)
	value.Bundle = cloneVersionBundle(value.Bundle)
	value.TerminalAt = cloneTimePointer(value.TerminalAt)
	if value.Review != nil {
		review := *value.Review
		value.Review = &review
	}
	return value
}

func cloneAgentManifest(value AgentManifestV1) AgentManifestV1 {
	value.Assets = cloneOrganizationSlice(value.Assets)
	value.ModelConstraints.AllowedProviders = cloneOrganizationSlice(value.ModelConstraints.AllowedProviders)
	value.ModelConstraints.AllowedModels = cloneOrganizationSlice(value.ModelConstraints.AllowedModels)
	value.Tools.Allowed = cloneOrganizationSlice(value.Tools.Allowed)
	value.Tools.Denied = cloneOrganizationSlice(value.Tools.Denied)
	value.Dependencies = cloneOrganizationSlice(value.Dependencies)
	return value
}

func cloneVersionBundle(value VersionBundleV1) VersionBundleV1 {
	value.Assets = cloneOrganizationSlice(value.Assets)
	return value
}

func cloneOrganizationSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	cloned := make([]T, len(values))
	copy(cloned, values)
	return cloned
}
