package agentcontrol

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestCanonicalizeOrganizationSubmissionIsStableAndDetached(t *testing.T) {
	input := lockedOrganizationInitialPackage(t)
	first, err := CanonicalizeOrganizationSubmission(input)
	if err != nil {
		t.Fatalf("CanonicalizeOrganizationSubmission() error = %v", err)
	}

	input.Bundle.Assets[0].Content = "changed after call"
	input.IconData[0] ^= 0xff
	second, err := CanonicalizeOrganizationSubmission(lockedOrganizationInitialPackage(t))
	if err != nil {
		t.Fatalf("second canonicalization error = %v", err)
	}
	if first.ContentDigest != second.ContentDigest || first.ManifestDigest != second.ManifestDigest ||
		first.BundleDigest != second.BundleDigest {
		t.Fatal("canonical Organization submission digests are not stable")
	}
	if first.Package.Bundle.Assets[0].Content == "changed after call" {
		t.Fatal("canonical package aliases caller bundle memory")
	}
	if first.Package.IconData[0] == input.IconData[0] {
		t.Fatal("canonical package aliases caller icon memory")
	}
}

func TestCanonicalizeOrganizationSubmissionEnforcesTaggedVariant(t *testing.T) {
	initial := lockedOrganizationInitialPackage(t)
	next := initial
	next.Kind = OrganizationSubmissionNext
	next.BaseVersionID = uuid.New()
	next.DisplayName = ""
	next.IconMediaType = ""
	next.IconData = nil
	if _, err := CanonicalizeOrganizationSubmission(next); err != nil {
		t.Fatalf("CanonicalizeOrganizationSubmission(valid next) error = %v", err)
	}

	tests := map[string]OrganizationSubmissionPackage{
		"missing definition": func() OrganizationSubmissionPackage {
			value := initial
			value.DefinitionID = uuid.Nil
			return value
		}(),
		"initial with base": func() OrganizationSubmissionPackage {
			value := initial
			value.BaseVersionID = uuid.New()
			return value
		}(),
		"next with display name": func() OrganizationSubmissionPackage {
			value := next
			value.DisplayName = "Forbidden"
			return value
		}(),
		"unknown kind": func() OrganizationSubmissionPackage {
			value := initial
			value.Kind = OrganizationSubmissionKind("replacement")
			return value
		}(),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := CanonicalizeOrganizationSubmission(input); !errors.Is(err, ErrInvalidAgentContent) {
				t.Fatalf("error = %v, want ErrInvalidAgentContent", err)
			}
		})
	}
}

func lockedOrganizationInitialPackage(t *testing.T) OrganizationSubmissionPackage {
	t.Helper()
	manifest, bundle := validManifestFixture()
	return OrganizationSubmissionPackage{
		Kind:          OrganizationSubmissionInitial,
		DefinitionID:  uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		DisplayName:   "Research Agent",
		IconMediaType: "image/png",
		IconData:      encodedPNG(t, 1, 1),
		Manifest:      manifest,
		Bundle:        bundle,
	}
}
