package agentcontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type experienceCandidateVectorFile struct {
	ContractVersion     string                             `json:"contract_version"`
	CanonicalCases      []experienceCandidateCanonicalCase `json:"canonical_cases"`
	CanonicalRejections []experienceCandidateCanonicalCase `json:"canonical_rejections"`
	DLPCases            []experienceCandidateDLPVectorCase `json:"dlp_cases"`
}

type experienceCandidateCanonicalCase struct {
	Name                    string                      `json:"name"`
	Bundle                  ExperienceCandidateBundleV1 `json:"bundle"`
	CanonicalJSON           string                      `json:"canonical_json"`
	ContentDigest           string                      `json:"content_digest"`
	FirstAssetContentBase64 string                      `json:"first_asset_content_base64"`
}

type experienceCandidateDLPVectorCase struct {
	Name     string                       `json:"name"`
	Bundle   ExperienceCandidateBundleV1  `json:"bundle"`
	Findings []ExperienceCandidateFinding `json:"findings"`
}

func TestCanonicalizeExperienceCandidateVectors(t *testing.T) {
	vectors := loadExperienceCandidateVectors(t)
	if vectors.ContractVersion != ExperienceCandidateDLPVersion {
		t.Fatalf("contract version = %q, want %q", vectors.ContractVersion, ExperienceCandidateDLPVersion)
	}
	for _, vector := range vectors.CanonicalCases {
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := CanonicalizeExperienceCandidate(vector.Bundle)
			if err != nil {
				t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
			}
			if !bytes.Equal(canonical.CanonicalJSON, []byte(vector.CanonicalJSON)) {
				t.Fatalf("canonical JSON = %s, want %s", canonical.CanonicalJSON, vector.CanonicalJSON)
			}
			if got := hex.EncodeToString(canonical.ContentDigest[:]); got != vector.ContentDigest {
				t.Fatalf("content digest = %s, want %s", got, vector.ContentDigest)
			}
		})
	}
}

func TestCanonicalizeExperienceCandidateRejectsLockedVectors(t *testing.T) {
	for _, vector := range loadExperienceCandidateVectors(t).CanonicalRejections {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.FirstAssetContentBase64 != "" {
				raw, err := base64.StdEncoding.DecodeString(vector.FirstAssetContentBase64)
				if err != nil {
					t.Fatalf("decode fixture bytes: %v", err)
				}
				vector.Bundle.Assets[0].Content = string(raw)
			}
			if _, err := CanonicalizeExperienceCandidate(vector.Bundle); err == nil {
				t.Fatal("CanonicalizeExperienceCandidate() accepted locked rejection vector")
			}
		})
	}
}

func TestCanonicalizeExperienceCandidateSortsAssetsAndNormalizesPaths(t *testing.T) {
	bundle := validExperienceCandidateBundle()
	bundle.Assets = append(bundle.Assets,
		ExperienceCandidateAssetV1{
			Path: "skills/weekly-summary/ze\u0301ro.txt", MediaType: MediaTypeTextPlain, Content: "zero\n",
		},
		ExperienceCandidateAssetV1{
			Path: "skills/weekly-summary/alpha.txt", MediaType: MediaTypeTextPlain, Content: "alpha\n",
		},
	)
	canonical, err := CanonicalizeExperienceCandidate(bundle)
	if err != nil {
		t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
	}
	paths := []string{
		canonical.Bundle.Assets[0].Path,
		canonical.Bundle.Assets[1].Path,
		canonical.Bundle.Assets[2].Path,
	}
	want := []string{
		"skills/weekly-summary/SKILL.md",
		"skills/weekly-summary/alpha.txt",
		"skills/weekly-summary/zéro.txt",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("asset paths = %#v, want %#v", paths, want)
	}

	bundle.Assets = append(bundle.Assets, ExperienceCandidateAssetV1{
		Path: "skills/weekly-summary/zéro.txt", MediaType: MediaTypeTextPlain, Content: "duplicate\n",
	})
	if _, err := CanonicalizeExperienceCandidate(bundle); err == nil {
		t.Fatal("CanonicalizeExperienceCandidate() accepted normalized duplicate paths")
	}
}

func TestCanonicalizeExperienceCandidateEnforcesLimits(t *testing.T) {
	t.Run("file count", func(t *testing.T) {
		bundle := validExperienceCandidateBundle()
		for index := 1; index <= MaxExperienceCandidateFiles; index++ {
			bundle.Assets = append(bundle.Assets, ExperienceCandidateAssetV1{
				Path:      fmt.Sprintf("skills/weekly-summary/file-%03d.txt", index),
				MediaType: MediaTypeTextPlain,
				Content:   "x",
			})
		}
		if _, err := CanonicalizeExperienceCandidate(bundle); err == nil {
			t.Fatal("CanonicalizeExperienceCandidate() accepted too many files")
		}
	})

	t.Run("single file bytes", func(t *testing.T) {
		bundle := validExperienceCandidateBundle()
		bundle.Assets[0].Content = strings.Repeat("x", MaxExperienceCandidateFileBytes+1)
		if _, err := CanonicalizeExperienceCandidate(bundle); err == nil {
			t.Fatal("CanonicalizeExperienceCandidate() accepted an oversized file")
		}
	})

	t.Run("total bytes", func(t *testing.T) {
		bundle := validExperienceCandidateBundle()
		bundle.Assets[0].Content = strings.Repeat("x", MaxExperienceCandidateFileBytes)
		for index := 0; index < 4; index++ {
			bundle.Assets = append(bundle.Assets, ExperienceCandidateAssetV1{
				Path:      "skills/weekly-summary/part-" + string(rune('a'+index)) + ".txt",
				MediaType: MediaTypeTextPlain,
				Content:   strings.Repeat("x", MaxExperienceCandidateFileBytes),
			})
		}
		if _, err := CanonicalizeExperienceCandidate(bundle); err == nil {
			t.Fatal("CanonicalizeExperienceCandidate() accepted an oversized bundle")
		}
	})
}

func TestCanonicalizeExperienceCandidateDoesNotMutateInput(t *testing.T) {
	bundle := validExperienceCandidateBundle()
	original, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CanonicalizeExperienceCandidate(bundle); err != nil {
		t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
	}
	after, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatalf("input mutated:\nbefore %s\nafter  %s", original, after)
	}
}

func validExperienceCandidateBundle() ExperienceCandidateBundleV1 {
	return ExperienceCandidateBundleV1{
		SchemaVersion: 1,
		SkillName:     "weekly-summary",
		Assets: []ExperienceCandidateAssetV1{{
			Path:      "skills/weekly-summary/SKILL.md",
			MediaType: MediaTypeTextMarkdown,
			Content:   "# Weekly summary\n",
		}},
	}
}

func loadExperienceCandidateVectors(t *testing.T) experienceCandidateVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "experience-candidate-v1-vectors.json"))
	if err != nil {
		t.Fatalf("read candidate vectors: %v", err)
	}
	var vectors experienceCandidateVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode candidate vectors: %v", err)
	}
	return vectors
}
