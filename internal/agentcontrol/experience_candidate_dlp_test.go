package agentcontrol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestScanExperienceCandidateVectors(t *testing.T) {
	vectors := loadExperienceCandidateVectors(t)
	for _, vector := range vectors.DLPCases {
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := CanonicalizeExperienceCandidate(vector.Bundle)
			if err != nil {
				t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
			}
			if findings := ScanExperienceCandidate(canonical); !reflect.DeepEqual(findings, vector.Findings) {
				t.Fatalf("findings = %#v, want %#v", findings, vector.Findings)
			}
		})
	}
}

func TestExperienceCandidateFindingsDoNotLeakEvidence(t *testing.T) {
	for _, vector := range loadExperienceCandidateVectors(t).DLPCases {
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := CanonicalizeExperienceCandidate(vector.Bundle)
			if err != nil {
				t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
			}
			encoded, err := json.Marshal(ScanExperienceCandidate(canonical))
			if err != nil {
				t.Fatalf("marshal findings: %v", err)
			}
			serialized := string(encoded)
			for _, forbidden := range []string{
				"abcdefghijklmnopqrstuvwxyz012345",
				"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				"correct-horse-battery",
				"/Users/alice/.hermes/profiles/work",
				`C:\Users\Alice\.hermes\profiles\work`,
				"private preference",
				"session-1",
				"conversation-1",
			} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("findings leaked source evidence %q: %s", forbidden, serialized)
				}
			}
		})
	}
}

func TestScanExperienceCandidateReturnsNoFindingsForSafeContent(t *testing.T) {
	canonical, err := CanonicalizeExperienceCandidate(validExperienceCandidateBundle())
	if err != nil {
		t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
	}
	if findings := ScanExperienceCandidate(canonical); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}
