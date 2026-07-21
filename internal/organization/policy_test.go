package organization

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDefaultPolicyCanonicalJSONAndDigest(t *testing.T) {
	canonical, err := CanonicalizePolicy(DefaultPolicyDocument())
	if err != nil {
		t.Fatalf("CanonicalizePolicy(default) error = %v", err)
	}
	want := `{"schema_version":1,"models":{"allowlist":null},"tools":{"allowlist":null},"experience_candidates":{"mode":"manual_review"},"official_agents":{"installation":"allowed"}}`
	if string(canonical.CanonicalJSON) != want {
		t.Fatalf("default canonical JSON = %s, want %s", canonical.CanonicalJSON, want)
	}
	if canonical.ContentDigest != sha256.Sum256([]byte(want)) {
		t.Fatalf("default digest = %x", canonical.ContentDigest)
	}
	if canonical.Document.Models.Allowlist != nil || canonical.Document.Tools.Allowlist != nil {
		t.Fatal("default policy did not preserve null inheritance")
	}
}

func TestCanonicalizePolicySortsSetsAndPreservesNullEmptyRestrictSemantics(t *testing.T) {
	document := PolicyDocument{
		SchemaVersion: 1,
		Models: ModelPolicy{Allowlist: []ModelIdentifier{
			{Provider: "openai", Model: "gpt-5.6"},
			{Provider: "anthropic", Model: "claude-opus-5"},
		}},
		Tools:                ToolPolicy{Allowlist: []string{}},
		ExperienceCandidates: ExperienceCandidatePolicy{Mode: ExperienceCandidateManualReview},
		OfficialAgents:       OfficialAgentPolicy{Installation: OfficialAgentInstallationBlocked},
	}
	canonical, err := CanonicalizePolicy(document)
	if err != nil {
		t.Fatalf("CanonicalizePolicy() error = %v", err)
	}
	if !strings.Contains(string(canonical.CanonicalJSON), `"models":{"allowlist":[{"provider":"anthropic","model":"claude-opus-5"},{"provider":"openai","model":"gpt-5.6"}]}`) {
		t.Fatalf("model allowlist is not canonical: %s", canonical.CanonicalJSON)
	}
	if !strings.Contains(string(canonical.CanonicalJSON), `"tools":{"allowlist":[]}`) {
		t.Fatalf("empty deny-all tool list became null: %s", canonical.CanonicalJSON)
	}
	if canonical.Document.Tools.Allowlist == nil || len(canonical.Document.Tools.Allowlist) != 0 {
		t.Fatalf("empty tool allowlist semantics changed: %#v", canonical.Document.Tools.Allowlist)
	}

	document.Models.Allowlist[0], document.Models.Allowlist[1] = document.Models.Allowlist[1], document.Models.Allowlist[0]
	permuted, err := CanonicalizePolicy(document)
	if err != nil {
		t.Fatalf("CanonicalizePolicy(permuted) error = %v", err)
	}
	if !bytes.Equal(canonical.CanonicalJSON, permuted.CanonicalJSON) || canonical.ContentDigest != permuted.ContentDigest {
		t.Fatal("canonical policy changed after input permutation")
	}
	document.Models.Allowlist[0].Provider = "mutated"
	if canonical.Document.Models.Allowlist[0].Provider == "mutated" {
		t.Fatal("canonical policy aliases caller model storage")
	}
}

func TestDecodePolicyDocumentRejectsAmbiguousOrUnknownJSON(t *testing.T) {
	valid := []byte(`{"schema_version":1,"models":{"allowlist":null},"tools":{"allowlist":null},"experience_candidates":{"mode":"manual_review"},"official_agents":{"installation":"allowed"}}`)
	if _, err := DecodePolicyDocument(valid); err != nil {
		t.Fatalf("DecodePolicyDocument(valid) error = %v", err)
	}
	for name, raw := range map[string][]byte{
		"unknown top-level key": bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"secret":"value"`), 1),
		"unknown nested key":    bytes.Replace(valid, []byte(`"models":{"allowlist":null}`), []byte(`"models":{"allowlist":null,"profile_path":"/private"}`), 1),
		"duplicate key":         bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"trailing JSON":         append(append([]byte(nil), valid...), []byte(` {}`)...),
		"invalid UTF-8":         append(append([]byte(nil), valid[:10]...), append([]byte{0xff}, valid[11:]...)...),
		"oversized input":       bytes.Repeat([]byte(" "), MaxPolicyDocumentBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicyDocument(raw); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("DecodePolicyDocument(%s) error = %v", name, err)
			}
		})
	}
}

func TestCanonicalizePolicyRejectsInvalidIdentifiersDuplicatesAndModes(t *testing.T) {
	valid := DefaultPolicyDocument()
	tests := []struct {
		name   string
		mutate func(*PolicyDocument)
	}{
		{name: "wrong schema", mutate: func(document *PolicyDocument) { document.SchemaVersion = 2 }},
		{name: "duplicate model", mutate: func(document *PolicyDocument) {
			document.Models.Allowlist = []ModelIdentifier{{Provider: "openai", Model: "gpt-5.6"}, {Provider: "openai", Model: "gpt-5.6"}}
		}},
		{name: "invalid provider", mutate: func(document *PolicyDocument) {
			document.Models.Allowlist = []ModelIdentifier{{Provider: "open ai", Model: "gpt-5.6"}}
		}},
		{name: "invalid model", mutate: func(document *PolicyDocument) {
			document.Models.Allowlist = []ModelIdentifier{{Provider: "openai", Model: strings.Repeat("m", 129)}}
		}},
		{name: "too many models", mutate: func(document *PolicyDocument) {
			document.Models.Allowlist = make([]ModelIdentifier, MaxPolicyAllowlistEntries+1)
			for index := range document.Models.Allowlist {
				document.Models.Allowlist[index] = ModelIdentifier{Provider: "openai", Model: fmt.Sprintf("model-%03d", index)}
			}
		}},
		{name: "duplicate tool", mutate: func(document *PolicyDocument) { document.Tools.Allowlist = []string{"files.read", "files.read"} }},
		{name: "invalid tool", mutate: func(document *PolicyDocument) { document.Tools.Allowlist = []string{"shell exec"} }},
		{name: "automatic experience", mutate: func(document *PolicyDocument) { document.ExperienceCandidates.Mode = "automatic" }},
		{name: "invalid official installation", mutate: func(document *PolicyDocument) { document.OfficialAgents.Installation = "inherit" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := clonePolicyForTest(t, valid)
			test.mutate(&document)
			if _, err := CanonicalizePolicy(document); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("CanonicalizePolicy() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestPolicyAllowlistIntersectionCanOnlyNarrow(t *testing.T) {
	platform := []string{"files.read", "web.search", "calendar.read"}
	organization := []string{"web.search", "files.read", "shell.exec"}
	local := []string{"files.read", "calendar.read"}
	if got := IntersectStringAllowlists(platform, organization, local); !equalStrings(got, []string{"files.read"}) {
		t.Fatalf("intersection = %v", got)
	}
	if got := IntersectStringAllowlists(platform, nil, local); !equalStrings(got, []string{"calendar.read", "files.read"}) {
		t.Fatalf("nil inheritance intersection = %v", got)
	}
	if got := IntersectStringAllowlists(platform, []string{}, local); len(got) != 0 || got == nil {
		t.Fatalf("empty deny-all intersection = %#v", got)
	}
}

func clonePolicyForTest(t *testing.T, document PolicyDocument) PolicyDocument {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal policy fixture: %v", err)
	}
	decoded, err := DecodePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("decode policy fixture: %v", err)
	}
	return decoded
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
