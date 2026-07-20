package organization

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"unicode/utf8"
)

const (
	MaxPolicyDocumentBytes    = 64 * 1024
	MaxPolicyAllowlistEntries = 128
)

var policyIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

type ModelIdentifier struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type ModelPolicy struct {
	Allowlist []ModelIdentifier `json:"allowlist"`
}

type ToolPolicy struct {
	Allowlist []string `json:"allowlist"`
}

type ExperienceCandidateMode string

const (
	ExperienceCandidateDisabled     ExperienceCandidateMode = "disabled"
	ExperienceCandidateManualReview ExperienceCandidateMode = "manual_review"
)

type ExperienceCandidatePolicy struct {
	Mode ExperienceCandidateMode `json:"mode"`
}

type OfficialAgentInstallation string

const (
	OfficialAgentInstallationAllowed OfficialAgentInstallation = "allowed"
	OfficialAgentInstallationBlocked OfficialAgentInstallation = "blocked"
)

type OfficialAgentPolicy struct {
	Installation OfficialAgentInstallation `json:"installation"`
}

type PolicyDocument struct {
	SchemaVersion        int                       `json:"schema_version"`
	Models               ModelPolicy               `json:"models"`
	Tools                ToolPolicy                `json:"tools"`
	ExperienceCandidates ExperienceCandidatePolicy `json:"experience_candidates"`
	OfficialAgents       OfficialAgentPolicy       `json:"official_agents"`
}

type CanonicalPolicy struct {
	Document      PolicyDocument
	CanonicalJSON []byte
	ContentDigest [sha256.Size]byte
}

func DefaultPolicyDocument() PolicyDocument {
	return PolicyDocument{
		SchemaVersion:        1,
		Models:               ModelPolicy{Allowlist: nil},
		Tools:                ToolPolicy{Allowlist: nil},
		ExperienceCandidates: ExperienceCandidatePolicy{Mode: ExperienceCandidateManualReview},
		OfficialAgents:       OfficialAgentPolicy{Installation: OfficialAgentInstallationAllowed},
	}
}

func DecodePolicyDocument(raw []byte) (PolicyDocument, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyDocumentBytes || !utf8.Valid(raw) || rejectPolicyDuplicateJSONKeys(raw) != nil {
		return PolicyDocument{}, ErrInvalidRequest
	}
	var document PolicyDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return PolicyDocument{}, ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PolicyDocument{}, ErrInvalidRequest
	}
	canonical, err := CanonicalizePolicy(document)
	if err != nil {
		return PolicyDocument{}, err
	}
	return canonical.Document, nil
}

func CanonicalizePolicy(document PolicyDocument) (CanonicalPolicy, error) {
	if document.SchemaVersion != 1 {
		return CanonicalPolicy{}, ErrInvalidRequest
	}
	models, err := canonicalModelAllowlist(document.Models.Allowlist)
	if err != nil {
		return CanonicalPolicy{}, err
	}
	tools, err := canonicalStringAllowlist(document.Tools.Allowlist)
	if err != nil {
		return CanonicalPolicy{}, err
	}
	if document.ExperienceCandidates.Mode != ExperienceCandidateDisabled &&
		document.ExperienceCandidates.Mode != ExperienceCandidateManualReview {
		return CanonicalPolicy{}, ErrInvalidRequest
	}
	if document.OfficialAgents.Installation != OfficialAgentInstallationAllowed &&
		document.OfficialAgents.Installation != OfficialAgentInstallationBlocked {
		return CanonicalPolicy{}, ErrInvalidRequest
	}
	canonicalDocument := PolicyDocument{
		SchemaVersion:        1,
		Models:               ModelPolicy{Allowlist: models},
		Tools:                ToolPolicy{Allowlist: tools},
		ExperienceCandidates: document.ExperienceCandidates,
		OfficialAgents:       document.OfficialAgents,
	}
	encoded, err := json.Marshal(canonicalDocument)
	if err != nil || len(encoded) > MaxPolicyDocumentBytes {
		return CanonicalPolicy{}, ErrInvalidRequest
	}
	return CanonicalPolicy{
		Document: canonicalDocument, CanonicalJSON: encoded, ContentDigest: sha256.Sum256(encoded),
	}, nil
}

func canonicalModelAllowlist(input []ModelIdentifier) ([]ModelIdentifier, error) {
	if input == nil {
		return nil, nil
	}
	if len(input) > MaxPolicyAllowlistEntries {
		return nil, ErrInvalidRequest
	}
	output := make([]ModelIdentifier, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, identifier := range input {
		if !policyIdentifierPattern.MatchString(identifier.Provider) || !policyIdentifierPattern.MatchString(identifier.Model) {
			return nil, ErrInvalidRequest
		}
		key := identifier.Provider + "\x00" + identifier.Model
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrInvalidRequest
		}
		seen[key] = struct{}{}
		output = append(output, identifier)
	}
	sort.Slice(output, func(left, right int) bool {
		if output[left].Provider == output[right].Provider {
			return output[left].Model < output[right].Model
		}
		return output[left].Provider < output[right].Provider
	})
	return output, nil
}

func canonicalStringAllowlist(input []string) ([]string, error) {
	if input == nil {
		return nil, nil
	}
	if len(input) > MaxPolicyAllowlistEntries {
		return nil, ErrInvalidRequest
	}
	output := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, identifier := range input {
		if !policyIdentifierPattern.MatchString(identifier) {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, ErrInvalidRequest
		}
		seen[identifier] = struct{}{}
		output = append(output, identifier)
	}
	sort.Strings(output)
	return output, nil
}

func IntersectStringAllowlists(inputs ...[]string) []string {
	var result map[string]struct{}
	constrained := false
	for _, input := range inputs {
		if input == nil {
			continue
		}
		current := make(map[string]struct{}, len(input))
		for _, value := range input {
			current[value] = struct{}{}
		}
		if !constrained {
			result = current
			constrained = true
			continue
		}
		for value := range result {
			if _, allowed := current[value]; !allowed {
				delete(result, value)
			}
		}
	}
	if !constrained {
		return nil
	}
	output := make([]string, 0, len(result))
	for value := range result {
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}

func rejectPolicyDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanPolicyJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func scanPolicyJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := scanPolicyJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanPolicyJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil || closing != matchingPolicyDelimiter(delimiter) {
		return errors.New("JSON container is not closed")
	}
	return nil
}

func matchingPolicyDelimiter(open json.Delim) json.Delim {
	if open == '{' {
		return '}'
	}
	return ']'
}
