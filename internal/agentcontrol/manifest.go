package agentcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var semanticVersionPattern = regexp.MustCompile(
	`^(?:v)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`,
)

func DecodeManifest(raw []byte) (AgentManifestV1, error) {
	var manifest AgentManifestV1
	if !utf8.Valid(raw) || len(raw) == 0 || len(raw) > MaxManifestBytes || rejectDuplicateJSONKeys(raw) != nil {
		return AgentManifestV1{}, ErrInvalidAgentContent
	}
	if err := decodeStrictJSON(raw, &manifest); err != nil {
		return AgentManifestV1{}, ErrInvalidAgentContent
	}
	return manifest, nil
}

func DecodeBundle(raw []byte) (VersionBundleV1, error) {
	var bundle VersionBundleV1
	if !utf8.Valid(raw) || len(raw) == 0 || rejectDuplicateJSONKeys(raw) != nil {
		return VersionBundleV1{}, ErrInvalidAgentContent
	}
	if err := decodeStrictJSON(raw, &bundle); err != nil {
		return VersionBundleV1{}, ErrInvalidAgentContent
	}
	return bundle, nil
}

func CanonicalizeVersion(manifest AgentManifestV1, bundle VersionBundleV1) (CanonicalVersion, error) {
	if manifest.SchemaVersion != 1 || !validText(manifest.Identity.SystemPrompt, 1, MaxManifestBytes) ||
		len(manifest.Assets) > MaxAssetCount || len(bundle.Assets) > MaxAssetCount {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}

	canonicalBundleAssets := make([]canonicalBundleAsset, 0, len(bundle.Assets))
	bundleByPath := make(map[string]string, len(bundle.Assets))
	totalAssetBytes := 0
	for _, asset := range bundle.Assets {
		normalizedPath, err := normalizeAssetPath(asset.Path)
		if err != nil || !utf8.ValidString(asset.Content) || len([]byte(asset.Content)) > MaxAssetBytes {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		if _, duplicate := bundleByPath[normalizedPath]; duplicate {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		totalAssetBytes += len([]byte(asset.Content))
		if totalAssetBytes > MaxBundleBytes {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		bundleByPath[normalizedPath] = asset.Content
		canonicalBundleAssets = append(canonicalBundleAssets, canonicalBundleAsset{Content: asset.Content, Path: normalizedPath})
	}

	canonicalAssets := make([]canonicalManifestAsset, 0, len(manifest.Assets))
	seenManifestPaths := make(map[string]struct{}, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		normalizedPath, err := normalizeAssetPath(asset.Path)
		if err != nil || !validAssetKind(asset.Kind) || !validMediaType(asset.MediaType) {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		if _, duplicate := seenManifestPaths[normalizedPath]; duplicate {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		seenManifestPaths[normalizedPath] = struct{}{}
		content, ok := bundleByPath[normalizedPath]
		if !ok {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		digestBytes, err := hex.DecodeString(asset.SHA256)
		contentDigest := sha256.Sum256([]byte(content))
		if err != nil || len(digestBytes) != sha256.Size || !bytes.Equal(digestBytes, contentDigest[:]) || asset.SHA256 != strings.ToLower(asset.SHA256) {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		canonicalAssets = append(canonicalAssets, canonicalManifestAsset{
			Kind: asset.Kind, MediaType: asset.MediaType, Path: normalizedPath, SHA256: asset.SHA256,
		})
	}
	if len(seenManifestPaths) != len(bundleByPath) {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}

	providers, err := canonicalStringSet(manifest.ModelConstraints.AllowedProviders, true)
	if err != nil || len(providers) == 0 {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}
	models, err := canonicalStringSet(manifest.ModelConstraints.AllowedModels, true)
	if err != nil || len(models) == 0 {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}
	allowedTools, err := canonicalStringSet(manifest.Tools.Allowed, true)
	if err != nil {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}
	deniedTools, err := canonicalStringSet(manifest.Tools.Denied, true)
	if err != nil {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}
	allowedLookup := make(map[string]struct{}, len(allowedTools))
	for _, tool := range allowedTools {
		allowedLookup[tool] = struct{}{}
	}
	for _, tool := range deniedTools {
		if _, conflict := allowedLookup[tool]; conflict {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
	}

	dependencies := make([]canonicalDependency, 0, len(manifest.Dependencies))
	seenDependencies := make(map[string]struct{}, len(manifest.Dependencies))
	for _, dependency := range manifest.Dependencies {
		if dependency.AgentDefinitionID.String() == "00000000-0000-0000-0000-000000000000" ||
			dependency.AgentVersionID.String() == "00000000-0000-0000-0000-000000000000" {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		key := dependency.AgentDefinitionID.String() + "\x00" + dependency.AgentVersionID.String()
		if _, duplicate := seenDependencies[key]; duplicate {
			return CanonicalVersion{}, ErrInvalidAgentContent
		}
		seenDependencies[key] = struct{}{}
		dependencies = append(dependencies, canonicalDependency{
			AgentDefinitionID: dependency.AgentDefinitionID.String(), AgentVersionID: dependency.AgentVersionID.String(),
		})
	}

	minimum, minimumVersion, err := parseSemanticVersion(manifest.RuntimeCompatibility.MinimumVersion)
	if err != nil {
		return CanonicalVersion{}, ErrRuntimeIncompatible
	}
	var maximum *string
	if manifest.RuntimeCompatibility.MaximumVersionExclusive != "" {
		normalizedMaximum, maximumVersion, err := parseSemanticVersion(manifest.RuntimeCompatibility.MaximumVersionExclusive)
		if err != nil || compareSemanticVersion(maximumVersion, minimumVersion) <= 0 {
			return CanonicalVersion{}, ErrRuntimeIncompatible
		}
		maximum = &normalizedMaximum
	}

	sort.Slice(canonicalAssets, func(left, right int) bool { return canonicalAssets[left].Path < canonicalAssets[right].Path })
	sort.Slice(canonicalBundleAssets, func(left, right int) bool {
		return canonicalBundleAssets[left].Path < canonicalBundleAssets[right].Path
	})
	sort.Slice(dependencies, func(left, right int) bool {
		if dependencies[left].AgentDefinitionID == dependencies[right].AgentDefinitionID {
			return dependencies[left].AgentVersionID < dependencies[right].AgentVersionID
		}
		return dependencies[left].AgentDefinitionID < dependencies[right].AgentDefinitionID
	})

	canonicalManifestValue := canonicalManifest{
		Assets:       canonicalAssets,
		Dependencies: dependencies,
		Identity: canonicalIdentity{
			SystemPrompt: manifest.Identity.SystemPrompt,
		},
		ModelConstraints: canonicalModelConstraints{AllowedModels: models, AllowedProviders: providers},
		RuntimeCompatibility: canonicalRuntimeCompatibility{
			MaximumVersionExclusive: maximum, MinimumVersion: minimum,
		},
		SchemaVersion: manifest.SchemaVersion,
		Tools:         canonicalTools{Allowed: allowedTools, Denied: deniedTools},
	}
	manifestJSON, err := marshalCanonical(canonicalManifestValue)
	if err != nil || len(manifestJSON) > MaxManifestBytes {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}
	bundleJSON, err := marshalCanonical(canonicalBundle{Assets: canonicalBundleAssets})
	if err != nil {
		return CanonicalVersion{}, ErrInvalidAgentContent
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	bundleDigest := sha256.Sum256(bundleJSON)
	contentInput := make([]byte, 0, len(manifestJSON)+1+len(bundleJSON))
	contentInput = append(contentInput, manifestJSON...)
	contentInput = append(contentInput, 0)
	contentInput = append(contentInput, bundleJSON...)
	return CanonicalVersion{
		ManifestJSON: manifestJSON, BundleJSON: bundleJSON,
		ManifestDigest: manifestDigest, BundleDigest: bundleDigest, ContentDigest: sha256.Sum256(contentInput),
	}, nil
}

func ValidateIcon(mediaType string, data []byte) error {
	if len(data) == 0 || len(data) > MaxIconBytes {
		return ErrInvalidAgentContent
	}
	var width, height int
	var animated bool
	var err error
	switch mediaType {
	case "image/png":
		width, height, animated, err = inspectPNG(data)
	case "image/webp":
		width, height, animated, err = inspectWebP(data)
	default:
		return ErrInvalidAgentContent
	}
	if err != nil || animated || width <= 0 || height <= 0 || width > MaxIconDimension || height > MaxIconDimension {
		return ErrInvalidAgentContent
	}
	return nil
}

type canonicalManifest struct {
	Assets               []canonicalManifestAsset      `json:"assets"`
	Dependencies         []canonicalDependency         `json:"dependencies"`
	Identity             canonicalIdentity             `json:"identity"`
	ModelConstraints     canonicalModelConstraints     `json:"model_constraints"`
	RuntimeCompatibility canonicalRuntimeCompatibility `json:"runtime_compatibility"`
	SchemaVersion        int                           `json:"schema_version"`
	Tools                canonicalTools                `json:"tools"`
}

type canonicalManifestAsset struct {
	Kind      AssetKind `json:"kind"`
	MediaType MediaType `json:"media_type"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
}

type canonicalDependency struct {
	AgentDefinitionID string `json:"agent_definition_id"`
	AgentVersionID    string `json:"agent_version_id"`
}

type canonicalIdentity struct {
	SystemPrompt string `json:"system_prompt"`
}

type canonicalModelConstraints struct {
	AllowedModels    []string `json:"allowed_models"`
	AllowedProviders []string `json:"allowed_providers"`
}

type canonicalRuntimeCompatibility struct {
	MaximumVersionExclusive *string `json:"maximum_version_exclusive"`
	MinimumVersion          string  `json:"minimum_version"`
}

type canonicalTools struct {
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

type canonicalBundle struct {
	Assets []canonicalBundleAsset `json:"assets"`
}

type canonicalBundleAsset struct {
	Content string `json:"content"`
	Path    string `json:"path"`
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
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
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil || closing != matchingDelimiter(delimiter) {
		return errors.New("JSON container is not closed")
	}
	return nil
}

func matchingDelimiter(open json.Delim) json.Delim {
	if open == '{' {
		return '}'
	}
	return ']'
}

func normalizeAssetPath(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || !utf8.ValidString(raw) || strings.ContainsRune(raw, '\x00') ||
		strings.Contains(raw, `\`) || strings.Contains(raw, "://") || strings.HasPrefix(raw, "/") ||
		(len(raw) >= 2 && raw[1] == ':') {
		return "", ErrInvalidAgentContent
	}
	normalized := norm.NFC.String(raw)
	if cleaned := path.Clean(normalized); cleaned != normalized || cleaned == "." || strings.HasPrefix(cleaned, "../") {
		return "", ErrInvalidAgentContent
	}
	for _, segment := range strings.Split(strings.ToLower(normalized), "/") {
		switch segment {
		case ".env", "auth.json", "memory.md", "user.md", "credentials", "sessions", "curator", "archives":
			return "", ErrInvalidAgentContent
		}
	}
	return normalized, nil
}

func canonicalStringSet(values []string, forbidRemote bool) ([]string, error) {
	result := append([]string(nil), values...)
	if result == nil {
		result = []string{}
	}
	seen := make(map[string]struct{}, len(result))
	for _, value := range result {
		if !validText(value, 1, 128) || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") ||
			(forbidRemote && strings.Contains(value, "://")) {
			return nil, ErrInvalidAgentContent
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrInvalidAgentContent
		}
		seen[value] = struct{}{}
	}
	sort.Strings(result)
	return result, nil
}

func validText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len([]byte(value)) >= minimum && len([]byte(value)) <= maximum && !strings.ContainsRune(value, '\x00')
}

func validAssetKind(kind AssetKind) bool {
	return kind == AssetKindSkill || kind == AssetKindSOP || kind == AssetKindKnowledge
}

func validMediaType(mediaType MediaType) bool {
	return mediaType == MediaTypeTextMarkdown || mediaType == MediaTypeTextPlain
}

func marshalCanonical(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

type semanticVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease []string
}

func parseSemanticVersion(raw string) (string, semanticVersion, error) {
	matches := semanticVersionPattern.FindStringSubmatch(raw)
	if matches == nil {
		return "", semanticVersion{}, ErrRuntimeIncompatible
	}
	major, errMajor := strconv.ParseUint(matches[1], 10, 64)
	minor, errMinor := strconv.ParseUint(matches[2], 10, 64)
	patchVersion, errPatch := strconv.ParseUint(matches[3], 10, 64)
	if errMajor != nil || errMinor != nil || errPatch != nil || !validSemverIdentifiers(matches[4], true) || !validSemverIdentifiers(matches[5], false) {
		return "", semanticVersion{}, ErrRuntimeIncompatible
	}
	normalized := raw
	if !strings.HasPrefix(normalized, "v") {
		normalized = "v" + normalized
	}
	prerelease := []string{}
	if matches[4] != "" {
		prerelease = strings.Split(matches[4], ".")
	}
	return normalized, semanticVersion{major: major, minor: minor, patch: patchVersion, prerelease: prerelease}, nil
}

func validSemverIdentifiers(raw string, rejectNumericLeadingZero bool) bool {
	if raw == "" {
		return true
	}
	for _, identifier := range strings.Split(raw, ".") {
		if identifier == "" {
			return false
		}
		for _, character := range identifier {
			if !(character == '-' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
				return false
			}
		}
		if rejectNumericLeadingZero && len(identifier) > 1 && identifier[0] == '0' && allDigits(identifier) {
			return false
		}
	}
	return true
}

func allDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func compareSemanticVersion(left, right semanticVersion) int {
	for _, pair := range [][2]uint64{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if len(left.prerelease) == 0 && len(right.prerelease) == 0 {
		return 0
	}
	if len(left.prerelease) == 0 {
		return 1
	}
	if len(right.prerelease) == 0 {
		return -1
	}
	for index := 0; index < len(left.prerelease) && index < len(right.prerelease); index++ {
		leftIdentifier, rightIdentifier := left.prerelease[index], right.prerelease[index]
		leftNumeric, rightNumeric := allDigits(leftIdentifier), allDigits(rightIdentifier)
		switch {
		case leftNumeric && rightNumeric:
			leftValue, _ := strconv.ParseUint(leftIdentifier, 10, 64)
			rightValue, _ := strconv.ParseUint(rightIdentifier, 10, 64)
			if leftValue < rightValue {
				return -1
			}
			if leftValue > rightValue {
				return 1
			}
		case leftNumeric:
			return -1
		case rightNumeric:
			return 1
		case leftIdentifier < rightIdentifier:
			return -1
		case leftIdentifier > rightIdentifier:
			return 1
		}
	}
	if len(left.prerelease) < len(right.prerelease) {
		return -1
	}
	if len(left.prerelease) > len(right.prerelease) {
		return 1
	}
	return 0
}

func inspectPNG(data []byte) (int, int, bool, error) {
	if len(data) < 33 || !bytes.Equal(data[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		return 0, 0, false, ErrInvalidAgentContent
	}
	animated := false
	for offset := 8; offset+12 <= len(data); {
		length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		if length < 0 || offset+12+length > len(data) {
			return 0, 0, false, ErrInvalidAgentContent
		}
		chunkType := string(data[offset+4 : offset+8])
		if chunkType == "acTL" || chunkType == "fcTL" || chunkType == "fdAT" {
			animated = true
		}
		offset += 12 + length
	}
	configuration, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, false, err
	}
	return configuration.Width, configuration.Height, animated, nil
}

func inspectWebP(data []byte) (int, int, bool, error) {
	if len(data) < 30 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" ||
		int(binary.LittleEndian.Uint32(data[4:8]))+8 != len(data) {
		return 0, 0, false, ErrInvalidAgentContent
	}
	for offset := 12; offset+8 <= len(data); {
		chunkType := string(data[offset : offset+4])
		length := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		contentStart := offset + 8
		contentEnd := contentStart + length
		if length < 0 || contentEnd > len(data) {
			return 0, 0, false, ErrInvalidAgentContent
		}
		content := data[contentStart:contentEnd]
		switch chunkType {
		case "VP8X":
			if len(content) != 10 {
				return 0, 0, false, ErrInvalidAgentContent
			}
			width := readUint24LE(content[4:7]) + 1
			height := readUint24LE(content[7:10]) + 1
			return width, height, content[0]&0x02 != 0, nil
		case "ANIM", "ANMF":
			return 1, 1, true, nil
		}
		offset = contentEnd
		if length%2 == 1 {
			offset++
		}
	}
	return 0, 0, false, fmt.Errorf("%w: WebP has no supported image chunk", ErrInvalidAgentContent)
}

func readUint24LE(value []byte) int {
	return int(value[0]) | int(value[1])<<8 | int(value[2])<<16
}
