package agentcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"image"
	"image/png"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCanonicalizeVersionSortsEverySetAndProducesStableDigests(t *testing.T) {
	manifest, bundle := validManifestFixture()
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion() error = %v", err)
	}

	manifest.Assets[0], manifest.Assets[1] = manifest.Assets[1], manifest.Assets[0]
	manifest.ModelConstraints.AllowedProviders[0], manifest.ModelConstraints.AllowedProviders[1] =
		manifest.ModelConstraints.AllowedProviders[1], manifest.ModelConstraints.AllowedProviders[0]
	manifest.ModelConstraints.AllowedModels[0], manifest.ModelConstraints.AllowedModels[1] =
		manifest.ModelConstraints.AllowedModels[1], manifest.ModelConstraints.AllowedModels[0]
	manifest.Tools.Allowed[0], manifest.Tools.Allowed[1] = manifest.Tools.Allowed[1], manifest.Tools.Allowed[0]
	manifest.Dependencies[0], manifest.Dependencies[1] = manifest.Dependencies[1], manifest.Dependencies[0]
	bundle.Assets[0], bundle.Assets[1] = bundle.Assets[1], bundle.Assets[0]
	permuted, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion(permuted) error = %v", err)
	}

	if !bytes.Equal(canonical.ManifestJSON, permuted.ManifestJSON) || !bytes.Equal(canonical.BundleJSON, permuted.BundleJSON) {
		t.Fatalf("canonical output changed after input permutation:\n%s\n%s", canonical.ManifestJSON, permuted.ManifestJSON)
	}
	if canonical.ManifestDigest != permuted.ManifestDigest || canonical.BundleDigest != permuted.BundleDigest ||
		canonical.ContentDigest != permuted.ContentDigest {
		t.Fatal("canonical digests changed after input permutation")
	}
	if !strings.HasPrefix(string(canonical.ManifestJSON), `{"assets":[`) ||
		!strings.Contains(string(canonical.ManifestJSON), `"path":"knowledge/alpha.md"`) {
		t.Fatalf("manifest is not sorted canonical JSON: %s", canonical.ManifestJSON)
	}
	if canonical.ManifestDigest != sha256.Sum256(canonical.ManifestJSON) || canonical.BundleDigest != sha256.Sum256(canonical.BundleJSON) {
		t.Fatal("canonical digests do not match exact canonical bytes")
	}
}

func TestCanonicalizeVersionV2SupportsRuntimeModelSelection(t *testing.T) {
	manifest, bundle := emptyManifestV2Fixture(ModelSelectionUserSelect, nil, nil)
	canonical, err := CanonicalizeVersion(manifest, bundle)
	if err != nil {
		t.Fatalf("CanonicalizeVersion(V2 user_select) error = %v", err)
	}

	want := `{"assets":[],"dependencies":[],"identity":{"system_prompt":"Agent identity"},"model_policy":{"allowed_models":[],"allowed_providers":[],"mode":"user_select"},"runtime_compatibility":{"maximum_version_exclusive":null,"minimum_version":"v0.18.2-agentera.1"},"schema_version":2,"tools":{"allowed":["files.read"],"denied":["shell.exec"]}}`
	if string(canonical.ManifestJSON) != want {
		t.Fatalf("canonical V2 manifest = %s, want %s", canonical.ManifestJSON, want)
	}
	decoded, err := DecodeManifest(canonical.ManifestJSON)
	if err != nil {
		t.Fatalf("DecodeManifest(canonical V2) error = %v", err)
	}
	if decoded.SchemaVersion != 2 || decoded.ModelPolicy.Mode != ModelSelectionUserSelect {
		t.Fatalf("decoded V2 policy = %+v", decoded.ModelPolicy)
	}
}

func TestCanonicalizeVersionV2EnforcesModelPolicyModes(t *testing.T) {
	tests := []struct {
		name      string
		mode      ModelSelectionMode
		providers []string
		models    []string
		valid     bool
	}{
		{name: "user selected", mode: ModelSelectionUserSelect, valid: true},
		{name: "user selected rejects allowlist", mode: ModelSelectionUserSelect, providers: []string{"openai"}, models: []string{"gpt-5.6"}},
		{name: "allowlist", mode: ModelSelectionAllowlist, providers: []string{"openai"}, models: []string{"gpt-5.6"}, valid: true},
		{name: "allowlist requires providers", mode: ModelSelectionAllowlist, models: []string{"gpt-5.6"}},
		{name: "allowlist requires models", mode: ModelSelectionAllowlist, providers: []string{"openai"}},
		{name: "fixed", mode: ModelSelectionFixed, providers: []string{"openai"}, models: []string{"gpt-5.6"}, valid: true},
		{name: "fixed rejects multiple providers", mode: ModelSelectionFixed, providers: []string{"openai", "anthropic"}, models: []string{"gpt-5.6"}},
		{name: "fixed rejects multiple models", mode: ModelSelectionFixed, providers: []string{"openai"}, models: []string{"gpt-5.6", "gpt-5.5"}},
		{name: "unknown mode", mode: ModelSelectionMode("automatic")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, bundle := emptyManifestV2Fixture(tt.mode, tt.providers, tt.models)
			_, err := CanonicalizeVersion(manifest, bundle)
			if tt.valid && err != nil {
				t.Fatalf("CanonicalizeVersion() error = %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("CanonicalizeVersion() accepted an invalid V2 model policy")
			}
		})
	}
}

func TestManifestDecoderKeepsV1AndV2FieldsDisjoint(t *testing.T) {
	v1WithPolicy := bytes.Replace(strictManifestJSON(), []byte(`"model_constraints":{"allowed_providers":["openai"],"allowed_models":["gpt-5.6"]}`), []byte(`"model_constraints":{"allowed_providers":["openai"],"allowed_models":["gpt-5.6"]},"model_policy":{"mode":"user_select","allowed_providers":[],"allowed_models":[]}`), 1)
	if _, err := DecodeManifest(v1WithPolicy); err == nil {
		t.Fatal("DecodeManifest() accepted a V2 policy in a V1 manifest")
	}

	v2WithConstraints := []byte(`{"schema_version":2,"identity":{"system_prompt":"Agent identity"},"assets":[],"model_policy":{"mode":"user_select","allowed_providers":[],"allowed_models":[]},"model_constraints":{"allowed_providers":["openai"],"allowed_models":["gpt-5.6"]},"tools":{"allowed":[],"denied":[]},"dependencies":[],"runtime_compatibility":{"minimum_version":"0.18.2-agentera.1","maximum_version_exclusive":null}}`)
	if _, err := DecodeManifest(v2WithConstraints); err == nil {
		t.Fatal("DecodeManifest() accepted V1 constraints in a V2 manifest")
	}
}

func TestCanonicalizeVersionRejectsUnsafePathsAndDuplicateNormalizedPaths(t *testing.T) {
	for _, unsafePath := range []string{
		"../escape.md",
		"/absolute.md",
		"C:/windows.md",
		`skills\windows.md`,
		"skills/../escape.md",
		"./skills/dot.md",
		"https://example.com/remote.md",
		"skills/nul\x00.md",
		"MEMORY.md",
		"USER.md",
		".env",
	} {
		t.Run(strconv.Quote(unsafePath), func(t *testing.T) {
			manifest, bundle := singleAssetFixture(unsafePath, []byte("content"))
			if _, err := CanonicalizeVersion(manifest, bundle); err == nil {
				t.Fatalf("CanonicalizeVersion() accepted unsafe path %q", unsafePath)
			}
		})
	}

	manifest, bundle := validManifestFixture()
	manifest.Assets[0].Path = "knowledge/e\u0301.md"
	manifest.Assets[1].Path = "knowledge/é.md"
	bundle.Assets[0].Path = manifest.Assets[0].Path
	bundle.Assets[1].Path = manifest.Assets[1].Path
	if _, err := CanonicalizeVersion(manifest, bundle); err == nil {
		t.Fatal("CanonicalizeVersion() accepted Unicode-normalized duplicate paths")
	}
}

func TestStrictManifestAndBundleDecodersRejectAmbiguousOrExecutableInput(t *testing.T) {
	valid := strictManifestJSON()
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "unknown field", raw: bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unexpected":true`), 1)},
		{name: "duplicate key", raw: bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)},
		{name: "remote URL metadata", raw: bytes.Replace(valid, []byte(`"sha256":"`), []byte(`"url":"https://example.com/a","sha256":"`), 1)},
		{name: "executable dependency", raw: bytes.Replace(valid, []byte(`"agent_version_id":"`), []byte(`"command":"sh","agent_version_id":"`), 1)},
		{name: "invalid UTF-8", raw: append(append([]byte(nil), valid[:bytes.Index(valid, []byte("Agent identity"))]...), append([]byte{0xff}, valid[bytes.Index(valid, []byte("Agent identity"))+1:]...)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeManifest(tt.raw); err == nil {
				t.Fatalf("DecodeManifest() accepted %s", tt.name)
			}
		})
	}

	for name, raw := range map[string][]byte{
		"unknown bundle field": []byte(`{"assets":[],"unexpected":true}`),
		"symlink metadata":     []byte(`{"assets":[{"content":"x","path":"skill.md","symlink_target":"target"}]}`),
		"duplicate bundle key": []byte(`{"assets":[],"assets":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBundle(raw); err == nil {
				t.Fatalf("DecodeBundle() accepted %s", name)
			}
		})
	}
}

func TestCanonicalizeVersionEnforcesManifestAndAssetLimits(t *testing.T) {
	t.Run("asset count", func(t *testing.T) {
		manifest, bundle := emptyManifestFixture()
		for index := range MaxAssetCount + 1 {
			content := []byte("x")
			path := "knowledge/" + strconv.Itoa(index) + ".md"
			manifest.Assets = append(manifest.Assets, manifestAsset(path, AssetKindKnowledge, content))
			bundle.Assets = append(bundle.Assets, BundleAssetV1{Path: path, Content: string(content)})
		}
		if _, err := CanonicalizeVersion(manifest, bundle); err == nil {
			t.Fatal("CanonicalizeVersion() accepted 129 assets")
		}
	})

	t.Run("single asset bytes", func(t *testing.T) {
		content := bytes.Repeat([]byte("a"), MaxAssetBytes+1)
		manifest, bundle := singleAssetFixture("knowledge/large.md", content)
		if _, err := CanonicalizeVersion(manifest, bundle); err == nil {
			t.Fatal("CanonicalizeVersion() accepted an oversized asset")
		}
	})

	t.Run("total asset bytes", func(t *testing.T) {
		manifest, bundle := emptyManifestFixture()
		for index := range 9 {
			content := bytes.Repeat([]byte{byte('a' + index)}, MaxAssetBytes)
			path := "knowledge/part-" + strconv.Itoa(index) + ".md"
			manifest.Assets = append(manifest.Assets, manifestAsset(path, AssetKindKnowledge, content))
			bundle.Assets = append(bundle.Assets, BundleAssetV1{Path: path, Content: string(content)})
		}
		if _, err := CanonicalizeVersion(manifest, bundle); err == nil {
			t.Fatal("CanonicalizeVersion() accepted a bundle over 2 MiB")
		}
	})

	t.Run("canonical manifest bytes", func(t *testing.T) {
		manifest, bundle := emptyManifestFixture()
		manifest.Identity.SystemPrompt = strings.Repeat("a", MaxManifestBytes+1)
		if _, err := CanonicalizeVersion(manifest, bundle); err == nil {
			t.Fatal("CanonicalizeVersion() accepted a manifest over 256 KiB")
		}
	})
}

func TestCanonicalizeVersionValidatesRuntimeCompatibilityRanges(t *testing.T) {
	for _, compatibility := range []RuntimeCompatibilityV1{
		{},
		{MinimumVersion: "not-semver"},
		{MinimumVersion: "0.18.2-agentera.1", MaximumVersionExclusive: "0.18.2-agentera.1"},
		{MinimumVersion: "v0.19.0", MaximumVersionExclusive: "v0.18.9"},
	} {
		manifest, bundle := validManifestFixture()
		manifest.RuntimeCompatibility = compatibility
		if _, err := CanonicalizeVersion(manifest, bundle); err == nil {
			t.Fatalf("CanonicalizeVersion() accepted compatibility %+v", compatibility)
		}
	}

	manifest, bundle := validManifestFixture()
	manifest.RuntimeCompatibility = RuntimeCompatibilityV1{
		MinimumVersion: "0.18.2-agentera.1", MaximumVersionExclusive: "v0.19.0",
	}
	if _, err := CanonicalizeVersion(manifest, bundle); err != nil {
		t.Fatalf("CanonicalizeVersion(valid range) error = %v", err)
	}
}

func TestValidateIconRejectsOversizeDimensionsAnimationAndTypeMismatch(t *testing.T) {
	validPNG := encodedPNG(t, 1, 1)
	if err := ValidateIcon("image/png", validPNG); err != nil {
		t.Fatalf("ValidateIcon(valid PNG) error = %v", err)
	}
	if err := ValidateIcon("image/webp", webPVP8X(1, 1, false)); err != nil {
		t.Fatalf("ValidateIcon(valid WebP) error = %v", err)
	}

	for name, tt := range map[string]struct {
		mediaType string
		data      []byte
	}{
		"oversized bytes":        {mediaType: "image/png", data: bytes.Repeat([]byte("x"), MaxIconBytes+1)},
		"oversized PNG":          {mediaType: "image/png", data: encodedPNG(t, MaxIconDimension+1, 1)},
		"animated PNG":           {mediaType: "image/png", data: insertPNGChunk(t, validPNG, "acTL", []byte{0, 0, 0, 1, 0, 0, 0, 0})},
		"oversized WebP":         {mediaType: "image/webp", data: webPVP8X(MaxIconDimension+1, 1, false)},
		"animated WebP":          {mediaType: "image/webp", data: webPVP8X(1, 1, true)},
		"media type mismatch":    {mediaType: "image/webp", data: validPNG},
		"unsupported media type": {mediaType: "image/svg+xml", data: []byte(`<svg/>`)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateIcon(tt.mediaType, tt.data); err == nil {
				t.Fatalf("ValidateIcon() accepted %s", name)
			}
		})
	}
}

func validManifestFixture() (AgentManifestV1, VersionBundleV1) {
	alpha := []byte("# Alpha\n")
	beta := []byte("# Beta\n")
	manifest, bundle := emptyManifestFixture()
	manifest.Assets = []ManifestAssetV1{
		manifestAsset("skills/beta/SKILL.md", AssetKindSkill, beta),
		manifestAsset("knowledge/alpha.md", AssetKindKnowledge, alpha),
	}
	bundle.Assets = []BundleAssetV1{
		{Path: "skills/beta/SKILL.md", Content: string(beta)},
		{Path: "knowledge/alpha.md", Content: string(alpha)},
	}
	manifest.ModelConstraints = ModelConstraintsV1{
		AllowedProviders: []string{"openai", "anthropic"},
		AllowedModels:    []string{"gpt-5.6", "claude-opus-5"},
	}
	manifest.Tools = ToolPolicyV1{Allowed: []string{"web.search", "files.read"}, Denied: []string{"shell.exec"}}
	manifest.Dependencies = []AgentDependencyV1{
		{AgentDefinitionID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), AgentVersionID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")},
		{AgentDefinitionID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), AgentVersionID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")},
	}
	return manifest, bundle
}

func emptyManifestFixture() (AgentManifestV1, VersionBundleV1) {
	return AgentManifestV1{
		SchemaVersion: 1,
		Identity:      AgentIdentityV1{SystemPrompt: "Agent identity"},
		ModelConstraints: ModelConstraintsV1{
			AllowedProviders: []string{"openai"}, AllowedModels: []string{"gpt-5.6"},
		},
		Tools:                ToolPolicyV1{Allowed: []string{"files.read"}, Denied: []string{"shell.exec"}},
		RuntimeCompatibility: RuntimeCompatibilityV1{MinimumVersion: "0.18.2-agentera.1"},
	}, VersionBundleV1{Assets: []BundleAssetV1{}}
}

func emptyManifestV2Fixture(
	mode ModelSelectionMode,
	providers []string,
	models []string,
) (AgentManifest, VersionBundleV1) {
	return AgentManifest{
		SchemaVersion: 2,
		Identity:      AgentIdentityV1{SystemPrompt: "Agent identity"},
		ModelPolicy: ModelPolicyV2{
			Mode: mode, AllowedProviders: providers, AllowedModels: models,
		},
		Tools:                ToolPolicyV1{Allowed: []string{"files.read"}, Denied: []string{"shell.exec"}},
		RuntimeCompatibility: RuntimeCompatibilityV1{MinimumVersion: "0.18.2-agentera.1"},
	}, VersionBundleV1{Assets: []BundleAssetV1{}}
}

func singleAssetFixture(path string, content []byte) (AgentManifestV1, VersionBundleV1) {
	manifest, bundle := emptyManifestFixture()
	manifest.Assets = []ManifestAssetV1{manifestAsset(path, AssetKindKnowledge, content)}
	bundle.Assets = []BundleAssetV1{{Path: path, Content: string(content)}}
	return manifest, bundle
}

func manifestAsset(path string, kind AssetKind, content []byte) ManifestAssetV1 {
	digest := sha256.Sum256(content)
	return ManifestAssetV1{
		Path: path, Kind: kind, MediaType: MediaTypeTextMarkdown, SHA256: hex.EncodeToString(digest[:]),
	}
}

func strictManifestJSON() []byte {
	definitionID := "11111111-1111-4111-8111-111111111111"
	versionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	digest := strings.Repeat("0", 64)
	return []byte(`{"schema_version":1,"identity":{"system_prompt":"Agent identity"},"assets":[{"path":"knowledge/a.md","kind":"knowledge","media_type":"text/markdown","sha256":"` + digest + `"}],"model_constraints":{"allowed_providers":["openai"],"allowed_models":["gpt-5.6"]},"tools":{"allowed":["files.read"],"denied":[]},"dependencies":[{"agent_definition_id":"` + definitionID + `","agent_version_id":"` + versionID + `"}],"runtime_compatibility":{"minimum_version":"0.18.2-agentera.1","maximum_version_exclusive":null}}`)
}

func encodedPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := png.Encode(&output, image.NewRGBA(image.Rect(0, 0, width, height))); err != nil {
		t.Fatalf("png.Encode() error = %v", err)
	}
	return output.Bytes()
}

func insertPNGChunk(t *testing.T, input []byte, chunkType string, data []byte) []byte {
	t.Helper()
	if len(input) < 33 || len(chunkType) != 4 {
		t.Fatal("invalid PNG fixture")
	}
	chunk := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(chunk[:4], uint32(len(data)))
	copy(chunk[4:8], chunkType)
	copy(chunk[8:8+len(data)], data)
	binary.BigEndian.PutUint32(chunk[8+len(data):], crc32.ChecksumIEEE(chunk[4:8+len(data)]))
	output := append([]byte(nil), input[:33]...)
	output = append(output, chunk...)
	return append(output, input[33:]...)
}

func webPVP8X(width, height int, animated bool) []byte {
	data := make([]byte, 10)
	if animated {
		data[0] = 0x02
	}
	writeUint24LE(data[4:7], width-1)
	writeUint24LE(data[7:10], height-1)
	output := make([]byte, 12+8+len(data))
	copy(output[:4], "RIFF")
	binary.LittleEndian.PutUint32(output[4:8], uint32(len(output)-8))
	copy(output[8:12], "WEBP")
	copy(output[12:16], "VP8X")
	binary.LittleEndian.PutUint32(output[16:20], uint32(len(data)))
	copy(output[20:], data)
	return output
}

func writeUint24LE(target []byte, value int) {
	target[0] = byte(value)
	target[1] = byte(value >> 8)
	target[2] = byte(value >> 16)
}
