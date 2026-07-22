package config

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	envOfficialAgentsEnabled          = "AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED"
	envPlatformID                     = "AGENTERA_CLOUD_PLATFORM_ID"
	envPlatformKey                    = "AGENTERA_CLOUD_PLATFORM_KEY"
	envPlatformDisplayName            = "AGENTERA_CLOUD_PLATFORM_DISPLAY_NAME"
	envOfficialRolloutHMACActiveKeyID = "AGENTERA_CLOUD_OFFICIAL_ROLLOUT_HMAC_ACTIVE_KEY_ID"
	envOfficialRolloutHMACKeys        = "AGENTERA_CLOUD_OFFICIAL_ROLLOUT_HMAC_KEYS"
)

var officialPlatformKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

type OfficialAgentConfig struct {
	Enabled              bool
	PlatformID           uuid.UUID
	PlatformKey          string
	PlatformDisplayName  string
	RolloutHMACActiveKey string
	RolloutHMACKeys      map[string][]byte
}

func loadOfficialAgent(lookup LookupEnv) (OfficialAgentConfig, error) {
	raw, ok := lookup(envOfficialAgentsEnabled)
	enabled := strings.TrimSpace(raw)
	if !ok || enabled == "" || strings.EqualFold(enabled, "false") {
		return OfficialAgentConfig{}, nil
	}
	if !strings.EqualFold(enabled, "true") {
		return OfficialAgentConfig{}, fmt.Errorf("%s must be true or false", envOfficialAgentsEnabled)
	}

	platformIDText, err := required(lookup, envPlatformID)
	if err != nil {
		return OfficialAgentConfig{}, err
	}
	platformID, err := uuid.Parse(platformIDText)
	if err != nil || platformID == uuid.Nil || platformID.String() != platformIDText {
		return OfficialAgentConfig{}, fmt.Errorf("%s must be a canonical non-nil UUID", envPlatformID)
	}

	platformKey, err := required(lookup, envPlatformKey)
	if err != nil {
		return OfficialAgentConfig{}, err
	}
	if !officialPlatformKeyPattern.MatchString(platformKey) {
		return OfficialAgentConfig{}, fmt.Errorf("%s is invalid", envPlatformKey)
	}

	displayName, err := required(lookup, envPlatformDisplayName)
	if err != nil {
		return OfficialAgentConfig{}, err
	}
	runeCount := utf8.RuneCountInString(displayName)
	if !utf8.ValidString(displayName) || runeCount < 1 || runeCount > 100 || strings.IndexFunc(displayName, unicode.IsControl) >= 0 {
		return OfficialAgentConfig{}, fmt.Errorf("%s is invalid", envPlatformDisplayName)
	}

	rolloutKeys, err := loadKeyRing(
		lookup,
		envOfficialRolloutHMACActiveKeyID,
		envOfficialRolloutHMACKeys,
		32,
		true,
	)
	if err != nil {
		return OfficialAgentConfig{}, err
	}
	if err := requireIndependentKeyRing("official rollout", rolloutKeys); err != nil {
		return OfficialAgentConfig{}, err
	}

	return OfficialAgentConfig{
		Enabled:              true,
		PlatformID:           platformID,
		PlatformKey:          platformKey,
		PlatformDisplayName:  displayName,
		RolloutHMACActiveKey: rolloutKeys.ActiveKeyID,
		RolloutHMACKeys:      rolloutKeys.Keys,
	}, nil
}

func requireIndependentKeyRing(name string, keyRing KeyRing) error {
	materials := make(map[string][]byte, len(keyRing.Keys))
	for keyID, material := range keyRing.Keys {
		materials[fmt.Sprintf("%s %s", name, keyID)] = material
	}
	return requireIndependentKeys(materials)
}

func addKeyRingMaterials(materials map[string][]byte, name string, keyRing KeyRing) {
	for keyID, material := range keyRing.Keys {
		materials[fmt.Sprintf("%s %s", name, keyID)] = material
	}
}
