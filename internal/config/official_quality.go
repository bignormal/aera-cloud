package config

import (
	"fmt"
	"strings"
)

const (
	envOfficialQualityEnabled                  = "AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED"
	envOfficialQualityPseudonymHMACActiveKeyID = "AGENTERA_CLOUD_OFFICIAL_QUALITY_PSEUDONYM_HMAC_ACTIVE_KEY_ID"
	envOfficialQualityPseudonymHMACKeys        = "AGENTERA_CLOUD_OFFICIAL_QUALITY_PSEUDONYM_HMAC_KEYS"

	officialQualityRawRetentionDays       = 30
	officialQualityAggregateRetentionDays = 180
	officialQualityMinimumSubjects        = 10
)

type OfficialQualityConfig struct {
	Enabled                bool
	PseudonymHMACActiveKey string
	PseudonymHMACKeys      map[string][]byte
	RawRetentionDays       int
	AggregateRetentionDays int
	MinimumSubjects        int
}

func loadOfficialQuality(lookup LookupEnv, officialAgentEnabled bool) (OfficialQualityConfig, error) {
	defaults := OfficialQualityConfig{
		RawRetentionDays:       officialQualityRawRetentionDays,
		AggregateRetentionDays: officialQualityAggregateRetentionDays,
		MinimumSubjects:        officialQualityMinimumSubjects,
	}
	raw, ok := lookup(envOfficialQualityEnabled)
	enabled := strings.TrimSpace(raw)
	if !ok || enabled == "" || strings.EqualFold(enabled, "false") {
		return defaults, nil
	}
	if !strings.EqualFold(enabled, "true") {
		return OfficialQualityConfig{}, fmt.Errorf("%s must be true or false", envOfficialQualityEnabled)
	}
	if !officialAgentEnabled {
		return OfficialQualityConfig{}, fmt.Errorf("official quality requires the official Agent control plane")
	}
	keys, err := loadKeyRing(
		lookup,
		envOfficialQualityPseudonymHMACActiveKeyID,
		envOfficialQualityPseudonymHMACKeys,
		32,
		true,
	)
	if err != nil {
		return OfficialQualityConfig{}, err
	}
	if err := requireIndependentKeyRing("official quality pseudonym", keys); err != nil {
		return OfficialQualityConfig{}, err
	}
	defaults.Enabled = true
	defaults.PseudonymHMACActiveKey = keys.ActiveKeyID
	defaults.PseudonymHMACKeys = keys.Keys
	return defaults, nil
}
