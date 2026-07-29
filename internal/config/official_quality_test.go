package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestOfficialQualityConfigurationDefaultsDisabledWithFixedPrivacyBounds(t *testing.T) {
	cfg, err := Load(mapLookup(validEnvironment("production")))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OfficialQuality.Enabled {
		t.Fatal("OfficialQuality.Enabled = true, want false")
	}
	if cfg.OfficialQuality.RawRetentionDays != 30 || cfg.OfficialQuality.AggregateRetentionDays != 180 ||
		cfg.OfficialQuality.MinimumSubjects != 10 {
		t.Fatalf("OfficialQuality privacy bounds = %+v", cfg.OfficialQuality)
	}
}

func TestOfficialQualityConfigurationLoadsIndependentPseudonymKeyRing(t *testing.T) {
	key := bytes.Repeat([]byte{0x63}, 32)
	env := completeOfficialQualityEnvironment()
	env[envOfficialQualityPseudonymHMACKeys] = encodedKeyRing("quality-v1", key)

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OfficialQuality.Enabled || cfg.OfficialQuality.PseudonymHMACActiveKey != "quality-v1" {
		t.Fatalf("OfficialQuality = %+v", cfg.OfficialQuality)
	}
	if !bytes.Equal(cfg.OfficialQuality.PseudonymHMACKeys["quality-v1"], key) {
		t.Fatal("official quality pseudonym key material differs")
	}
}

func TestOfficialQualityConfigurationFailsClosedWhenEnabledButIncomplete(t *testing.T) {
	t.Run("requires official agent control plane", func(t *testing.T) {
		env := validEnvironment("production")
		env[envOfficialQualityEnabled] = "true"
		env[envOfficialQualityPseudonymHMACActiveKeyID] = "quality-v1"
		env[envOfficialQualityPseudonymHMACKeys] = encodedKeyRing("quality-v1", bytes.Repeat([]byte{0x63}, 32))
		_, err := Load(mapLookup(env))
		if err == nil || !strings.Contains(err.Error(), "official Agent") {
			t.Fatalf("Load() error = %v, want official Agent dependency", err)
		}
	})

	for _, mutation := range []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{name: "invalid flag", key: envOfficialQualityEnabled, value: "sometimes", want: "true or false"},
		{name: "missing active key", key: envOfficialQualityPseudonymHMACActiveKeyID, value: "missing", want: "active key"},
		{name: "short key", key: envOfficialQualityPseudonymHMACKeys, value: encodedKeyRing("quality-v1", bytes.Repeat([]byte{0x63}, 31)), want: "32 bytes"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			env := completeOfficialQualityEnvironment()
			env[mutation.key] = mutation.value
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("Load() error = %v, want %q", err, mutation.want)
			}
		})
	}
}

func TestOfficialQualityConfigurationRejectsKeyReuse(t *testing.T) {
	env := completeOfficialQualityEnvironment()
	env[envOfficialQualityPseudonymHMACKeys] = encodedKeyRing("quality-v1", bytes.Repeat([]byte{1}, 32))
	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "independent") {
		t.Fatalf("Load() error = %v, want independent key material", err)
	}
}

func completeOfficialQualityEnvironment() map[string]string {
	env := validEnvironment("production")
	env[envOfficialAgentsEnabled] = "true"
	env[envPlatformID] = uuid.NewString()
	env[envPlatformKey] = "agentera_official"
	env[envPlatformDisplayName] = "Aera Official"
	env[envOfficialRolloutHMACActiveKeyID] = "rollout-v1"
	env[envOfficialRolloutHMACKeys] = encodedKeyRing("rollout-v1", bytes.Repeat([]byte{0x62}, 32))
	env[envOfficialQualityEnabled] = "true"
	env[envOfficialQualityPseudonymHMACActiveKeyID] = "quality-v1"
	env[envOfficialQualityPseudonymHMACKeys] = encodedKeyRing("quality-v1", bytes.Repeat([]byte{0x63}, 32))
	return env
}
