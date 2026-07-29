package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestOfficialAgentConfigurationDefaultsDisabled(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		t.Run(environment+" missing", func(t *testing.T) {
			cfg, err := Load(mapLookup(validEnvironment(environment)))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.OfficialAgent.Enabled {
				t.Fatal("OfficialAgent.Enabled = true, want false")
			}
		})

		t.Run(environment+" explicit false", func(t *testing.T) {
			env := validEnvironment(environment)
			env[envOfficialAgentsEnabled] = "false"
			cfg, err := Load(mapLookup(env))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.OfficialAgent.Enabled {
				t.Fatal("OfficialAgent.Enabled = true, want false")
			}
		})
	}
}

func TestOfficialAgentConfigurationLoadsCompleteConfiguration(t *testing.T) {
	platformID := uuid.New()
	keyMaterial := bytes.Repeat([]byte{14}, 32)
	env := validEnvironment("production")
	env[envOfficialAgentsEnabled] = "true"
	env[envPlatformID] = platformID.String()
	env[envPlatformKey] = "agentera_official"
	env[envPlatformDisplayName] = "Aera Official"
	env[envOfficialRolloutHMACActiveKeyID] = "rollout-v1"
	env[envOfficialRolloutHMACKeys] = encodedKeyRing("rollout-v1", keyMaterial)

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OfficialAgent.Enabled {
		t.Fatal("OfficialAgent.Enabled = false, want true")
	}
	if cfg.OfficialAgent.PlatformID != platformID {
		t.Fatalf("PlatformID = %s, want %s", cfg.OfficialAgent.PlatformID, platformID)
	}
	if cfg.OfficialAgent.PlatformKey != "agentera_official" {
		t.Fatalf("PlatformKey = %q", cfg.OfficialAgent.PlatformKey)
	}
	if cfg.OfficialAgent.PlatformDisplayName != "Aera Official" {
		t.Fatalf("PlatformDisplayName = %q", cfg.OfficialAgent.PlatformDisplayName)
	}
	if cfg.OfficialAgent.RolloutHMACActiveKey != "rollout-v1" {
		t.Fatalf("RolloutHMACActiveKey = %q", cfg.OfficialAgent.RolloutHMACActiveKey)
	}
	if !bytes.Equal(cfg.OfficialAgent.RolloutHMACKeys["rollout-v1"], keyMaterial) {
		t.Fatal("RolloutHMACKeys active material differs")
	}
}

func TestOfficialAgentConfigurationRejectsPartialOrInvalidValues(t *testing.T) {
	complete := func() map[string]string {
		env := validEnvironment("production")
		env[envOfficialAgentsEnabled] = "true"
		env[envPlatformID] = uuid.NewString()
		env[envPlatformKey] = "agentera_official"
		env[envPlatformDisplayName] = "Aera Official"
		env[envOfficialRolloutHMACActiveKeyID] = "rollout-v1"
		env[envOfficialRolloutHMACKeys] = encodedKeyRing("rollout-v1", bytes.Repeat([]byte{14}, 32))
		return env
	}

	for _, key := range []string{
		envPlatformID,
		envPlatformKey,
		envPlatformDisplayName,
		envOfficialRolloutHMACActiveKeyID,
		envOfficialRolloutHMACKeys,
	} {
		t.Run("missing "+key, func(t *testing.T) {
			env := complete()
			delete(env, key)
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load() error = %v, want missing %s", err, key)
			}
		})
	}

	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{name: "invalid feature flag", key: envOfficialAgentsEnabled, value: "sometimes", want: "true or false"},
		{name: "non UUID platform ID", key: envPlatformID, value: "platform-one", want: envPlatformID},
		{name: "nil platform ID", key: envPlatformID, value: uuid.Nil.String(), want: envPlatformID},
		{name: "non canonical platform ID", key: envPlatformID, value: "123E4567-E89B-12D3-A456-426614174000", want: envPlatformID},
		{name: "invalid platform key", key: envPlatformKey, value: "Official Platform", want: envPlatformKey},
		{name: "unsafe display name", key: envPlatformDisplayName, value: "Aera\nOfficial", want: envPlatformDisplayName},
		{name: "short rollout key", key: envOfficialRolloutHMACKeys, value: encodedKeyRing("rollout-v1", bytes.Repeat([]byte{14}, 31)), want: "32 bytes"},
		{name: "missing active rollout key", key: envOfficialRolloutHMACActiveKeyID, value: "rollout-v2", want: "active key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := complete()
			env[test.key] = test.value
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOfficialAgentConfigurationRejectsDuplicateOrReusedKeyMaterial(t *testing.T) {
	platformID := uuid.NewString()
	base := func() map[string]string {
		env := validEnvironment("production")
		env[envOfficialAgentsEnabled] = "true"
		env[envPlatformID] = platformID
		env[envPlatformKey] = "agentera_official"
		env[envPlatformDisplayName] = "Aera Official"
		env[envOfficialRolloutHMACActiveKeyID] = "rollout-v1"
		return env
	}

	t.Run("duplicate rollout material", func(t *testing.T) {
		env := base()
		material := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{14}, 32))
		env[envOfficialRolloutHMACKeys] = `{"rollout-v1":"` + material + `","rollout-v2":"` + material + `"}`
		_, err := Load(mapLookup(env))
		if err == nil || !strings.Contains(err.Error(), "independent") {
			t.Fatalf("Load() error = %v, want independent rollout keys", err)
		}
	})

	t.Run("reused existing key material", func(t *testing.T) {
		env := base()
		env[envOfficialRolloutHMACKeys] = encodedKeyRing("rollout-v1", bytes.Repeat([]byte{1}, 32))
		_, err := Load(mapLookup(env))
		if err == nil || !strings.Contains(err.Error(), "independent") {
			t.Fatalf("Load() error = %v, want independent existing and rollout keys", err)
		}
	})
}
