package config

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testInternalAdminEnabled          = "AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED"
	testInternalAdminListenAddr       = "AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR"
	testInternalAdminServerCertFile   = "AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE"
	testInternalAdminServerKeyFile    = "AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE"
	testInternalAdminClientCAFile     = "AGENTERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE"
	testInternalAdminJWTPublicKeyFile = "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE"
	testInternalAdminJWTIssuer        = "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_ISSUER"
	testInternalAdminJWTSubject       = "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_SUBJECT"
	testInternalAdminHMACActiveKeyID  = "AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_ACTIVE_KEY_ID"
	testInternalAdminHMACKeys         = "AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_KEYS"
)

func TestLoadLeavesInternalAdminDisabledWithoutSecretFiles(t *testing.T) {
	for _, enabled := range []string{"", "false"} {
		t.Run("enabled="+enabled, func(t *testing.T) {
			env := validEnvironment("development")
			if enabled != "" {
				env[testInternalAdminEnabled] = enabled
			}

			lookup := func(key string) (string, bool) {
				if strings.HasPrefix(key, "AGENTERA_CLOUD_INTERNAL_ADMIN_") && key != testInternalAdminEnabled {
					t.Fatalf("disabled Internal Admin unexpectedly read %s", key)
				}
				value, ok := env[key]
				return value, ok
			}

			cfg, err := Load(lookup)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.InternalAdmin.Enabled {
				t.Fatal("InternalAdmin.Enabled = true, want false")
			}
		})
	}
}

func TestLoadRequiresEveryInternalAdminSettingWhenEnabled(t *testing.T) {
	requiredKeys := []string{
		testInternalAdminListenAddr,
		testInternalAdminServerCertFile,
		testInternalAdminServerKeyFile,
		testInternalAdminClientCAFile,
		testInternalAdminJWTPublicKeyFile,
		testInternalAdminJWTIssuer,
		testInternalAdminJWTSubject,
		testInternalAdminHMACActiveKeyID,
		testInternalAdminHMACKeys,
	}

	for _, missing := range requiredKeys {
		t.Run(missing, func(t *testing.T) {
			env := validInternalAdminEnvironment()
			delete(env, missing)

			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), missing+" is required") {
				t.Fatalf("Load() error = %v, want missing %s error", err, missing)
			}
		})
	}
}

func TestLoadAcceptsCompleteInternalAdminConfiguration(t *testing.T) {
	env := validInternalAdminEnvironment()

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	internal := cfg.InternalAdmin
	if !internal.Enabled || internal.ListenAddr != "127.0.0.1:8443" {
		t.Fatalf("InternalAdmin enabled/listen = %t / %q", internal.Enabled, internal.ListenAddr)
	}
	if internal.ServerCertFile != "/run/secrets/internal-admin-server.crt" ||
		internal.ServerKeyFile != "/run/secrets/internal-admin-server.key" ||
		internal.ClientCAFile != "/run/secrets/internal-admin-client-ca.crt" ||
		internal.JWTPublicKeyFile != "/run/secrets/internal-admin-jwt.pub" {
		t.Fatalf("InternalAdmin file configuration = %#v", internal)
	}
	if internal.JWTIssuer != "aera-admin" || internal.JWTSubject != "admin-bff" {
		t.Fatalf("InternalAdmin service identity = %q / %q", internal.JWTIssuer, internal.JWTSubject)
	}
	if internal.HMACKeys.ActiveKeyID != "admin-hmac-v1" ||
		!bytes.Equal(internal.HMACKeys.Keys["admin-hmac-v1"], bytes.Repeat([]byte{21}, 32)) {
		t.Fatal("InternalAdmin HMAC key ring was not decoded")
	}
}

func TestLoadRejectsInvalidInternalAdminEnableValue(t *testing.T) {
	env := validEnvironment("development")
	env[testInternalAdminEnabled] = "1"

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "must be true or false") {
		t.Fatalf("Load() error = %v, want strict boolean error", err)
	}
}

func TestLoadRejectsInternalAdminOnPublicListener(t *testing.T) {
	env := validInternalAdminEnvironment()
	env[testInternalAdminListenAddr] = env["AGENTERA_CLOUD_LISTEN_ADDR"]

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("Load() error = %v, want listener separation error", err)
	}
}

func TestLoadRejectsInvalidInternalAdminServiceIdentity(t *testing.T) {
	for _, key := range []string{testInternalAdminJWTIssuer, testInternalAdminJWTSubject} {
		t.Run(key, func(t *testing.T) {
			env := validInternalAdminEnvironment()
			env[key] = "Admin BFF"

			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), key+" is invalid") {
				t.Fatalf("Load() error = %v, want invalid identity error", err)
			}
		})
	}
}

func TestLoadRequiresExactInternalAdminHMACKeyLength(t *testing.T) {
	for _, length := range []int{31, 33} {
		t.Run(string(rune('A'+length-31)), func(t *testing.T) {
			env := validInternalAdminEnvironment()
			env[testInternalAdminHMACKeys] = encodedKeyRing("admin-hmac-v1", bytes.Repeat([]byte{21}, length))

			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), "must be 32 bytes") {
				t.Fatalf("Load() error = %v, want exact key length error", err)
			}
		})
	}
}

func validInternalAdminEnvironment() map[string]string {
	env := validEnvironment("development")
	env[testInternalAdminEnabled] = "true"
	env[testInternalAdminListenAddr] = "127.0.0.1:8443"
	env[testInternalAdminServerCertFile] = "/run/secrets/internal-admin-server.crt"
	env[testInternalAdminServerKeyFile] = "/run/secrets/internal-admin-server.key"
	env[testInternalAdminClientCAFile] = "/run/secrets/internal-admin-client-ca.crt"
	env[testInternalAdminJWTPublicKeyFile] = "/run/secrets/internal-admin-jwt.pub"
	env[testInternalAdminJWTIssuer] = "aera-admin"
	env[testInternalAdminJWTSubject] = "admin-bff"
	env[testInternalAdminHMACActiveKeyID] = "admin-hmac-v1"
	env[testInternalAdminHMACKeys] = encodedKeyRing("admin-hmac-v1", bytes.Repeat([]byte{21}, 32))
	return env
}
