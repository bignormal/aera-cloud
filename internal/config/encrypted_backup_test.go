package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testEncryptedBackupEnabled   = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED"
	testEncryptedBackupEndpoint  = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENDPOINT"
	testEncryptedBackupBucket    = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_BUCKET"
	testEncryptedBackupRegion    = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_REGION"
	testEncryptedBackupAccessKey = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ACCESS_KEY"
	testEncryptedBackupSecretKey = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_SECRET_KEY"
	testEncryptedBackupUseTLS    = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_USE_TLS"
)

func TestEncryptedBackupConfigurationDefaultsDisabledWithHardBounds(t *testing.T) {
	cfg, err := Load(mapLookup(validEnvironment("production")))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertEncryptedBackupField(t, cfg, "Enabled", false)
	assertEncryptedBackupField(t, cfg, "MaxBackupBytes", int64(1<<30))
	assertEncryptedBackupField(t, cfg, "MaxBackupsPerLineage", 3)
	assertEncryptedBackupField(t, cfg, "MaxAccountBytes", int64(5<<30))
	assertEncryptedBackupField(t, cfg, "IncompleteUploadTTL", 24*time.Hour)
}

func TestEncryptedBackupConfigurationLoadsCompleteObjectStore(t *testing.T) {
	env := completeEncryptedBackupEnvironment("production")

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertEncryptedBackupField(t, cfg, "Enabled", true)
	assertEncryptedBackupField(t, cfg, "Endpoint", "backup-storage.internal:9000")
	assertEncryptedBackupField(t, cfg, "Bucket", "agentera-encrypted-backups")
	assertEncryptedBackupField(t, cfg, "Region", "us-east-1")
	assertEncryptedBackupField(t, cfg, "AccessKey", "backup-access")
	assertEncryptedBackupField(t, cfg, "SecretKey", "backup-secret")
	assertEncryptedBackupField(t, cfg, "UseTLS", true)
}

func TestEncryptedBackupConfigurationRequiresCompleteObjectStore(t *testing.T) {
	required := []string{
		testEncryptedBackupEndpoint,
		testEncryptedBackupBucket,
		testEncryptedBackupRegion,
		testEncryptedBackupAccessKey,
		testEncryptedBackupSecretKey,
		testEncryptedBackupUseTLS,
	}
	for _, missing := range required {
		t.Run(missing, func(t *testing.T) {
			env := completeEncryptedBackupEnvironment("production")
			delete(env, missing)
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("Load() error = %v, want missing %s", err, missing)
			}
		})
	}
}

func TestEncryptedBackupConfigurationRejectsInvalidFlagsAndEndpoints(t *testing.T) {
	t.Run("invalid feature flag", func(t *testing.T) {
		env := validEnvironment("production")
		env[testEncryptedBackupEnabled] = "sometimes"
		_, err := Load(mapLookup(env))
		if err == nil || !strings.Contains(err.Error(), "true or false") {
			t.Fatalf("Load() error = %v, want boolean flag validation", err)
		}
	})

	t.Run("invalid TLS flag", func(t *testing.T) {
		env := completeEncryptedBackupEnvironment("production")
		env[testEncryptedBackupUseTLS] = "sometimes"
		_, err := Load(mapLookup(env))
		if err == nil || !strings.Contains(err.Error(), testEncryptedBackupUseTLS) {
			t.Fatalf("Load() error = %v, want TLS flag validation", err)
		}
	})

	for _, endpoint := range []string{
		"https://backup-storage.internal:9000",
		"user:password@backup-storage.internal:9000",
		"backup-storage.internal:9000/private",
	} {
		t.Run(endpoint, func(t *testing.T) {
			env := completeEncryptedBackupEnvironment("production")
			env[testEncryptedBackupEndpoint] = endpoint
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), testEncryptedBackupEndpoint) {
				t.Fatalf("Load() error = %v, want endpoint validation", err)
			}
		})
	}
}

func TestEncryptedBackupConfigurationRejectsProductionPlaintextNonLoopback(t *testing.T) {
	env := completeEncryptedBackupEnvironment("production")
	env[testEncryptedBackupUseTLS] = "false"

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("Load() error = %v, want plaintext production endpoint rejection", err)
	}
}

func TestEncryptedBackupConfigurationAllowsDevelopmentPlaintextLoopback(t *testing.T) {
	env := completeEncryptedBackupEnvironment("development")
	env[testEncryptedBackupEndpoint] = "127.0.0.1:59010"
	env[testEncryptedBackupUseTLS] = "false"

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertEncryptedBackupField(t, cfg, "Enabled", true)
	assertEncryptedBackupField(t, cfg, "Endpoint", "127.0.0.1:59010")
	assertEncryptedBackupField(t, cfg, "UseTLS", false)
}

func TestEncryptedBackupConfigurationAllowsInternalBetaPlaintextPrivateService(t *testing.T) {
	env := completeEncryptedBackupEnvironment("internal_beta")
	env[testEncryptedBackupEndpoint] = "aera-backup:9000"
	env[testEncryptedBackupUseTLS] = "false"

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertEncryptedBackupField(t, cfg, "Enabled", true)
	assertEncryptedBackupField(t, cfg, "Endpoint", "aera-backup:9000")
	assertEncryptedBackupField(t, cfg, "UseTLS", false)
}

func TestEncryptedBackupConfigurationRejectsInternalBetaPlaintextRoutableHost(t *testing.T) {
	for _, endpoint := range []string{"backup.example.com:9000", "192.0.2.20:9000"} {
		t.Run(endpoint, func(t *testing.T) {
			env := completeEncryptedBackupEnvironment("internal_beta")
			env[testEncryptedBackupEndpoint] = endpoint
			env[testEncryptedBackupUseTLS] = "false"

			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), "private service") {
				t.Fatalf("Load() error = %v, want private-service rejection", err)
			}
		})
	}
}

func completeEncryptedBackupEnvironment(environment string) map[string]string {
	env := validEnvironment(environment)
	env[testEncryptedBackupEnabled] = "true"
	env[testEncryptedBackupEndpoint] = "backup-storage.internal:9000"
	env[testEncryptedBackupBucket] = "agentera-encrypted-backups"
	env[testEncryptedBackupRegion] = "us-east-1"
	env[testEncryptedBackupAccessKey] = "backup-access"
	env[testEncryptedBackupSecretKey] = "backup-secret"
	env[testEncryptedBackupUseTLS] = "true"
	return env
}

func assertEncryptedBackupField(t *testing.T, cfg Config, name string, expected any) {
	t.Helper()
	outer := reflect.ValueOf(cfg).FieldByName("EncryptedBackup")
	if !outer.IsValid() {
		t.Fatal("Config.EncryptedBackup does not exist")
	}
	field := outer.FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("EncryptedBackupConfig.%s does not exist", name)
	}
	actual := field.Interface()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("EncryptedBackupConfig.%s = %#v, want %#v", name, actual, expected)
	}
}
