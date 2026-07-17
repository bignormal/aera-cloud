package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	envEnvironment   = "AGENTERA_CLOUD_ENVIRONMENT"
	envListenAddr    = "AGENTERA_CLOUD_LISTEN_ADDR"
	envPublicURL     = "AGENTERA_CLOUD_PUBLIC_URL"
	envDatabaseURL   = "AGENTERA_CLOUD_DATABASE_URL"
	envRedisAddr     = "AGENTERA_CLOUD_REDIS_ADDR"
	envRedisUsername = "AGENTERA_CLOUD_REDIS_USERNAME"
	envRedisPassword = "AGENTERA_CLOUD_REDIS_PASSWORD"
	envRedisDB       = "AGENTERA_CLOUD_REDIS_DB"

	envIdentityEncryptionActiveKeyID = "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID"
	envIdentityEncryptionKeys        = "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS"
	envIdentityLookupActiveKeyID     = "AGENTERA_CLOUD_IDENTITY_LOOKUP_ACTIVE_KEY_ID"
	envIdentityLookupKeys            = "AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS"
)

type LookupEnv func(string) (string, bool)

type KeyRing struct {
	ActiveKeyID string
	Keys        map[string][]byte
}

type Config struct {
	Environment               string
	ListenAddr                string
	PublicURL                 string
	DatabaseURL               string
	RedisAddr                 string
	RedisUsername             string
	RedisPassword             string
	RedisDB                   int
	IdentityEncryptionKeyRing KeyRing
	IdentityLookupKeyRing     KeyRing
}

func Load(lookup LookupEnv) (Config, error) {
	environment, err := required(lookup, envEnvironment)
	if err != nil {
		return Config{}, err
	}
	if environment != "development" && environment != "test" && environment != "production" {
		return Config{}, fmt.Errorf("%s must be development, test, or production", envEnvironment)
	}

	listenAddr, err := required(lookup, envListenAddr)
	if err != nil {
		return Config{}, err
	}
	publicURL, err := required(lookup, envPublicURL)
	if err != nil {
		return Config{}, err
	}
	if err := validatePublicURL(environment, publicURL); err != nil {
		return Config{}, err
	}

	databaseURL, err := required(lookup, envDatabaseURL)
	if err != nil {
		return Config{}, err
	}
	if err := validateDatabaseURL(databaseURL); err != nil {
		return Config{}, err
	}

	redisAddr, err := required(lookup, envRedisAddr)
	if err != nil {
		return Config{}, err
	}
	redisUsername, err := required(lookup, envRedisUsername)
	if err != nil {
		return Config{}, err
	}
	redisPassword, err := required(lookup, envRedisPassword)
	if err != nil {
		return Config{}, err
	}
	redisDBText, err := required(lookup, envRedisDB)
	if err != nil {
		return Config{}, err
	}
	redisDB, err := strconv.Atoi(redisDBText)
	if err != nil || redisDB < 0 || redisDB > 15 {
		return Config{}, fmt.Errorf("%s must be an integer between 0 and 15", envRedisDB)
	}
	identityEncryptionKeyRing, err := loadKeyRing(
		lookup,
		envIdentityEncryptionActiveKeyID,
		envIdentityEncryptionKeys,
		32,
		true,
	)
	if err != nil {
		return Config{}, err
	}
	identityLookupKeyRing, err := loadKeyRing(
		lookup,
		envIdentityLookupActiveKeyID,
		envIdentityLookupKeys,
		32,
		false,
	)
	if err != nil {
		return Config{}, err
	}

	return Config{
		Environment:               environment,
		ListenAddr:                listenAddr,
		PublicURL:                 publicURL,
		DatabaseURL:               databaseURL,
		RedisAddr:                 redisAddr,
		RedisUsername:             redisUsername,
		RedisPassword:             redisPassword,
		RedisDB:                   redisDB,
		IdentityEncryptionKeyRing: identityEncryptionKeyRing,
		IdentityLookupKeyRing:     identityLookupKeyRing,
	}, nil
}

func loadKeyRing(
	lookup LookupEnv,
	activeKeyEnv string,
	keysEnv string,
	minimumBytes int,
	exactLength bool,
) (KeyRing, error) {
	activeKeyID, err := required(lookup, activeKeyEnv)
	if err != nil {
		return KeyRing{}, err
	}
	rawKeys, err := required(lookup, keysEnv)
	if err != nil {
		return KeyRing{}, err
	}
	var encodedKeys map[string]string
	if err := json.Unmarshal([]byte(rawKeys), &encodedKeys); err != nil || len(encodedKeys) == 0 {
		return KeyRing{}, fmt.Errorf("%s must be a JSON object of base64 keys", keysEnv)
	}

	keys := make(map[string][]byte, len(encodedKeys))
	for keyID, encoded := range encodedKeys {
		if strings.TrimSpace(keyID) == "" || keyID != strings.TrimSpace(keyID) {
			return KeyRing{}, fmt.Errorf("%s contains an invalid key ID", keysEnv)
		}
		material, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return KeyRing{}, fmt.Errorf("%s value for key %q must be base64", keysEnv, keyID)
		}
		invalidLength := len(material) < minimumBytes
		lengthDescription := fmt.Sprintf("at least %d bytes", minimumBytes)
		if exactLength {
			invalidLength = len(material) != minimumBytes
			lengthDescription = fmt.Sprintf("%d bytes", minimumBytes)
		}
		if invalidLength {
			return KeyRing{}, fmt.Errorf("%s value for key %q must be %s", keysEnv, keyID, lengthDescription)
		}
		keys[keyID] = append([]byte(nil), material...)
	}
	if _, ok := keys[activeKeyID]; !ok {
		return KeyRing{}, fmt.Errorf("%s active key %q is not present in %s", activeKeyEnv, activeKeyID, keysEnv)
	}
	return KeyRing{ActiveKeyID: activeKeyID, Keys: keys}, nil
}

func required(lookup LookupEnv, key string) (string, error) {
	value, ok := lookup(key)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}

func validatePublicURL(environment, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute origin", envPublicURL)
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must contain only scheme and host", envPublicURL)
	}

	if environment == "production" {
		if parsed.Scheme != "https" {
			return fmt.Errorf("%s must use HTTPS in production", envPublicURL)
		}
		return nil
	}

	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("%s may use HTTP only on a loopback host", envPublicURL)
	}
	return nil
}

func validateDatabaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		return fmt.Errorf("%s must be a PostgreSQL URL", envDatabaseURL)
	}
	if parsed.User == nil || strings.TrimSpace(parsed.User.Username()) == "" {
		return fmt.Errorf("%s must include a dedicated database role", envDatabaseURL)
	}
	if password, ok := parsed.User.Password(); !ok || password == "" {
		return fmt.Errorf("%s must include database credentials", envDatabaseURL)
	}
	databaseName := strings.Trim(parsed.Path, "/")
	if databaseName != "aera_cloud" {
		return fmt.Errorf("%s must use the dedicated aera_cloud database", envDatabaseURL)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
