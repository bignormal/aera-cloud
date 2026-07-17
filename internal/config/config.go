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
	envVerificationCodeActiveKeyID   = "AGENTERA_CLOUD_VERIFICATION_CODE_ACTIVE_KEY_ID"
	envVerificationCodeKeys          = "AGENTERA_CLOUD_VERIFICATION_CODE_KEYS"
	envVerificationRequestHMACKey    = "AGENTERA_CLOUD_VERIFICATION_REQUEST_HMAC_KEY"
	envSMTPHost                      = "AGENTERA_CLOUD_SMTP_HOST"
	envSMTPPort                      = "AGENTERA_CLOUD_SMTP_PORT"
	envSMTPUsername                  = "AGENTERA_CLOUD_SMTP_USERNAME"
	envSMTPPassword                  = "AGENTERA_CLOUD_SMTP_PASSWORD"
	envSMTPFromAddress               = "AGENTERA_CLOUD_SMTP_FROM_ADDRESS"
	envSMTPFromName                  = "AGENTERA_CLOUD_SMTP_FROM_NAME"
	envSMSEndpoint                   = "AGENTERA_CLOUD_SMS_ENDPOINT"
	envSMSAPIKey                     = "AGENTERA_CLOUD_SMS_API_KEY"
	envSMSSenderID                   = "AGENTERA_CLOUD_SMS_SENDER_ID"
	envCaptchaEndpoint               = "AGENTERA_CLOUD_CAPTCHA_ENDPOINT"
	envCaptchaSecret                 = "AGENTERA_CLOUD_CAPTCHA_SECRET"
)

type LookupEnv func(string) (string, bool)

type KeyRing struct {
	ActiveKeyID string
	Keys        map[string][]byte
}

type Config struct {
	Environment                string
	ListenAddr                 string
	PublicURL                  string
	DatabaseURL                string
	RedisAddr                  string
	RedisUsername              string
	RedisPassword              string
	RedisDB                    int
	IdentityEncryptionKeyRing  KeyRing
	IdentityLookupKeyRing      KeyRing
	VerificationCodeKeyRing    KeyRing
	VerificationRequestHMACKey []byte
	SMTPHost                   string
	SMTPPort                   int
	SMTPUsername               string
	SMTPPassword               string
	SMTPFromAddress            string
	SMTPFromName               string
	SMSEndpoint                string
	SMSAPIKey                  string
	SMSSenderID                string
	CaptchaEndpoint            string
	CaptchaSecret              string
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
	verificationCodeKeyRing, err := loadKeyRing(
		lookup,
		envVerificationCodeActiveKeyID,
		envVerificationCodeKeys,
		32,
		false,
	)
	if err != nil {
		return Config{}, err
	}
	verificationRequestHMACKey, err := loadBase64Key(lookup, envVerificationRequestHMACKey, 32)
	if err != nil {
		return Config{}, err
	}
	smtpHost, err := required(lookup, envSMTPHost)
	if err != nil {
		return Config{}, err
	}
	smtpPortText, err := required(lookup, envSMTPPort)
	if err != nil {
		return Config{}, err
	}
	smtpPort, err := strconv.Atoi(smtpPortText)
	if err != nil || smtpPort <= 0 || smtpPort > 65535 {
		return Config{}, fmt.Errorf("%s must be an integer between 1 and 65535", envSMTPPort)
	}
	smtpUsername, err := required(lookup, envSMTPUsername)
	if err != nil {
		return Config{}, err
	}
	smtpPassword, err := required(lookup, envSMTPPassword)
	if err != nil {
		return Config{}, err
	}
	smtpFromAddress, err := required(lookup, envSMTPFromAddress)
	if err != nil {
		return Config{}, err
	}
	smtpFromName, err := required(lookup, envSMTPFromName)
	if err != nil {
		return Config{}, err
	}
	smsEndpoint, err := required(lookup, envSMSEndpoint)
	if err != nil {
		return Config{}, err
	}
	smsAPIKey, err := required(lookup, envSMSAPIKey)
	if err != nil {
		return Config{}, err
	}
	smsSenderID, err := required(lookup, envSMSSenderID)
	if err != nil {
		return Config{}, err
	}
	captchaEndpoint, err := required(lookup, envCaptchaEndpoint)
	if err != nil {
		return Config{}, err
	}
	captchaSecret, err := required(lookup, envCaptchaSecret)
	if err != nil {
		return Config{}, err
	}

	return Config{
		Environment:                environment,
		ListenAddr:                 listenAddr,
		PublicURL:                  publicURL,
		DatabaseURL:                databaseURL,
		RedisAddr:                  redisAddr,
		RedisUsername:              redisUsername,
		RedisPassword:              redisPassword,
		RedisDB:                    redisDB,
		IdentityEncryptionKeyRing:  identityEncryptionKeyRing,
		IdentityLookupKeyRing:      identityLookupKeyRing,
		VerificationCodeKeyRing:    verificationCodeKeyRing,
		VerificationRequestHMACKey: verificationRequestHMACKey,
		SMTPHost:                   smtpHost,
		SMTPPort:                   smtpPort,
		SMTPUsername:               smtpUsername,
		SMTPPassword:               smtpPassword,
		SMTPFromAddress:            smtpFromAddress,
		SMTPFromName:               smtpFromName,
		SMSEndpoint:                smsEndpoint,
		SMSAPIKey:                  smsAPIKey,
		SMSSenderID:                smsSenderID,
		CaptchaEndpoint:            captchaEndpoint,
		CaptchaSecret:              captchaSecret,
	}, nil
}

func loadBase64Key(lookup LookupEnv, key string, minimumBytes int) ([]byte, error) {
	encoded, err := required(lookup, key)
	if err != nil {
		return nil, err
	}
	material, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64", key)
	}
	if len(material) < minimumBytes {
		return nil, fmt.Errorf("%s must decode to at least %d bytes", key, minimumBytes)
	}
	return append([]byte(nil), material...), nil
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
