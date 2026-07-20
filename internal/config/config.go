package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
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

	envIdentityEncryptionActiveKeyID   = "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID"
	envIdentityEncryptionKeys          = "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS"
	envIdentityLookupActiveKeyID       = "AGENTERA_CLOUD_IDENTITY_LOOKUP_ACTIVE_KEY_ID"
	envIdentityLookupKeys              = "AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS"
	envVerificationCodeActiveKeyID     = "AGENTERA_CLOUD_VERIFICATION_CODE_ACTIVE_KEY_ID"
	envVerificationCodeKeys            = "AGENTERA_CLOUD_VERIFICATION_CODE_KEYS"
	envVerificationReceiptActiveKeyID  = "AGENTERA_CLOUD_VERIFICATION_RECEIPT_ACTIVE_KEY_ID"
	envVerificationReceiptKeys         = "AGENTERA_CLOUD_VERIFICATION_RECEIPT_KEYS"
	envVerificationRequestHMACKey      = "AGENTERA_CLOUD_VERIFICATION_REQUEST_HMAC_KEY"
	envBrowserSessionHMACKey           = "AGENTERA_CLOUD_BROWSER_SESSION_HMAC_KEY"
	envLoginRateHMACKey                = "AGENTERA_CLOUD_LOGIN_RATE_HMAC_KEY"
	envOAuthStateEncryptionActiveKeyID = "AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_ACTIVE_KEY_ID"
	envOAuthStateEncryptionKeys        = "AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_KEYS"
	envOAuthStateHMACKey               = "AGENTERA_CLOUD_OAUTH_STATE_HMAC_KEY"
	envRefreshTokenHMACKey             = "AGENTERA_CLOUD_REFRESH_TOKEN_HMAC_KEY"
	envAccessSigningActiveKeyID        = "AGENTERA_CLOUD_ACCESS_SIGNING_ACTIVE_KEY_ID"
	envAccessSigningKeys               = "AGENTERA_CLOUD_ACCESS_SIGNING_KEYS"
	envOfflineSigningActiveKeyID       = "AGENTERA_CLOUD_OFFLINE_SIGNING_ACTIVE_KEY_ID"
	envOfflineSigningKeys              = "AGENTERA_CLOUD_OFFLINE_SIGNING_KEYS"
	envAgentControlSigningActiveKeyID  = "AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_ACTIVE_KEY_ID"
	envAgentControlSigningKeys         = "AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_KEYS"
	envOfflinePolicyVersion            = "AGENTERA_CLOUD_OFFLINE_POLICY_VERSION"
	envActiveDeviceLimit               = "AGENTERA_CLOUD_ACTIVE_DEVICE_LIMIT"
	envBrowserCookieName               = "AGENTERA_CLOUD_BROWSER_COOKIE_NAME"
	envBrowserSessionTTLSeconds        = "AGENTERA_CLOUD_BROWSER_SESSION_TTL_SECONDS"
	envLoginIdentityLimit              = "AGENTERA_CLOUD_LOGIN_IDENTITY_LIMIT"
	envLoginIPLimit                    = "AGENTERA_CLOUD_LOGIN_IP_LIMIT"
	envLoginWindowSeconds              = "AGENTERA_CLOUD_LOGIN_WINDOW_SECONDS"
	envWorkspaceActiveOwnedLimit       = "AGENTERA_CLOUD_WORKSPACE_ACTIVE_OWNED_LIMIT"
	envWorkspaceMemberLimit            = "AGENTERA_CLOUD_WORKSPACE_MEMBER_LIMIT"
	envWorkspacePendingInviteLimit     = "AGENTERA_CLOUD_WORKSPACE_PENDING_INVITE_LIMIT"
	envWorkspaceCreateRateLimit        = "AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_LIMIT"
	envWorkspaceCreateRateWindow       = "AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_WINDOW"
	envWorkspaceInviteRateLimit        = "AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_LIMIT"
	envWorkspaceInviteRateWindow       = "AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_WINDOW"
	envWorkspaceAcceptRateLimit        = "AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_LIMIT"
	envWorkspaceAcceptRateWindow       = "AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_WINDOW"
	envOrganizationOwnedLimit          = "AGENTERA_CLOUD_ORGANIZATION_OWNED_LIMIT"
	envOrganizationMemberLimit         = "AGENTERA_CLOUD_ORGANIZATION_MEMBER_LIMIT"
	envOrganizationDepartmentLimit     = "AGENTERA_CLOUD_ORGANIZATION_DEPARTMENT_LIMIT"
	envOrganizationPendingInviteLimit  = "AGENTERA_CLOUD_ORGANIZATION_PENDING_INVITE_LIMIT"
	envOrganizationCreateRateLimit     = "AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_LIMIT"
	envOrganizationCreateRateWindow    = "AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_WINDOW"
	envOrganizationInviteRateLimit     = "AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_LIMIT"
	envOrganizationInviteRateWindow    = "AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_WINDOW"
	envOrganizationAcceptRateLimit     = "AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_LIMIT"
	envOrganizationAcceptRateWindow    = "AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_WINDOW"
	envOrganizationMutationRateLimit   = "AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_LIMIT"
	envOrganizationMutationRateWindow  = "AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_WINDOW"
	envOrganizationHighRiskRateLimit   = "AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_LIMIT"
	envOrganizationHighRiskRateWindow  = "AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_WINDOW"
	envTermsVersion                    = "AGENTERA_CLOUD_TERMS_VERSION"
	envPrivacyVersion                  = "AGENTERA_CLOUD_PRIVACY_VERSION"
	envSMTPHost                        = "AGENTERA_CLOUD_SMTP_HOST"
	envSMTPPort                        = "AGENTERA_CLOUD_SMTP_PORT"
	envSMTPUsername                    = "AGENTERA_CLOUD_SMTP_USERNAME"
	envSMTPPassword                    = "AGENTERA_CLOUD_SMTP_PASSWORD"
	envSMTPFromAddress                 = "AGENTERA_CLOUD_SMTP_FROM_ADDRESS"
	envSMTPFromName                    = "AGENTERA_CLOUD_SMTP_FROM_NAME"
	envSMSEndpoint                     = "AGENTERA_CLOUD_SMS_ENDPOINT"
	envSMSAPIKey                       = "AGENTERA_CLOUD_SMS_API_KEY"
	envSMSSenderID                     = "AGENTERA_CLOUD_SMS_SENDER_ID"
	envCaptchaEndpoint                 = "AGENTERA_CLOUD_CAPTCHA_ENDPOINT"
	envCaptchaSecret                   = "AGENTERA_CLOUD_CAPTCHA_SECRET"
)

type LookupEnv func(string) (string, bool)

type KeyRing struct {
	ActiveKeyID string
	Keys        map[string][]byte
}

type Config struct {
	Environment                    string
	ListenAddr                     string
	PublicURL                      string
	DatabaseURL                    string
	RedisAddr                      string
	RedisUsername                  string
	RedisPassword                  string
	RedisDB                        int
	IdentityEncryptionKeyRing      KeyRing
	IdentityLookupKeyRing          KeyRing
	VerificationCodeKeyRing        KeyRing
	VerificationReceiptKeyRing     KeyRing
	VerificationRequestHMACKey     []byte
	BrowserSessionHMACKey          []byte
	LoginRateHMACKey               []byte
	OAuthStateEncryptionKeyRing    KeyRing
	OAuthStateHMACKey              []byte
	RefreshTokenHMACKey            []byte
	AccessSigningKeyRing           KeyRing
	OfflineSigningKeyRing          KeyRing
	AgentControlSigningKeyRing     KeyRing
	OfflinePolicyVersion           int
	ActiveDeviceLimit              int
	BrowserCookieName              string
	BrowserSessionTTLSeconds       int
	LoginIdentityLimit             int64
	LoginIPLimit                   int64
	LoginWindowSeconds             int
	WorkspaceActiveOwnedLimit      int
	WorkspaceMemberLimit           int
	WorkspacePendingInviteLimit    int
	WorkspaceCreateRateLimit       int64
	WorkspaceCreateRateWindow      time.Duration
	WorkspaceInviteRateLimit       int64
	WorkspaceInviteRateWindow      time.Duration
	WorkspaceAcceptRateLimit       int64
	WorkspaceAcceptRateWindow      time.Duration
	OrganizationOwnedLimit         int
	OrganizationMemberLimit        int
	OrganizationDepartmentLimit    int
	OrganizationPendingInviteLimit int
	OrganizationCreateRateLimit    int64
	OrganizationCreateRateWindow   time.Duration
	OrganizationInviteRateLimit    int64
	OrganizationInviteRateWindow   time.Duration
	OrganizationAcceptRateLimit    int64
	OrganizationAcceptRateWindow   time.Duration
	OrganizationMutationRateLimit  int64
	OrganizationMutationRateWindow time.Duration
	OrganizationHighRiskRateLimit  int64
	OrganizationHighRiskRateWindow time.Duration
	TermsVersion                   string
	PrivacyVersion                 string
	SMTPHost                       string
	SMTPPort                       int
	SMTPUsername                   string
	SMTPPassword                   string
	SMTPFromAddress                string
	SMTPFromName                   string
	SMSEndpoint                    string
	SMSAPIKey                      string
	SMSSenderID                    string
	CaptchaEndpoint                string
	CaptchaSecret                  string
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
	verificationReceiptKeyRing, err := loadKeyRing(
		lookup,
		envVerificationReceiptActiveKeyID,
		envVerificationReceiptKeys,
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
	browserSessionHMACKey, err := loadBase64Key(lookup, envBrowserSessionHMACKey, 32)
	if err != nil {
		return Config{}, err
	}
	loginRateHMACKey, err := loadBase64Key(lookup, envLoginRateHMACKey, 32)
	if err != nil {
		return Config{}, err
	}
	oauthStateEncryptionKeyRing, err := loadKeyRing(
		lookup,
		envOAuthStateEncryptionActiveKeyID,
		envOAuthStateEncryptionKeys,
		32,
		true,
	)
	if err != nil {
		return Config{}, err
	}
	oauthStateHMACKey, err := loadBase64Key(lookup, envOAuthStateHMACKey, 32)
	if err != nil {
		return Config{}, err
	}
	refreshTokenHMACKey, err := loadBase64Key(lookup, envRefreshTokenHMACKey, 32)
	if err != nil {
		return Config{}, err
	}
	accessSigningKeyRing, err := loadPrivateSigningKeyRing(lookup, envAccessSigningActiveKeyID, envAccessSigningKeys)
	if err != nil {
		return Config{}, err
	}
	offlineSigningKeyRing, err := loadPrivateSigningKeyRing(lookup, envOfflineSigningActiveKeyID, envOfflineSigningKeys)
	if err != nil {
		return Config{}, err
	}
	agentControlSigningKeyRing, err := loadPrivateSigningKeyRing(
		lookup,
		envAgentControlSigningActiveKeyID,
		envAgentControlSigningKeys,
	)
	if err != nil {
		return Config{}, err
	}
	offlinePolicyVersion, err := requiredInteger(lookup, envOfflinePolicyVersion, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	activeDeviceLimit, err := requiredInteger(lookup, envActiveDeviceLimit, 5, 5)
	if err != nil {
		return Config{}, err
	}
	if err := requireIndependentKeys(map[string][]byte{
		"identity encryption":    identityEncryptionKeyRing.Keys[identityEncryptionKeyRing.ActiveKeyID],
		"identity lookup":        identityLookupKeyRing.Keys[identityLookupKeyRing.ActiveKeyID],
		"verification code":      verificationCodeKeyRing.Keys[verificationCodeKeyRing.ActiveKeyID],
		"verification receipt":   verificationReceiptKeyRing.Keys[verificationReceiptKeyRing.ActiveKeyID],
		"verification request":   verificationRequestHMACKey,
		"browser session":        browserSessionHMACKey,
		"login rate":             loginRateHMACKey,
		"OAuth state encryption": oauthStateEncryptionKeyRing.Keys[oauthStateEncryptionKeyRing.ActiveKeyID],
		"OAuth state HMAC":       oauthStateHMACKey,
		"refresh token HMAC":     refreshTokenHMACKey,
		"access signing":         accessSigningKeyRing.Keys[accessSigningKeyRing.ActiveKeyID],
		"offline signing":        offlineSigningKeyRing.Keys[offlineSigningKeyRing.ActiveKeyID],
		"Agent control signing":  agentControlSigningKeyRing.Keys[agentControlSigningKeyRing.ActiveKeyID],
	}); err != nil {
		return Config{}, err
	}
	browserCookieName, err := required(lookup, envBrowserCookieName)
	if err != nil {
		return Config{}, err
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(browserCookieName) {
		return Config{}, fmt.Errorf("%s is invalid", envBrowserCookieName)
	}
	browserSessionTTLSeconds, err := requiredInteger(lookup, envBrowserSessionTTLSeconds, 300, 1800)
	if err != nil {
		return Config{}, err
	}
	loginIdentityLimit, err := requiredInteger(lookup, envLoginIdentityLimit, 1, 1000)
	if err != nil {
		return Config{}, err
	}
	loginIPLimit, err := requiredInteger(lookup, envLoginIPLimit, loginIdentityLimit, 10000)
	if err != nil {
		return Config{}, err
	}
	loginWindowSeconds, err := requiredInteger(lookup, envLoginWindowSeconds, 60, 86400)
	if err != nil {
		return Config{}, err
	}
	workspaceActiveOwnedLimit, err := requiredInteger(lookup, envWorkspaceActiveOwnedLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	workspaceMemberLimit, err := requiredInteger(lookup, envWorkspaceMemberLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	workspacePendingInviteLimit, err := requiredInteger(lookup, envWorkspacePendingInviteLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	workspaceCreateRateLimit, err := requiredInteger(lookup, envWorkspaceCreateRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	workspaceCreateRateWindow, err := requiredPositiveDuration(lookup, envWorkspaceCreateRateWindow)
	if err != nil {
		return Config{}, err
	}
	workspaceInviteRateLimit, err := requiredInteger(lookup, envWorkspaceInviteRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	workspaceInviteRateWindow, err := requiredPositiveDuration(lookup, envWorkspaceInviteRateWindow)
	if err != nil {
		return Config{}, err
	}
	workspaceAcceptRateLimit, err := requiredInteger(lookup, envWorkspaceAcceptRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	workspaceAcceptRateWindow, err := requiredPositiveDuration(lookup, envWorkspaceAcceptRateWindow)
	if err != nil {
		return Config{}, err
	}
	organizationOwnedLimit, err := requiredInteger(lookup, envOrganizationOwnedLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationMemberLimit, err := requiredInteger(lookup, envOrganizationMemberLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationDepartmentLimit, err := requiredInteger(lookup, envOrganizationDepartmentLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationPendingInviteLimit, err := requiredInteger(lookup, envOrganizationPendingInviteLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationCreateRateLimit, err := requiredInteger(lookup, envOrganizationCreateRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationCreateRateWindow, err := requiredPositiveDuration(lookup, envOrganizationCreateRateWindow)
	if err != nil {
		return Config{}, err
	}
	organizationInviteRateLimit, err := requiredInteger(lookup, envOrganizationInviteRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationInviteRateWindow, err := requiredPositiveDuration(lookup, envOrganizationInviteRateWindow)
	if err != nil {
		return Config{}, err
	}
	organizationAcceptRateLimit, err := requiredInteger(lookup, envOrganizationAcceptRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationAcceptRateWindow, err := requiredPositiveDuration(lookup, envOrganizationAcceptRateWindow)
	if err != nil {
		return Config{}, err
	}
	organizationMutationRateLimit, err := requiredInteger(lookup, envOrganizationMutationRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationMutationRateWindow, err := requiredPositiveDuration(lookup, envOrganizationMutationRateWindow)
	if err != nil {
		return Config{}, err
	}
	organizationHighRiskRateLimit, err := requiredInteger(lookup, envOrganizationHighRiskRateLimit, 1, 1_000_000)
	if err != nil {
		return Config{}, err
	}
	organizationHighRiskRateWindow, err := requiredPositiveDuration(lookup, envOrganizationHighRiskRateWindow)
	if err != nil {
		return Config{}, err
	}
	termsVersion, err := requiredVersion(lookup, envTermsVersion)
	if err != nil {
		return Config{}, err
	}
	privacyVersion, err := requiredVersion(lookup, envPrivacyVersion)
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
	if err := validateProductionProviders(
		environment,
		smtpHost,
		smtpFromAddress,
		smsEndpoint,
		captchaEndpoint,
	); err != nil {
		return Config{}, err
	}

	return Config{
		Environment:                    environment,
		ListenAddr:                     listenAddr,
		PublicURL:                      publicURL,
		DatabaseURL:                    databaseURL,
		RedisAddr:                      redisAddr,
		RedisUsername:                  redisUsername,
		RedisPassword:                  redisPassword,
		RedisDB:                        redisDB,
		IdentityEncryptionKeyRing:      identityEncryptionKeyRing,
		IdentityLookupKeyRing:          identityLookupKeyRing,
		VerificationCodeKeyRing:        verificationCodeKeyRing,
		VerificationReceiptKeyRing:     verificationReceiptKeyRing,
		VerificationRequestHMACKey:     verificationRequestHMACKey,
		BrowserSessionHMACKey:          browserSessionHMACKey,
		LoginRateHMACKey:               loginRateHMACKey,
		OAuthStateEncryptionKeyRing:    oauthStateEncryptionKeyRing,
		OAuthStateHMACKey:              oauthStateHMACKey,
		RefreshTokenHMACKey:            refreshTokenHMACKey,
		AccessSigningKeyRing:           accessSigningKeyRing,
		OfflineSigningKeyRing:          offlineSigningKeyRing,
		AgentControlSigningKeyRing:     agentControlSigningKeyRing,
		OfflinePolicyVersion:           offlinePolicyVersion,
		ActiveDeviceLimit:              activeDeviceLimit,
		BrowserCookieName:              browserCookieName,
		BrowserSessionTTLSeconds:       browserSessionTTLSeconds,
		LoginIdentityLimit:             int64(loginIdentityLimit),
		LoginIPLimit:                   int64(loginIPLimit),
		LoginWindowSeconds:             loginWindowSeconds,
		WorkspaceActiveOwnedLimit:      workspaceActiveOwnedLimit,
		WorkspaceMemberLimit:           workspaceMemberLimit,
		WorkspacePendingInviteLimit:    workspacePendingInviteLimit,
		WorkspaceCreateRateLimit:       int64(workspaceCreateRateLimit),
		WorkspaceCreateRateWindow:      workspaceCreateRateWindow,
		WorkspaceInviteRateLimit:       int64(workspaceInviteRateLimit),
		WorkspaceInviteRateWindow:      workspaceInviteRateWindow,
		WorkspaceAcceptRateLimit:       int64(workspaceAcceptRateLimit),
		WorkspaceAcceptRateWindow:      workspaceAcceptRateWindow,
		OrganizationOwnedLimit:         organizationOwnedLimit,
		OrganizationMemberLimit:        organizationMemberLimit,
		OrganizationDepartmentLimit:    organizationDepartmentLimit,
		OrganizationPendingInviteLimit: organizationPendingInviteLimit,
		OrganizationCreateRateLimit:    int64(organizationCreateRateLimit),
		OrganizationCreateRateWindow:   organizationCreateRateWindow,
		OrganizationInviteRateLimit:    int64(organizationInviteRateLimit),
		OrganizationInviteRateWindow:   organizationInviteRateWindow,
		OrganizationAcceptRateLimit:    int64(organizationAcceptRateLimit),
		OrganizationAcceptRateWindow:   organizationAcceptRateWindow,
		OrganizationMutationRateLimit:  int64(organizationMutationRateLimit),
		OrganizationMutationRateWindow: organizationMutationRateWindow,
		OrganizationHighRiskRateLimit:  int64(organizationHighRiskRateLimit),
		OrganizationHighRiskRateWindow: organizationHighRiskRateWindow,
		TermsVersion:                   termsVersion,
		PrivacyVersion:                 privacyVersion,
		SMTPHost:                       smtpHost,
		SMTPPort:                       smtpPort,
		SMTPUsername:                   smtpUsername,
		SMTPPassword:                   smtpPassword,
		SMTPFromAddress:                smtpFromAddress,
		SMTPFromName:                   smtpFromName,
		SMSEndpoint:                    smsEndpoint,
		SMSAPIKey:                      smsAPIKey,
		SMSSenderID:                    smsSenderID,
		CaptchaEndpoint:                captchaEndpoint,
		CaptchaSecret:                  captchaSecret,
	}, nil
}

func loadPrivateSigningKeyRing(lookup LookupEnv, activeKeyEnv, keysEnv string) (KeyRing, error) {
	keyRing, err := loadKeyRing(lookup, activeKeyEnv, keysEnv, ed25519.PrivateKeySize, true)
	if err != nil {
		return KeyRing{}, err
	}
	for keyID, material := range keyRing.Keys {
		canonical := ed25519.NewKeyFromSeed(material[:ed25519.SeedSize])
		if !bytes.Equal(material, canonical) {
			return KeyRing{}, fmt.Errorf("%s value for key %q is not a canonical Ed25519 private key", keysEnv, keyID)
		}
	}
	return keyRing, nil
}

func requireIndependentKeys(materials map[string][]byte) error {
	names := make([]string, 0, len(materials))
	for name := range materials {
		names = append(names, name)
	}
	for index, name := range names {
		for _, otherName := range names[index+1:] {
			material := materials[name]
			other := materials[otherName]
			if len(material) == len(other) && bytes.Equal(material, other) {
				return fmt.Errorf("%s and %s keys must be independent", name, otherName)
			}
		}
	}
	return nil
}

func requiredInteger(lookup LookupEnv, key string, minimum, maximum int) (int, error) {
	value, err := required(lookup, key)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, minimum, maximum)
	}
	return parsed, nil
}

func requiredPositiveDuration(lookup LookupEnv, key string) (time.Duration, error) {
	value, err := required(lookup, key)
	if err != nil {
		return 0, err
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return parsed, nil
}

func requiredVersion(lookup LookupEnv, key string) (string, error) {
	value, err := required(lookup, key)
	if err != nil {
		return "", err
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(value) {
		return "", fmt.Errorf("%s is invalid", key)
	}
	return value, nil
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

func validateProductionProviders(environment, smtpHost, smtpFromAddress, smsEndpoint, captchaEndpoint string) error {
	if environment != "production" {
		return nil
	}
	if fakeProviderHost(smtpHost) {
		return errors.New("production requires real providers instead of reserved SMTP hosts")
	}
	_, fromDomain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(smtpFromAddress)), "@")
	if !ok || fakeProviderHost(fromDomain) {
		return errors.New("production requires real providers instead of reserved sender addresses")
	}
	for _, endpoint := range []string{smsEndpoint, captchaEndpoint} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || fakeProviderHost(parsed.Hostname()) {
			return errors.New("production requires real providers on trusted HTTPS endpoints")
		}
	}
	return nil
}

func fakeProviderHost(raw string) bool {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	return host == "invalid" || strings.HasSuffix(host, ".invalid")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
