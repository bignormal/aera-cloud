package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	envEncryptedBackupEnabled   = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED"
	envEncryptedBackupEndpoint  = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENDPOINT"
	envEncryptedBackupBucket    = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_BUCKET"
	envEncryptedBackupRegion    = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_REGION"
	envEncryptedBackupAccessKey = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ACCESS_KEY"
	envEncryptedBackupSecretKey = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_SECRET_KEY"
	envEncryptedBackupUseTLS    = "AGENTERA_CLOUD_ENCRYPTED_BACKUP_USE_TLS"

	encryptedBackupMaxBytes            int64 = 1 << 30
	encryptedBackupMaxPerLineage             = 3
	encryptedBackupMaxAccountBytes     int64 = 5 << 30
	encryptedBackupIncompleteUploadTTL       = 24 * time.Hour
)

var (
	encryptedBackupBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	encryptedBackupRegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	privateServiceHostPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

type EncryptedBackupConfig struct {
	Enabled              bool
	Endpoint             string
	Bucket               string
	Region               string
	AccessKey            string
	SecretKey            string
	UseTLS               bool
	MaxBackupBytes       int64
	MaxBackupsPerLineage int
	MaxAccountBytes      int64
	IncompleteUploadTTL  time.Duration
}

func loadEncryptedBackup(lookup LookupEnv, environment string) (EncryptedBackupConfig, error) {
	defaults := EncryptedBackupConfig{
		MaxBackupBytes:       encryptedBackupMaxBytes,
		MaxBackupsPerLineage: encryptedBackupMaxPerLineage,
		MaxAccountBytes:      encryptedBackupMaxAccountBytes,
		IncompleteUploadTTL:  encryptedBackupIncompleteUploadTTL,
	}
	raw, ok := lookup(envEncryptedBackupEnabled)
	enabled := strings.TrimSpace(raw)
	if !ok || enabled == "" || strings.EqualFold(enabled, "false") {
		return defaults, nil
	}
	if !strings.EqualFold(enabled, "true") {
		return EncryptedBackupConfig{}, fmt.Errorf("%s must be true or false", envEncryptedBackupEnabled)
	}

	endpoint, err := required(lookup, envEncryptedBackupEndpoint)
	if err != nil {
		return EncryptedBackupConfig{}, err
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return EncryptedBackupConfig{}, fmt.Errorf("%s must be a host and port without a scheme or path", envEncryptedBackupEndpoint)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return EncryptedBackupConfig{}, fmt.Errorf("%s must include a valid port", envEncryptedBackupEndpoint)
	}

	bucket, err := required(lookup, envEncryptedBackupBucket)
	if err != nil {
		return EncryptedBackupConfig{}, err
	}
	if !encryptedBackupBucketPattern.MatchString(bucket) || strings.Contains(bucket, "..") {
		return EncryptedBackupConfig{}, fmt.Errorf("%s is invalid", envEncryptedBackupBucket)
	}
	region, err := required(lookup, envEncryptedBackupRegion)
	if err != nil {
		return EncryptedBackupConfig{}, err
	}
	if !encryptedBackupRegionPattern.MatchString(region) {
		return EncryptedBackupConfig{}, fmt.Errorf("%s is invalid", envEncryptedBackupRegion)
	}
	accessKey, err := required(lookup, envEncryptedBackupAccessKey)
	if err != nil {
		return EncryptedBackupConfig{}, err
	}
	secretKey, err := required(lookup, envEncryptedBackupSecretKey)
	if err != nil {
		return EncryptedBackupConfig{}, err
	}
	useTLSText, err := required(lookup, envEncryptedBackupUseTLS)
	if err != nil {
		return EncryptedBackupConfig{}, err
	}
	useTLS, err := strconv.ParseBool(strings.ToLower(useTLSText))
	if err != nil {
		return EncryptedBackupConfig{}, fmt.Errorf("%s must be true or false", envEncryptedBackupUseTLS)
	}
	if environment == "production" && !useTLS && !isLoopbackHost(host) {
		return EncryptedBackupConfig{}, fmt.Errorf("%s cannot use a plaintext non-loopback endpoint in production", envEncryptedBackupEndpoint)
	}
	if IsInternalBeta(environment) && !useTLS &&
		!isLoopbackHost(host) && !privateServiceHostPattern.MatchString(host) {
		return EncryptedBackupConfig{}, fmt.Errorf(
			"%s plaintext internal_beta endpoints must use a private service host",
			envEncryptedBackupEndpoint,
		)
	}

	defaults.Enabled = true
	defaults.Endpoint = endpoint
	defaults.Bucket = bucket
	defaults.Region = region
	defaults.AccessKey = accessKey
	defaults.SecretKey = secretKey
	defaults.UseTLS = useTLS
	return defaults, nil
}
