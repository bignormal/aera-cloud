package config

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	envInternalAdminEnabled          = "AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED"
	envInternalAdminListenAddr       = "AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR"
	envInternalAdminServerCertFile   = "AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE"
	envInternalAdminServerKeyFile    = "AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE"
	envInternalAdminClientCAFile     = "AGENTERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE"
	envInternalAdminJWTPublicKeyFile = "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE"
	envInternalAdminJWTIssuer        = "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_ISSUER"
	envInternalAdminJWTSubject       = "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_SUBJECT"
	envInternalAdminHMACActiveKeyID  = "AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_ACTIVE_KEY_ID"
	envInternalAdminHMACKeys         = "AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_KEYS"
)

var internalAdminServiceIdentityPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)

type InternalAdminConfig struct {
	Enabled          bool
	ListenAddr       string
	ServerCertFile   string
	ServerKeyFile    string
	ClientCAFile     string
	JWTPublicKeyFile string
	JWTIssuer        string
	JWTSubject       string
	HMACKeys         KeyRing
}

func loadInternalAdmin(lookup LookupEnv, publicListenAddr string) (InternalAdminConfig, error) {
	raw, ok := lookup(envInternalAdminEnabled)
	enabled := strings.TrimSpace(raw)
	if !ok || enabled == "" || strings.EqualFold(enabled, "false") {
		return InternalAdminConfig{}, nil
	}
	if !strings.EqualFold(enabled, "true") {
		return InternalAdminConfig{}, fmt.Errorf("%s must be true or false", envInternalAdminEnabled)
	}

	listenAddr, err := required(lookup, envInternalAdminListenAddr)
	if err != nil {
		return InternalAdminConfig{}, err
	}
	if listenAddr == publicListenAddr {
		return InternalAdminConfig{}, fmt.Errorf("%s must differ from %s", envInternalAdminListenAddr, envListenAddr)
	}

	serverCertFile, err := required(lookup, envInternalAdminServerCertFile)
	if err != nil {
		return InternalAdminConfig{}, err
	}
	serverKeyFile, err := required(lookup, envInternalAdminServerKeyFile)
	if err != nil {
		return InternalAdminConfig{}, err
	}
	clientCAFile, err := required(lookup, envInternalAdminClientCAFile)
	if err != nil {
		return InternalAdminConfig{}, err
	}
	jwtPublicKeyFile, err := required(lookup, envInternalAdminJWTPublicKeyFile)
	if err != nil {
		return InternalAdminConfig{}, err
	}
	issuer, err := required(lookup, envInternalAdminJWTIssuer)
	if err != nil {
		return InternalAdminConfig{}, err
	}
	subject, err := required(lookup, envInternalAdminJWTSubject)
	if err != nil {
		return InternalAdminConfig{}, err
	}
	if !internalAdminServiceIdentityPattern.MatchString(issuer) {
		return InternalAdminConfig{}, fmt.Errorf("%s is invalid", envInternalAdminJWTIssuer)
	}
	if !internalAdminServiceIdentityPattern.MatchString(subject) {
		return InternalAdminConfig{}, fmt.Errorf("%s is invalid", envInternalAdminJWTSubject)
	}

	hmacKeys, err := loadKeyRing(
		lookup,
		envInternalAdminHMACActiveKeyID,
		envInternalAdminHMACKeys,
		32,
		true,
	)
	if err != nil {
		return InternalAdminConfig{}, err
	}

	return InternalAdminConfig{
		Enabled:          true,
		ListenAddr:       listenAddr,
		ServerCertFile:   serverCertFile,
		ServerKeyFile:    serverKeyFile,
		ClientCAFile:     clientCAFile,
		JWTPublicKeyFile: jwtPublicKeyFile,
		JWTIssuer:        issuer,
		JWTSubject:       subject,
		HMACKeys:         hmacKeys,
	}, nil
}
