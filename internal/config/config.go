package config

import (
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
)

type LookupEnv func(string) (string, bool)

type Config struct {
	Environment   string
	ListenAddr    string
	PublicURL     string
	DatabaseURL   string
	RedisAddr     string
	RedisUsername string
	RedisPassword string
	RedisDB       int
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

	return Config{
		Environment:   environment,
		ListenAddr:    listenAddr,
		PublicURL:     publicURL,
		DatabaseURL:   databaseURL,
		RedisAddr:     redisAddr,
		RedisUsername: redisUsername,
		RedisPassword: redisPassword,
		RedisDB:       redisDB,
	}, nil
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
