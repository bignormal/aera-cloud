package browser

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	DefaultCookieName           = "agentera_browser_session"
	DefaultPersistentCookieName = DefaultCookieName + "_persistent"
	CSRFHeader                  = "X-CSRF-Token"
	redisSessionPrefix          = "aera-cloud:browser-session:"
	redisPersistentPrefix       = "aera-cloud:browser-persistent-session:"
	minimumSessionTTL           = 5 * time.Minute
	maximumSessionTTL           = 30 * time.Minute
	defaultPersistentSessionTTL = 30 * 24 * time.Hour
	minimumPersistentSessionTTL = time.Hour
	maximumPersistentSessionTTL = 90 * 24 * time.Hour
	secretLength                = 32
)

var (
	ErrUnauthenticated  = errors.New("browser session is unauthenticated")
	ErrCSRF             = errors.New("browser session CSRF validation failed")
	ErrStoreUnavailable = errors.New("browser session store is unavailable")
	cookieNamePattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

type Principal struct {
	UserID          uuid.UUID
	PersonalSpaceID uuid.UUID
	Nickname        string
}

type Session struct {
	Principal Principal
	csrfHMAC  []byte
}

type ManagerConfig struct {
	Redis                redis.UniversalClient
	HMACKey              []byte
	TTL                  time.Duration
	CookieName           string
	PersistentCookieName string
	PersistentTTL        time.Duration
	SecureCookies        bool
	Clock                func() time.Time
}

type Manager struct {
	redis                redis.UniversalClient
	hmacKey              []byte
	ttl                  time.Duration
	cookieName           string
	persistentCookieName string
	persistentTTL        time.Duration
	secureCookies        bool
	clock                func() time.Time
}

type storedSession struct {
	Version         int       `json:"v"`
	UserID          uuid.UUID `json:"user_id"`
	PersonalSpaceID uuid.UUID `json:"personal_space_id"`
	Nickname        string    `json:"nickname,omitempty"`
	CSRFHMAC        []byte    `json:"csrf_hmac"`
	ExpiresAtUnix   int64     `json:"expires_at"`
}

func NewManager(config ManagerConfig) (*Manager, error) {
	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}
	persistentCookieName := config.PersistentCookieName
	if persistentCookieName == "" {
		if cookieName == DefaultCookieName {
			persistentCookieName = DefaultPersistentCookieName
		} else {
			persistentCookieName = cookieName + "_persistent"
		}
	}
	persistentTTL := config.PersistentTTL
	if persistentTTL == 0 {
		persistentTTL = defaultPersistentSessionTTL
	}
	if config.Redis == nil || len(config.HMACKey) < secretLength ||
		config.TTL < minimumSessionTTL || config.TTL > maximumSessionTTL ||
		persistentTTL < minimumPersistentSessionTTL || persistentTTL > maximumPersistentSessionTTL ||
		!cookieNamePattern.MatchString(cookieName) || !cookieNamePattern.MatchString(persistentCookieName) ||
		cookieName == persistentCookieName {
		return nil, errors.New("browser session configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Manager{
		redis:                config.Redis,
		hmacKey:              append([]byte(nil), config.HMACKey...),
		ttl:                  config.TTL,
		cookieName:           cookieName,
		persistentCookieName: persistentCookieName,
		persistentTTL:        persistentTTL,
		secureCookies:        config.SecureCookies,
		clock:                clock,
	}, nil
}

func (m *Manager) Start(ctx context.Context, response http.ResponseWriter, principal Principal) (string, error) {
	if m == nil || response == nil || principal.UserID == uuid.Nil || principal.PersonalSpaceID == uuid.Nil {
		return "", errors.New("browser session principal is invalid")
	}
	sessionSecret, err := secure.RandomBytes(secretLength)
	if err != nil {
		return "", errors.New("browser session secret could not be generated")
	}
	persistentSecret, err := secure.RandomBytes(secretLength)
	if err != nil {
		return "", errors.New("persistent browser session secret could not be generated")
	}
	csrfSecret, err := secure.RandomBytes(secretLength)
	if err != nil {
		return "", errors.New("browser CSRF secret could not be generated")
	}
	now := m.clock().UTC()
	record := storedSession{
		Version: 1, UserID: principal.UserID, PersonalSpaceID: principal.PersonalSpaceID, Nickname: principal.Nickname,
		CSRFHMAC: m.digest("csrf", csrfSecret), ExpiresAtUnix: now.Add(m.ttl).Unix(),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", errors.New("browser session could not be encoded")
	}
	if err := m.redis.Set(ctx, m.redisKey(sessionSecret), encoded, m.ttl).Err(); err != nil {
		return "", ErrStoreUnavailable
	}
	persistentRecord := record
	persistentRecord.ExpiresAtUnix = now.Add(m.persistentTTL).Unix()
	persistentEncoded, err := json.Marshal(persistentRecord)
	if err != nil {
		_ = m.redis.Del(ctx, m.redisKey(sessionSecret)).Err()
		return "", errors.New("persistent browser session could not be encoded")
	}
	if err := m.redis.Set(
		ctx,
		m.persistentRedisKey(persistentSecret),
		persistentEncoded,
		m.persistentTTL,
	).Err(); err != nil {
		_ = m.redis.Del(ctx, m.redisKey(sessionSecret)).Err()
		return "", ErrStoreUnavailable
	}
	http.SetCookie(response, m.cookie(base64.RawURLEncoding.EncodeToString(sessionSecret), now.Add(m.ttl), int(m.ttl/time.Second)))
	http.SetCookie(response, m.persistentCookie(
		base64.RawURLEncoding.EncodeToString(persistentSecret),
		now.Add(m.persistentTTL),
		int(m.persistentTTL/time.Second),
	))
	return base64.RawURLEncoding.EncodeToString(csrfSecret), nil
}

func (m *Manager) Read(ctx context.Context, request *http.Request) (Session, error) {
	if m == nil || request == nil {
		return Session{}, ErrUnauthenticated
	}
	if cookie, err := request.Cookie(m.cookieName); err == nil {
		if secret, ok := decodeSecret(cookie.Value); ok {
			session, readErr := m.readStoredSession(ctx, m.redisKey(secret))
			if readErr == nil {
				return session, nil
			}
			if !errors.Is(readErr, ErrUnauthenticated) {
				return Session{}, readErr
			}
		}
	}
	cookie, err := request.Cookie(m.persistentCookieName)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	secret, ok := decodeSecret(cookie.Value)
	if !ok {
		return Session{}, ErrUnauthenticated
	}
	return m.readStoredSession(ctx, m.persistentRedisKey(secret))
}

func (m *Manager) RequireCSRF(request *http.Request, session Session) error {
	if m == nil || request == nil || len(session.csrfHMAC) != sha256.Size {
		return ErrCSRF
	}
	secret, ok := decodeSecret(request.Header.Get(CSRFHeader))
	if !ok {
		return ErrCSRF
	}
	candidate := m.digest("csrf", secret)
	if subtle.ConstantTimeCompare(candidate, session.csrfHMAC) != 1 {
		return ErrCSRF
	}
	return nil
}

func (m *Manager) End(ctx context.Context, response http.ResponseWriter, request *http.Request) error {
	if m == nil || response == nil {
		return ErrStoreUnavailable
	}
	http.SetCookie(response, m.cookie("", time.Unix(1, 0).UTC(), -1))
	http.SetCookie(response, m.persistentCookie("", time.Unix(1, 0).UTC(), -1))
	if request == nil {
		return nil
	}
	var keys []string
	if cookie, err := request.Cookie(m.cookieName); err == nil {
		if secret, ok := decodeSecret(cookie.Value); ok {
			keys = append(keys, m.redisKey(secret))
		}
	}
	if cookie, err := request.Cookie(m.persistentCookieName); err == nil {
		if secret, ok := decodeSecret(cookie.Value); ok {
			keys = append(keys, m.persistentRedisKey(secret))
		}
	}
	if len(keys) == 0 {
		return nil
	}
	if err := m.redis.Del(ctx, keys...).Err(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (m *Manager) redisKey(secret []byte) string {
	return redisSessionPrefix + base64.RawURLEncoding.EncodeToString(m.digest("session", secret))
}

func (m *Manager) persistentRedisKey(secret []byte) string {
	return redisPersistentPrefix + base64.RawURLEncoding.EncodeToString(m.digest("persistent-session", secret))
}

func (m *Manager) readStoredSession(ctx context.Context, key string) (Session, error) {
	encoded, err := m.redis.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrUnauthenticated
	}
	if err != nil {
		return Session{}, ErrStoreUnavailable
	}
	var record storedSession
	if json.Unmarshal(encoded, &record) != nil || record.Version != 1 || record.UserID == uuid.Nil ||
		record.PersonalSpaceID == uuid.Nil || len(record.CSRFHMAC) != sha256.Size {
		_ = m.redis.Del(ctx, key).Err()
		return Session{}, ErrUnauthenticated
	}
	if !m.clock().UTC().Before(time.Unix(record.ExpiresAtUnix, 0).UTC()) {
		_ = m.redis.Del(ctx, key).Err()
		return Session{}, ErrUnauthenticated
	}
	return Session{
		Principal: Principal{UserID: record.UserID, PersonalSpaceID: record.PersonalSpaceID, Nickname: record.Nickname},
		csrfHMAC:  append([]byte(nil), record.CSRFHMAC...),
	}, nil
}

func (m *Manager) digest(domain string, value []byte) []byte {
	mac := hmac.New(sha256.New, m.hmacKey)
	_, _ = mac.Write([]byte("agentera.browser." + domain + ".v1\x00"))
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}

func (m *Manager) cookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: m.cookieName, Value: value, Path: "/", Expires: expires,
		MaxAge: maxAge, HttpOnly: true, Secure: m.secureCookies, SameSite: http.SameSiteLaxMode,
	}
}

func (m *Manager) persistentCookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: m.persistentCookieName, Value: value, Path: "/", Expires: expires,
		MaxAge: maxAge, HttpOnly: true, Secure: m.secureCookies, SameSite: http.SameSiteLaxMode,
	}
}

func decodeSecret(encoded string) ([]byte, bool) {
	decoded, ok := secure.DecodeCanonicalBase64URL(encoded)
	if !ok || len(decoded) != secretLength {
		return nil, false
	}
	return decoded, true
}
