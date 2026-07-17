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
	DefaultCookieName  = "agentera_browser_session"
	CSRFHeader         = "X-CSRF-Token"
	redisSessionPrefix = "aera-cloud:browser-session:"
	minimumSessionTTL  = 5 * time.Minute
	maximumSessionTTL  = 30 * time.Minute
	secretLength       = 32
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
	Redis         redis.UniversalClient
	HMACKey       []byte
	TTL           time.Duration
	CookieName    string
	SecureCookies bool
	Clock         func() time.Time
}

type Manager struct {
	redis         redis.UniversalClient
	hmacKey       []byte
	ttl           time.Duration
	cookieName    string
	secureCookies bool
	clock         func() time.Time
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
	if config.Redis == nil || len(config.HMACKey) < secretLength ||
		config.TTL < minimumSessionTTL || config.TTL > maximumSessionTTL || !cookieNamePattern.MatchString(cookieName) {
		return nil, errors.New("browser session configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Manager{
		redis: config.Redis, hmacKey: append([]byte(nil), config.HMACKey...), ttl: config.TTL,
		cookieName: cookieName, secureCookies: config.SecureCookies, clock: clock,
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
	http.SetCookie(response, m.cookie(base64.RawURLEncoding.EncodeToString(sessionSecret), now.Add(m.ttl), int(m.ttl/time.Second)))
	return base64.RawURLEncoding.EncodeToString(csrfSecret), nil
}

func (m *Manager) Read(ctx context.Context, request *http.Request) (Session, error) {
	if m == nil || request == nil {
		return Session{}, ErrUnauthenticated
	}
	cookie, err := request.Cookie(m.cookieName)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	secret, ok := decodeSecret(cookie.Value)
	if !ok {
		return Session{}, ErrUnauthenticated
	}
	key := m.redisKey(secret)
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
	if request == nil {
		return nil
	}
	cookie, err := request.Cookie(m.cookieName)
	if err != nil {
		return nil
	}
	secret, ok := decodeSecret(cookie.Value)
	if !ok {
		return nil
	}
	if err := m.redis.Del(ctx, m.redisKey(secret)).Err(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (m *Manager) redisKey(secret []byte) string {
	return redisSessionPrefix + base64.RawURLEncoding.EncodeToString(m.digest("session", secret))
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

func decodeSecret(encoded string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != secretLength {
		return nil, false
	}
	return decoded, true
}
