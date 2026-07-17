package browser

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestManagerStartsReadsAndEndsOpaqueHostOnlySession(t *testing.T) {
	fixture := newBrowserFixture(t, true)
	principal := Principal{UserID: uuid.New(), PersonalSpaceID: uuid.New(), Nickname: "Alice"}
	response := httptest.NewRecorder()

	csrfToken, err := fixture.manager.Start(fixture.ctx, response, principal)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if csrfToken == "" {
		t.Fatal("Start() returned an empty CSRF token")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != DefaultCookieName || cookie.Domain != "" || cookie.Path != "/" ||
		!cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge <= 0 {
		t.Fatalf("session cookie = %+v", cookie)
	}
	if strings.Contains(cookie.Value, principal.UserID.String()) || strings.Contains(cookie.Value, principal.Nickname) {
		t.Fatal("session cookie exposed principal data")
	}

	keys, err := fixture.redis.Keys(fixture.ctx, redisSessionPrefix+"*").Result()
	if err != nil || len(keys) != 1 {
		t.Fatalf("Redis session keys = %+v, error:%v", keys, err)
	}
	if strings.Contains(keys[0], cookie.Value) {
		t.Fatal("Redis key contains the raw browser session token")
	}

	request := httptest.NewRequest(http.MethodGet, "https://app.agentera.example/account", nil)
	request.AddCookie(cookie)
	session, err := fixture.manager.Read(fixture.ctx, request)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if session.Principal != principal {
		t.Fatalf("Read() principal = %+v", session.Principal)
	}

	logoutResponse := httptest.NewRecorder()
	if err := fixture.manager.End(fixture.ctx, logoutResponse, request); err != nil {
		t.Fatalf("End() error = %v", err)
	}
	deletedCookies := logoutResponse.Result().Cookies()
	if len(deletedCookies) != 1 || deletedCookies[0].MaxAge >= 0 || !deletedCookies[0].HttpOnly || !deletedCookies[0].Secure {
		t.Fatalf("logout cookie = %+v", deletedCookies)
	}
	if _, err := fixture.manager.Read(fixture.ctx, request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Read() after End() error = %v", err)
	}
}

func TestManagerRequiresMatchingCSRFToken(t *testing.T) {
	fixture := newBrowserFixture(t, false)
	response := httptest.NewRecorder()
	csrfToken, err := fixture.manager.Start(fixture.ctx, response, Principal{UserID: uuid.New(), PersonalSpaceID: uuid.New()})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	cookie := response.Result().Cookies()[0]
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8086/api/v1/browser/logout", nil)
	request.AddCookie(cookie)
	session, err := fixture.manager.Read(fixture.ctx, request)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if err := fixture.manager.RequireCSRF(request, session); !errors.Is(err, ErrCSRF) {
		t.Fatalf("RequireCSRF(missing) error = %v", err)
	}
	request.Header.Set(CSRFHeader, "wrong-token")
	if err := fixture.manager.RequireCSRF(request, session); !errors.Is(err, ErrCSRF) {
		t.Fatalf("RequireCSRF(wrong) error = %v", err)
	}
	request.Header.Set(CSRFHeader, csrfToken)
	if err := fixture.manager.RequireCSRF(request, session); err != nil {
		t.Fatalf("RequireCSRF(correct) error = %v", err)
	}
	if response.Result().Cookies()[0].Secure {
		t.Fatal("loopback development cookie unexpectedly requires HTTPS")
	}
}

func TestManagerRejectsExpiredAndMalformedSessions(t *testing.T) {
	fixture := newBrowserFixture(t, false)
	response := httptest.NewRecorder()
	_, err := fixture.manager.Start(fixture.ctx, response, Principal{UserID: uuid.New(), PersonalSpaceID: uuid.New()})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	cookie := response.Result().Cookies()[0]
	fixture.now = fixture.now.Add(16 * time.Minute)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8086/account", nil)
	request.AddCookie(cookie)
	if _, err := fixture.manager.Read(fixture.ctx, request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Read(expired) error = %v", err)
	}

	malformed := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8086/account", nil)
	malformed.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: "not-a-session-token"})
	if _, err := fixture.manager.Read(fixture.ctx, malformed); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Read(malformed) error = %v", err)
	}

	fixture.now = fixture.now.Add(-16 * time.Minute)
	alias := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8086/account", nil)
	alias.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: testkit.NonCanonicalBase64URLAlias(t, cookie.Value),
	})
	if _, err := fixture.manager.Read(fixture.ctx, alias); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Read(noncanonical alias) error = %v", err)
	}
}

func TestNewManagerRejectsMissingOrWeakSecrets(t *testing.T) {
	if _, err := NewManager(ManagerConfig{}); err == nil {
		t.Fatal("NewManager() accepted missing dependencies")
	}
	if _, err := NewManager(ManagerConfig{
		Redis: &redis.Client{}, HMACKey: bytes.Repeat([]byte{1}, 16), TTL: 15 * time.Minute,
	}); err == nil {
		t.Fatal("NewManager() accepted a weak HMAC key")
	}
}

type browserFixture struct {
	ctx     context.Context
	redis   *redis.Client
	manager *Manager
	now     time.Time
}

func newBrowserFixture(t *testing.T, secureCookies bool) *browserFixture {
	t.Helper()
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("FlushDB() error = %v", err)
	}
	fixture := &browserFixture{ctx: ctx, redis: client, now: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)}
	manager, err := NewManager(ManagerConfig{
		Redis: client, HMACKey: bytes.Repeat([]byte{7}, 32), TTL: 15 * time.Minute,
		SecureCookies: secureCookies, Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	fixture.manager = manager
	return fixture
}
