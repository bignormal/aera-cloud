package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
)

type recordingListenerOpener struct {
	mu        sync.Mutex
	calls     []string
	listeners []*trackingListener
	opened    chan struct{}
	failAt    int
}

func newRecordingListenerOpener() *recordingListenerOpener {
	return &recordingListenerOpener{opened: make(chan struct{}, 4)}
}

func (o *recordingListenerOpener) Open(network, address string) (net.Listener, error) {
	o.mu.Lock()
	call := len(o.calls) + 1
	o.calls = append(o.calls, address)
	if o.failAt == call {
		o.mu.Unlock()
		o.opened <- struct{}{}
		return nil, errors.New("raw listener failure canary")
	}
	o.mu.Unlock()

	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	tracked := &trackingListener{Listener: listener}
	o.mu.Lock()
	o.listeners = append(o.listeners, tracked)
	o.mu.Unlock()
	o.opened <- struct{}{}
	return tracked, nil
}

func (o *recordingListenerOpener) snapshot() ([]string, []*trackingListener) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.calls...), append([]*trackingListener(nil), o.listeners...)
}

type trackingListener struct {
	net.Listener
	closed atomic.Bool
}

func (l *trackingListener) Close() error {
	l.closed.Store(true)
	return l.Listener.Close()
}

type failingListener struct {
	closed atomic.Bool
}

func (l *failingListener) Accept() (net.Conn, error) {
	return nil, errors.New("raw accept failure canary")
}

func (l *failingListener) Close() error {
	l.closed.Store(true)
	return nil
}

func (l *failingListener) Addr() net.Addr {
	return staticAddr("127.0.0.1:1")
}

type staticAddr string

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return string(a) }

func TestRunHTTPServersOpensOnlyConfiguredListenersAndClosesThemOnCancellation(t *testing.T) {
	tests := []struct {
		name            string
		enabled         bool
		wantOpenCount   int
		internalHandler http.Handler
		internalTLS     *tls.Config
	}{
		{name: "disabled opens only public", wantOpenCount: 1},
		{
			name: "enabled opens public and internal", enabled: true, wantOpenCount: 2,
			internalHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			internalTLS:     &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opener := newRecordingListenerOpener()
			cfg := config.Config{
				ListenAddr: "127.0.0.1:0",
				InternalAdmin: config.InternalAdminConfig{
					Enabled: test.enabled, ListenAddr: "127.0.0.1:0",
				},
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- runHTTPServers(
					ctx, cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
					test.internalHandler, test.internalTLS, opener.Open,
				)
			}()

			waitForListenerOpens(t, opener.opened, test.wantOpenCount)
			calls, _ := opener.snapshot()
			if len(calls) != test.wantOpenCount {
				cancel()
				t.Fatalf("listener calls = %v", calls)
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("runHTTPServers() error = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("runHTTPServers() did not stop")
			}
			_, listeners := opener.snapshot()
			for index, listener := range listeners {
				if !listener.closed.Load() {
					t.Fatalf("listener %d remained open", index)
				}
			}
		})
	}
}

func TestRunHTTPServersRejectsMissingInternalComponentsBeforeOpeningPublicListener(t *testing.T) {
	opener := newRecordingListenerOpener()
	cfg := config.Config{
		ListenAddr:    "127.0.0.1:0",
		InternalAdmin: config.InternalAdminConfig{Enabled: true, ListenAddr: "127.0.0.1:0"},
	}
	err := runHTTPServers(
		context.Background(), cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		nil, nil, opener.Open,
	)
	if err == nil {
		t.Fatal("runHTTPServers() succeeded without Internal Admin components")
	}
	calls, _ := opener.snapshot()
	if len(calls) != 0 {
		t.Fatalf("listeners opened before Internal Admin validation: %v", calls)
	}
}

func TestRunHTTPServersClosesPublicListenerWhenInternalBindFails(t *testing.T) {
	opener := newRecordingListenerOpener()
	opener.failAt = 2
	cfg := config.Config{
		ListenAddr:    "127.0.0.1:0",
		InternalAdmin: config.InternalAdminConfig{Enabled: true, ListenAddr: "127.0.0.1:0"},
	}
	var ready atomic.Bool
	err := runHTTPServersWithReady(
		context.Background(), cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, opener.Open,
		func() { ready.Store(true) },
	)
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("runHTTPServers() error = %v", err)
	}
	calls, listeners := opener.snapshot()
	if len(calls) != 2 || len(listeners) != 1 || !listeners[0].closed.Load() {
		t.Fatalf("calls/listeners/closed = %v / %d / %t", calls, len(listeners), len(listeners) == 1 && listeners[0].closed.Load())
	}
	if ready.Load() {
		t.Fatal("ready callback ran after internal bind failure")
	}
}

func TestRunHTTPServersCancelsTheOtherListenerAfterFatalServeFailure(t *testing.T) {
	failed := &failingListener{}
	secondRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second := &trackingListener{Listener: secondRaw}
	call := 0
	opener := func(string, string) (net.Listener, error) {
		call++
		if call == 1 {
			return failed, nil
		}
		return second, nil
	}
	cfg := config.Config{
		ListenAddr:    "127.0.0.1:0",
		InternalAdmin: config.InternalAdminConfig{Enabled: true, ListenAddr: "127.0.0.1:0"},
	}
	err = runHTTPServers(
		context.Background(), cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, opener,
	)
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("runHTTPServers() error = %v", err)
	}
	if !failed.closed.Load() || !second.closed.Load() {
		t.Fatalf("listeners closed = failed:%t second:%t", failed.closed.Load(), second.closed.Load())
	}
}

func TestBuildInternalAdminRejectsDisabledOrMissingRuntimeDependencies(t *testing.T) {
	if _, _, err := buildInternalAdmin(config.Config{}, nil, nil); err == nil {
		t.Fatal("buildInternalAdmin() accepted disabled configuration")
	}
	if _, _, err := buildInternalAdmin(config.Config{
		InternalAdmin: config.InternalAdminConfig{Enabled: true},
	}, nil, nil); err == nil {
		t.Fatal("buildInternalAdmin() accepted missing stores")
	}
}

func TestBuildInternalAdminServesAuthenticatedTLSHealth(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()
	redisStore, err := store.OpenRedis(ctx, store.RedisOptions{
		Addr: services.RedisAddr, Username: services.RedisUsername,
		Password: services.RedisPassword, DB: services.RedisDB,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = redisStore.Close() }()

	certificates := newInternalAdminCertificateFixture(t)
	cfg, err := config.Load(internalAdminTestLookup(integrationLookup(services), certificates))
	if err != nil {
		t.Fatal(err)
	}
	handler, serverTLS, err := buildInternalAdmin(cfg, postgres, redisStore)
	if err != nil {
		t.Fatalf("buildInternalAdmin() error = %v", err)
	}
	officialWithoutSharedService := cfg
	officialWithoutSharedService.OfficialAgent.Enabled = true
	if _, _, err := buildInternalAdmin(officialWithoutSharedService, postgres, redisStore); err == nil {
		t.Fatal("buildInternalAdmin() accepted enabled Official Agents without the shared PlatformService")
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS.Clone()
	server.StartTLS()
	defer server.Close()

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: certificates.serverRoots, ServerName: "internal.aera.test",
			Certificates: []tls.Certificate{certificates.clientCertificate},
		}},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/internal/admin/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+signInternalAdminTestToken(t, certificates.jwtPrivateKey, time.Now().UTC()))
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("internal health request error = %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("internal health status/TLS = %d / %+v", response.StatusCode, response.TLS)
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body["status"] != "ok" || len(body) != 1 {
		t.Fatalf("internal health body = %v / %v", body, err)
	}
}

func waitForListenerOpens(t *testing.T, opened <-chan struct{}, count int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for index := 0; index < count; index++ {
		select {
		case <-opened:
		case <-deadline.C:
			t.Fatalf("only %d of %d listeners opened", index, count)
		}
	}
}

type internalAdminCertificateFixture struct {
	serverCertFile    string
	serverKeyFile     string
	clientCAFile      string
	jwtPublicKeyFile  string
	serverRoots       *x509.CertPool
	clientCertificate tls.Certificate
	jwtPrivateKey     ed25519.PrivateKey
}

func newInternalAdminCertificateFixture(t *testing.T) internalAdminCertificateFixture {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Aera Internal Admin Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "internal.aera.test"},
		DNSNames: []string{"internal.aera.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, serverPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}

	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "aera-admin-e2e"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCertificate, clientPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		encodePKCS8PrivateKey(t, clientPrivate),
	)
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	serverCertFile := writeInternalAdminTestFile(t, directory, "server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}))
	serverKeyFile := writeInternalAdminTestFile(t, directory, "server.key", encodePKCS8PrivateKey(t, serverPrivate))
	clientCAFile := writeInternalAdminTestFile(t, directory, "client-ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	jwtPublic, jwtPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwtPublicDER, err := x509.MarshalPKIXPublicKey(jwtPublic)
	if err != nil {
		t.Fatal(err)
	}
	jwtPublicKeyFile := writeInternalAdminTestFile(t, directory, "jwt-public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: jwtPublicDER}))
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return internalAdminCertificateFixture{
		serverCertFile: serverCertFile, serverKeyFile: serverKeyFile, clientCAFile: clientCAFile,
		jwtPublicKeyFile: jwtPublicKeyFile, serverRoots: roots,
		clientCertificate: clientCertificate, jwtPrivateKey: jwtPrivate,
	}
}

func internalAdminTestLookup(base config.LookupEnv, certificates internalAdminCertificateFixture) config.LookupEnv {
	values := map[string]string{
		"AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED":             "true",
		"AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR":         "127.0.0.1:18443",
		"AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE":    certificates.serverCertFile,
		"AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE":     certificates.serverKeyFile,
		"AGENTERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE":      certificates.clientCAFile,
		"AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE": certificates.jwtPublicKeyFile,
		"AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_ISSUER":          "aera-admin",
		"AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_SUBJECT":         "aera-admin-e2e",
		"AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_ACTIVE_KEY_ID":  "admin-e2e-v1",
		"AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_KEYS": fmt.Sprintf(
			`{"admin-e2e-v1":"%s"}`,
			base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{31}, 32)),
		),
	}
	return func(key string) (string, bool) {
		if value, ok := values[key]; ok {
			return value, true
		}
		return base(key)
	}
}

func signInternalAdminTestToken(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": "aera-admin", "sub": "aera-admin-e2e", "aud": "aera-cloud-admin",
		"scope": []string{"users:read"}, "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(),
		"exp": now.Add(4 * time.Minute).Unix(), "jti": "019f0000000070008000000000000099",
	})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(unsigned)))
}

func encodePKCS8PrivateKey(t *testing.T, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
}

func writeInternalAdminTestFile(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
