package adminapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadEd25519PublicKeyAcceptsOnePKIXKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTestPEM(t, "service-jwt.pub", &pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	loaded, err := LoadEd25519PublicKey(path)
	if err != nil {
		t.Fatalf("LoadEd25519PublicKey() error = %v", err)
	}
	if !publicKey.Equal(loaded) {
		t.Fatal("loaded public key does not match")
	}
	loaded[0] ^= 0xff
	if publicKey[0] == loaded[0] {
		t.Fatal("public key was not copied")
	}
}

func TestLoadEd25519PublicKeyRejectsOtherPEMShapes(t *testing.T) {
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPublicDER, _ := x509.MarshalPKIXPublicKey(edPublic)
	edPrivateDER, _ := x509.MarshalPKCS8PrivateKey(edPrivate)
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPublicDER, _ := x509.MarshalPKIXPublicKey(&rsaPrivate.PublicKey)
	validBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edPublicDER})
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "private key", raw: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPrivateDER})},
		{name: "rsa key", raw: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPublicDER})},
		{name: "multiple blocks", raw: append(append([]byte(nil), validBlock...), validBlock...)},
		{name: "leading content", raw: append([]byte("raw-key-canary\n"), validBlock...)},
		{name: "trailing content", raw: append(append([]byte(nil), validBlock...), []byte("raw-key-canary")...)},
		{name: "malformed", raw: []byte("raw-key-canary")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "public.pem")
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadEd25519PublicKey(path)
			if err == nil {
				t.Fatal("LoadEd25519PublicKey() succeeded")
			}
			if strings.Contains(err.Error(), "raw-key-canary") {
				t.Fatalf("error leaked file contents: %v", err)
			}
		})
	}
}

func TestLoadTLSConfigRequiresTrustedClientCertificate(t *testing.T) {
	files := newTLSFiles(t)
	serverConfig, err := LoadTLSConfig(files.serverCert, files.serverKey, files.clientCA)
	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v", err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 ||
		serverConfig.ClientAuth != tls.RequireAndVerifyClientCert || serverConfig.ClientCAs == nil {
		t.Fatalf("TLS config = %+v", serverConfig)
	}

	trustedClient := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: files.serverRoots, ServerName: "internal.aera.test",
		Certificates: []tls.Certificate{files.clientCertificate},
	}
	if err := testTLSHandshake(serverConfig, trustedClient); err != nil {
		t.Fatalf("trusted handshake error = %v", err)
	}
	withoutClient := trustedClient.Clone()
	withoutClient.Certificates = nil
	if err := testTLSHandshake(serverConfig, withoutClient); err == nil {
		t.Fatal("handshake without client certificate succeeded")
	}
	untrustedClient := trustedClient.Clone()
	untrustedClient.Certificates = []tls.Certificate{files.untrustedClientCertificate}
	if err := testTLSHandshake(serverConfig, untrustedClient); err == nil {
		t.Fatal("handshake with untrusted client certificate succeeded")
	}
}

type tlsTestFiles struct {
	serverCert                 string
	serverKey                  string
	clientCA                   string
	serverRoots                *x509.CertPool
	clientCertificate          tls.Certificate
	untrustedClientCertificate tls.Certificate
}

func newTLSFiles(t *testing.T) tlsTestFiles {
	t.Helper()
	now := time.Now().UTC()
	serverCA, serverCAKey, serverCAPEM := issueTestCA(t, "server-ca", now, 1)
	clientCA, clientCAKey, clientCAPEM := issueTestCA(t, "client-ca", now, 2)
	untrustedCA, untrustedCAKey, _ := issueTestCA(t, "untrusted-client-ca", now, 3)

	serverCertPEM, serverKeyPEM := issueTestCertificate(
		t, serverCA, serverCAKey, "internal.aera.test", []string{"internal.aera.test"},
		x509.ExtKeyUsageServerAuth, now, 11,
	)
	clientCertPEM, clientKeyPEM := issueTestCertificate(
		t, clientCA, clientCAKey, "aera-admin-e2e", nil, x509.ExtKeyUsageClientAuth, now, 12,
	)
	untrustedCertPEM, untrustedKeyPEM := issueTestCertificate(
		t, untrustedCA, untrustedCAKey, "untrusted-admin", nil, x509.ExtKeyUsageClientAuth, now, 13,
	)
	clientCertificate, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	untrustedClientCertificate, err := tls.X509KeyPair(untrustedCertPEM, untrustedKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverRoots := x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(serverCAPEM) {
		t.Fatal("append server CA")
	}
	return tlsTestFiles{
		serverCert:  writeTestBytes(t, "server.crt", serverCertPEM),
		serverKey:   writeTestBytes(t, "server.key", serverKeyPEM),
		clientCA:    writeTestBytes(t, "client-ca.crt", clientCAPEM),
		serverRoots: serverRoots, clientCertificate: clientCertificate,
		untrustedClientCertificate: untrustedClientCertificate,
	}
}

func issueTestCA(t *testing.T, commonName string, now time.Time, serial int64) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func issueTestCertificate(
	t *testing.T,
	ca *x509.Certificate,
	caKey ed25519.PrivateKey,
	commonName string,
	dnsNames []string,
	usage x509.ExtKeyUsage,
	now time.Time,
	serial int64,
) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}

func testTLSHandshake(serverConfig, clientConfig *tls.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		server := tls.Server(connection, serverConfig.Clone())
		defer server.Close()
		serverResult <- server.HandshakeContext(ctx)
	}()
	clientConnection, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return err
	}
	client := tls.Client(clientConnection, clientConfig.Clone())
	defer client.Close()
	clientErr := client.HandshakeContext(ctx)
	serverErr := <-serverResult
	if serverErr != nil {
		return serverErr
	}
	return clientErr
}

func writeTestPEM(t *testing.T, name string, block *pem.Block) string {
	t.Helper()
	return writeTestBytes(t, name, pem.EncodeToMemory(block))
}

func writeTestBytes(t *testing.T, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
