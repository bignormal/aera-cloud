package adminapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("service JWT public key could not be read")
	}
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PUBLIC KEY-----")) {
		return nil, errors.New("service JWT public key must contain one PKIX public key")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("service JWT public key must contain one PKIX public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("service JWT public key is invalid")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("service JWT public key must be Ed25519")
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func LoadTLSConfig(serverCertFile, serverKeyFile, clientCAFile string) (*tls.Config, error) {
	serverCertificate, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, errors.New("internal admin TLS server identity is invalid")
	}
	clientCAPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, errors.New("internal admin client CA could not be read")
	}
	clientCAs, err := strictCertificatePool(clientCAPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

func strictCertificatePool(raw []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(raw)
	count := 0
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("internal admin client CA is invalid")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("internal admin client CA is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("internal admin client CA is invalid")
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, errors.New("internal admin client CA is invalid")
	}
	return pool, nil
}
