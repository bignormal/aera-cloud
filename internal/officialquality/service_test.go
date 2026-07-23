package officialquality

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceAcceptsSignedEligibleConsentedEventAndMinimizesIdentity(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	envelope := signedMetricEnvelope(t, now, private)
	repository := &fakeRepository{
		consentActive: true,
		deviceKey:     private.Public().(ed25519.PublicKey),
		eligible:      true,
	}
	service := newTestService(t, repository, allowQualityLimiter{}, allowQualityScanner{}, now)
	principal := validQualityPrincipal()

	result, err := service.Submit(context.Background(), principal, envelope)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if result.EventID != envelope.EventID || result.Replayed {
		t.Fatalf("Submit() = %+v", result)
	}
	if repository.acceptCalls != 1 {
		t.Fatalf("Accept() calls = %d, want 1", repository.acceptCalls)
	}
	if len(repository.accepted.SubjectPseudonym) != 32 || len(repository.accepted.BindingProofDigest) != 32 {
		t.Fatalf("sanitized digests = %d/%d", len(repository.accepted.SubjectPseudonym), len(repository.accepted.BindingProofDigest))
	}
	if repository.accepted.Principal != principal || repository.accepted.Envelope.BindingProof != envelope.BindingProof {
		t.Fatalf("transactional provenance command = %+v", repository.accepted)
	}
}

func TestServiceFailsClosedInPrivacyCheckOrder(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	valid := signedMetricEnvelope(t, now, private)

	tests := map[string]struct {
		prepare func(*fakeRepository, *PublicEnvelope) (QualityLimiter, QualityScanner)
		wantErr error
	}{
		"missing consent": {
			prepare: func(repository *fakeRepository, _ *PublicEnvelope) (QualityLimiter, QualityScanner) {
				repository.consentActive = false
				return allowQualityLimiter{}, allowQualityScanner{}
			},
			wantErr: ErrConsentRequired,
		},
		"invalid signature": {
			prepare: func(repository *fakeRepository, envelope *PublicEnvelope) (QualityLimiter, QualityScanner) {
				repository.consentActive = true
				repository.deviceKey = private.Public().(ed25519.PublicKey)
				envelope.DeviceSignature[0] ^= 0xff
				return allowQualityLimiter{}, allowQualityScanner{}
			},
			wantErr: ErrInvalidSignature,
		},
		"ineligible binding": {
			prepare: func(repository *fakeRepository, _ *PublicEnvelope) (QualityLimiter, QualityScanner) {
				repository.consentActive = true
				repository.deviceKey = private.Public().(ed25519.PublicKey)
				repository.eligible = false
				return allowQualityLimiter{}, allowQualityScanner{}
			},
			wantErr: ErrIneligible,
		},
		"rate limited": {
			prepare: func(repository *fakeRepository, _ *PublicEnvelope) (QualityLimiter, QualityScanner) {
				repository.consentActive = true
				repository.deviceKey = private.Public().(ed25519.PublicKey)
				repository.eligible = true
				return rejectQualityLimiter{}, allowQualityScanner{}
			},
			wantErr: ErrRateLimited,
		},
		"DLP rejected": {
			prepare: func(repository *fakeRepository, _ *PublicEnvelope) (QualityLimiter, QualityScanner) {
				repository.consentActive = true
				repository.deviceKey = private.Public().(ed25519.PublicKey)
				repository.eligible = true
				return allowQualityLimiter{}, rejectQualityScanner{}
			},
			wantErr: ErrDLPRejected,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := valid
			envelope.DeviceSignature = bytes.Clone(valid.DeviceSignature)
			repository := &fakeRepository{}
			limiter, scanner := test.prepare(repository, &envelope)
			service := newTestService(t, repository, limiter, scanner, now)
			if _, err := service.Submit(context.Background(), validQualityPrincipal(), envelope); !errors.Is(err, test.wantErr) {
				t.Fatalf("Submit() error = %v, want %v", err, test.wantErr)
			}
			if repository.acceptCalls != 0 {
				t.Fatalf("Accept() calls = %d, want 0", repository.acceptCalls)
			}
		})
	}
}

func TestServiceTreatsExactRepositoryReplayAsSuccess(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	envelope := signedMetricEnvelope(t, now, private)
	repository := &fakeRepository{
		consentActive: true, deviceKey: private.Public().(ed25519.PublicKey), eligible: true, replayed: true,
	}
	service := newTestService(t, repository, allowQualityLimiter{}, allowQualityScanner{}, now)
	result, err := service.Submit(context.Background(), validQualityPrincipal(), envelope)
	if err != nil || !result.Replayed {
		t.Fatalf("Submit() = %+v, %v", result, err)
	}
}

func TestMinimizedScannerRejectsCredentialAndPrivatePayloadCanaries(t *testing.T) {
	scanner := MinimizedScanner{}
	for name, raw := range map[string][]byte{
		"private key":  []byte("-----BEGIN PRIVATE KEY-----"),
		"bearer":       []byte("Bearer abcdefghijklmnopqrstuvwxyz012345"),
		"API key":      []byte("sk-proj-abcdefghijklmnopqrstuvwxyz012345"),
		"path":         []byte("/Users/alice/private/conversation.json"),
		"prompt key":   []byte(`{"prompt":"private-canary"}`),
		"response key": []byte(`{"response":"private-canary"}`),
		"memory key":   []byte(`{"memory":"private-canary"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := scanner.Scan(raw); !errors.Is(err, ErrDLPRejected) {
				t.Fatalf("Scan() error = %v, want ErrDLPRejected", err)
			}
		})
	}
	if err := scanner.Scan([]byte(`official-quality-event-v1\x00{"desktop_version":"1.2.3","binding_proof":"66666666-6666-4666-8666-666666666666"}`)); err != nil {
		t.Fatalf("Scan() rejected minimized payload: %v", err)
	}
}

func signedMetricEnvelope(t *testing.T, now time.Time, private ed25519.PrivateKey) PublicEnvelope {
	t.Helper()
	envelope, err := DecodePublicEnvelope(
		[]byte(validPublicEnvelopeJSON(mustUUIDV7(t), base64Signature(0x44))), now,
	)
	if err != nil {
		t.Fatalf("DecodePublicEnvelope() error = %v", err)
	}
	payload, err := envelope.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes() error = %v", err)
	}
	envelope.DeviceSignature = ed25519.Sign(private, payload)
	return envelope
}

func base64Signature(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, ed25519.SignatureSize))
}

func validQualityPrincipal() Principal {
	return Principal{
		UserID:          uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		DeviceID:        uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		PersonalSpaceID: uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
	}
}

func newTestService(
	t *testing.T,
	repository Repository,
	limiter QualityLimiter,
	scanner QualityScanner,
	now time.Time,
) *Service {
	t.Helper()
	pseudonyms, err := NewPseudonymizer("active", map[string][]byte{
		"active": bytes.Repeat([]byte{0x71}, 32),
	})
	if err != nil {
		t.Fatalf("NewPseudonymizer() error = %v", err)
	}
	service, err := NewService(ServiceConfig{
		Repository: repository, Pseudonymizer: pseudonyms, Limiter: limiter,
		Scanner: scanner, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

type fakeRepository struct {
	consentActive bool
	deviceKey     ed25519.PublicKey
	eligible      bool
	replayed      bool
	accepted      AcceptEventCommand
	acceptCalls   int
}

func (f *fakeRepository) ActiveConsent(context.Context, uuid.UUID, string, int64) (bool, error) {
	return f.consentActive, nil
}

func (f *fakeRepository) ActiveDeviceKey(context.Context, Principal) (ed25519.PublicKey, error) {
	return bytes.Clone(f.deviceKey), nil
}

func (f *fakeRepository) EligibleBinding(context.Context, Principal, PublicEnvelope) (bool, error) {
	return f.eligible, nil
}

func (f *fakeRepository) AcceptEvent(_ context.Context, command AcceptEventCommand) (bool, error) {
	f.acceptCalls++
	f.accepted = command
	return f.replayed, nil
}

type allowQualityLimiter struct{}

func (allowQualityLimiter) Allow(context.Context, Principal, string, []byte) error { return nil }

type rejectQualityLimiter struct{}

func (rejectQualityLimiter) Allow(context.Context, Principal, string, []byte) error {
	return ErrRateLimited
}

type allowQualityScanner struct{}

func (allowQualityScanner) Scan([]byte) error { return nil }

type rejectQualityScanner struct{}

func (rejectQualityScanner) Scan([]byte) error { return ErrDLPRejected }
