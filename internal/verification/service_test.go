package verification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
)

var sixDigitCode = regexp.MustCompile(`^[0-9]{6}$`)

func TestServiceDeliversSixDigitCodeBeforeSavingChallenge(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.events = &[]string{}
	fixture.sender.events = fixture.events
	fixture.repository.events = fixture.events

	err := fixture.service.Send(context.Background(), SendRequest{
		Kind:           secure.IdentityEmail,
		Destination:    "  Alice@Example.COM ",
		Purpose:        PurposeRegistration,
		IdempotencyKey: "request-1",
		IPAddress:      "203.0.113.10",
		DeviceID:       "device-1",
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if len(fixture.sender.deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(fixture.sender.deliveries))
	}
	delivery := fixture.sender.deliveries[0]
	if delivery.destination != "alice@example.com" {
		t.Fatalf("destination = %q", delivery.destination)
	}
	if !sixDigitCode.MatchString(delivery.code) {
		t.Fatalf("code = %q, want six numeric digits", delivery.code)
	}
	if len(fixture.repository.challenges) != 1 {
		t.Fatalf("saved challenges = %d, want 1", len(fixture.repository.challenges))
	}
	challenge := fixture.repository.challenges[0]
	if challenge.CreatedAt != fixture.now || challenge.ExpiresAt != fixture.now.Add(5*time.Minute) {
		t.Fatalf("challenge lifetime = %s to %s", challenge.CreatedAt, challenge.ExpiresAt)
	}
	if challenge.ResendAfter != fixture.now.Add(time.Minute) {
		t.Fatalf("ResendAfter = %s", challenge.ResendAfter)
	}
	if challenge.CodeKeyID != "code-v1" || len(challenge.CodeHMAC) != 32 {
		t.Fatalf("code key/hash = %q/%d", challenge.CodeKeyID, len(challenge.CodeHMAC))
	}
	if len(challenge.TargetLookupHMAC) != 32 || len(challenge.IdempotencyKeyHash) != 32 {
		t.Fatalf("target/idempotency hash lengths = %d/%d", len(challenge.TargetLookupHMAC), len(challenge.IdempotencyKeyHash))
	}
	if bytes.Contains(challenge.CodeHMAC, []byte(delivery.code)) || bytes.Contains(challenge.TargetLookupHMAC, []byte("alice@example.com")) {
		t.Fatal("persisted challenge contains plaintext secret material")
	}
	if got := strings.Join(*fixture.events, ","); got != "send,save" {
		t.Fatalf("event order = %q, want send,save", got)
	}
	if len(fixture.limiter.calls) != 3 {
		t.Fatalf("limiter calls = %d, want identity, IP, and device", len(fixture.limiter.calls))
	}
}

func TestServiceDoesNotSaveChallengeWhenProviderFails(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.sender.err = errors.New("provider rejected secret payload")

	err := fixture.service.Send(context.Background(), fixture.sendRequest("request-1"))
	if !errors.Is(err, ErrDeliveryUnavailable) {
		t.Fatalf("Send() error = %v, want ErrDeliveryUnavailable", err)
	}
	if len(fixture.repository.challenges) != 0 {
		t.Fatal("provider failure left a usable challenge")
	}
	if fixture.guard.releases != 1 {
		t.Fatalf("delivery lease releases = %d, want 1", fixture.guard.releases)
	}
}

func TestServiceMakesSequentialIdempotentRetryWithoutDuplicateDelivery(t *testing.T) {
	fixture := newServiceFixture(t)
	request := fixture.sendRequest("request-1")
	if err := fixture.service.Send(context.Background(), request); err != nil {
		t.Fatalf("first Send() error = %v", err)
	}
	if err := fixture.service.Send(context.Background(), request); err != nil {
		t.Fatalf("second Send() error = %v", err)
	}
	if len(fixture.sender.deliveries) != 1 || len(fixture.repository.challenges) != 1 {
		t.Fatalf("deliveries/challenges = %d/%d, want 1/1", len(fixture.sender.deliveries), len(fixture.repository.challenges))
	}
}

func TestServiceEnforcesResendDelayAcrossDifferentIdempotencyKeys(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Send(context.Background(), fixture.sendRequest("request-1")); err != nil {
		t.Fatalf("first Send() error = %v", err)
	}
	err := fixture.service.Send(context.Background(), fixture.sendRequest("request-2"))
	if !errors.Is(err, ErrResendTooSoon) {
		t.Fatalf("second Send() error = %v, want ErrResendTooSoon", err)
	}
	if len(fixture.sender.deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(fixture.sender.deliveries))
	}
}

func TestServiceFailsClosedOnLimiterFailureOrDenial(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
		limitErr error
		want     error
	}{
		{name: "redis unavailable", limitErr: errors.New("redis password leaked here"), want: ErrTemporarilyUnavailable},
		{name: "limit denied", decision: Decision{Allowed: false}, want: ErrRateLimited},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			fixture.limiter.decision = tt.decision
			fixture.limiter.err = tt.limitErr

			err := fixture.service.Send(context.Background(), fixture.sendRequest("request-1"))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Send() error = %v, want %v", err, tt.want)
			}
			if len(fixture.sender.deliveries) != 0 {
				t.Fatal("limited request reached notification provider")
			}
		})
	}
}

func TestServiceEscalatesAbnormalFrequencyToCaptcha(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.limiter.decision = Decision{Allowed: true, CaptchaRequired: true}

	err := fixture.service.Send(context.Background(), fixture.sendRequest("request-1"))
	if !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("Send() error = %v, want ErrCaptchaRequired", err)
	}
	if fixture.captcha.calls != 0 {
		t.Fatalf("CAPTCHA calls without a token = %d", fixture.captcha.calls)
	}

	request := fixture.sendRequest("request-2")
	request.CaptchaToken = "captcha-proof"
	if err := fixture.service.Send(context.Background(), request); err != nil {
		t.Fatalf("Send() with CAPTCHA error = %v", err)
	}
	if fixture.captcha.calls != 1 || fixture.captcha.lastIP != request.IPAddress {
		t.Fatalf("CAPTCHA calls/IP = %d/%q", fixture.captcha.calls, fixture.captcha.lastIP)
	}
}

func TestServiceConsumesCodeOnceAndInvalidatesAfterFiveFailures(t *testing.T) {
	t.Run("one time consumption", func(t *testing.T) {
		fixture := newServiceFixture(t)
		request := fixture.sendRequest("request-1")
		if err := fixture.service.Send(context.Background(), request); err != nil {
			t.Fatalf("Send() error = %v", err)
		}
		code := fixture.sender.deliveries[0].code
		verify := VerifyRequest{Kind: request.Kind, Destination: request.Destination, Purpose: request.Purpose, Code: code}
		if err := fixture.service.Verify(context.Background(), verify); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if err := fixture.service.Verify(context.Background(), verify); !errors.Is(err, ErrInvalidVerification) {
			t.Fatalf("second Verify() error = %v, want ErrInvalidVerification", err)
		}
	})

	t.Run("five failures invalidate", func(t *testing.T) {
		fixture := newServiceFixture(t)
		request := fixture.sendRequest("request-1")
		if err := fixture.service.Send(context.Background(), request); err != nil {
			t.Fatalf("Send() error = %v", err)
		}
		for attempt := 1; attempt <= 5; attempt++ {
			err := fixture.service.Verify(context.Background(), VerifyRequest{
				Kind: request.Kind, Destination: request.Destination, Purpose: request.Purpose, Code: "000000",
			})
			if !errors.Is(err, ErrInvalidVerification) {
				t.Fatalf("wrong attempt %d error = %v", attempt, err)
			}
		}
		correct := fixture.sender.deliveries[0].code
		err := fixture.service.Verify(context.Background(), VerifyRequest{
			Kind: request.Kind, Destination: request.Destination, Purpose: request.Purpose, Code: correct,
		})
		if !errors.Is(err, ErrInvalidVerification) {
			t.Fatalf("Verify() after five failures error = %v", err)
		}
	})
}

func TestServiceVerifiesChallengeAcrossCodeKeyRotation(t *testing.T) {
	fixture := newServiceFixture(t)
	request := fixture.sendRequest("request-1")
	if err := fixture.service.Send(context.Background(), request); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	code := fixture.sender.deliveries[0].code

	rotated, err := NewService(fixture.config("code-v2"))
	if err != nil {
		t.Fatalf("NewService(rotated) error = %v", err)
	}
	if err := rotated.Verify(context.Background(), VerifyRequest{
		Kind: request.Kind, Destination: request.Destination, Purpose: request.Purpose, Code: code,
	}); err != nil {
		t.Fatalf("rotated Verify() error = %v", err)
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	fixture := newServiceFixture(t)
	var logs bytes.Buffer
	fixture.sender.err = errors.New("provider secret=provider-password destination=alice@example.com code=123456")
	fixture.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	service, err := NewService(fixture.config("code-v1"))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	_ = service.Send(context.Background(), fixture.sendRequest("request-1"))
	output := logs.String()
	for _, secret := range []string{"provider-password", "alice@example.com", "123456", "request-1"} {
		if strings.Contains(output, secret) {
			t.Fatalf("logs contain secret %q: %s", secret, output)
		}
	}
}

type serviceFixture struct {
	now        time.Time
	sender     *fakeSender
	repository *fakeRepository
	limiter    *fakeLimiter
	captcha    *fakeCaptcha
	guard      *fakeDeliveryGuard
	indexer    *secure.IdentityCodec
	logger     *slog.Logger
	service    *Service
	events     *[]string
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	indexer, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: "enc-v1",
		EncryptionKeys:        map[string][]byte{"enc-v1": bytes.Repeat([]byte{1}, 32)},
		ActiveLookupKeyID:     "lookup-v1",
		LookupKeys:            map[string][]byte{"lookup-v1": bytes.Repeat([]byte{2}, 32)},
	})
	if err != nil {
		t.Fatalf("NewIdentityCodec() error = %v", err)
	}
	fixture := &serviceFixture{
		now:        time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		sender:     &fakeSender{},
		repository: &fakeRepository{},
		limiter:    &fakeLimiter{decision: Decision{Allowed: true}},
		captcha:    &fakeCaptcha{valid: true},
		guard:      &fakeDeliveryGuard{acquired: true},
		indexer:    indexer,
		logger:     slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	service, err := NewService(fixture.config("code-v1"))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

func (f *serviceFixture) config(activeCodeKeyID string) ServiceConfig {
	return ServiceConfig{
		Sender:          f.sender,
		Repository:      f.repository,
		Limiter:         f.limiter,
		Captcha:         f.captcha,
		DeliveryGuard:   f.guard,
		TargetIndexer:   f.indexer,
		ActiveCodeKeyID: activeCodeKeyID,
		CodeKeys: map[string][]byte{
			"code-v1": bytes.Repeat([]byte{3}, 32),
			"code-v2": bytes.Repeat([]byte{4}, 32),
		},
		RequestHMACKey: bytes.Repeat([]byte{5}, 32),
		Clock:          func() time.Time { return f.now },
		Logger:         f.logger,
	}
}

func (f *serviceFixture) sendRequest(idempotencyKey string) SendRequest {
	return SendRequest{
		Kind:           secure.IdentityEmail,
		Destination:    "alice@example.com",
		Purpose:        PurposeRegistration,
		IdempotencyKey: idempotencyKey,
		IPAddress:      "203.0.113.10",
		DeviceID:       "device-1",
	}
}

type delivery struct {
	destination string
	code        string
	purpose     Purpose
}

type fakeSender struct {
	deliveries []delivery
	err        error
	events     *[]string
}

func (f *fakeSender) SendVerification(_ context.Context, destination, code string, purpose Purpose) error {
	f.deliveries = append(f.deliveries, delivery{destination: destination, code: code, purpose: purpose})
	if f.events != nil {
		*f.events = append(*f.events, "send")
	}
	return f.err
}

type fakeRepository struct {
	challenges []Challenge
	events     *[]string
	err        error
}

func (f *fakeRepository) ExistsByIdempotency(_ context.Context, hash []byte) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	for _, challenge := range f.challenges {
		if hmac.Equal(challenge.IdempotencyKeyHash, hash) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeRepository) Latest(_ context.Context, targetHMACs [][]byte, purpose Purpose) (Challenge, bool, error) {
	if f.err != nil {
		return Challenge{}, false, f.err
	}
	for index := len(f.challenges) - 1; index >= 0; index-- {
		challenge := f.challenges[index]
		if challenge.Purpose != purpose {
			continue
		}
		for _, target := range targetHMACs {
			if hmac.Equal(challenge.TargetLookupHMAC, target) {
				return challenge, true, nil
			}
		}
	}
	return Challenge{}, false, nil
}

func (f *fakeRepository) SaveAfterDelivery(_ context.Context, challenge Challenge) error {
	if f.err != nil {
		return f.err
	}
	f.challenges = append(f.challenges, challenge)
	if f.events != nil {
		*f.events = append(*f.events, "save")
	}
	return nil
}

func (f *fakeRepository) Consume(_ context.Context, targetHMAC []byte, purpose Purpose, codeHMAC []byte, now time.Time) error {
	if f.err != nil {
		return f.err
	}
	for index := len(f.challenges) - 1; index >= 0; index-- {
		challenge := &f.challenges[index]
		if challenge.Purpose != purpose || !hmac.Equal(challenge.TargetLookupHMAC, targetHMAC) {
			continue
		}
		if challenge.ConsumedAt != nil || challenge.InvalidatedAt != nil || !now.Before(challenge.ExpiresAt) {
			return ErrChallengeNotFound
		}
		if !hmac.Equal(challenge.CodeHMAC, codeHMAC) {
			challenge.FailedAttempts++
			if challenge.FailedAttempts >= 5 {
				invalidated := now
				challenge.InvalidatedAt = &invalidated
			}
			return ErrCodeMismatch
		}
		consumed := now
		challenge.ConsumedAt = &consumed
		return nil
	}
	return ErrChallengeNotFound
}

type fakeLimiter struct {
	decision Decision
	err      error
	calls    []string
}

func (f *fakeLimiter) Allow(_ context.Context, key string, _ Policy) (Decision, error) {
	f.calls = append(f.calls, key)
	return f.decision, f.err
}

type fakeCaptcha struct {
	valid  bool
	err    error
	calls  int
	lastIP string
}

func (f *fakeCaptcha) Verify(_ context.Context, _, remoteIP string) (bool, error) {
	f.calls++
	f.lastIP = remoteIP
	return f.valid, f.err
}

type fakeDeliveryGuard struct {
	acquired bool
	err      error
	releases int
}

func (f *fakeDeliveryGuard) Acquire(context.Context, string, string, time.Duration) (bool, error) {
	return f.acquired, f.err
}

func (f *fakeDeliveryGuard) Release(context.Context, string, string) error {
	f.releases++
	return nil
}
