package officialquality

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrConsentRequired    = errors.New("official quality consent is required")
	ErrInvalidSignature   = errors.New("official quality device signature is invalid")
	ErrIneligible         = errors.New("official quality event provenance is ineligible")
	ErrRateLimited        = errors.New("official quality request is rate limited")
	ErrDLPRejected        = errors.New("official quality request failed privacy scan")
	ErrConflict           = errors.New("official quality event conflicts with an existing event")
	ErrServiceUnavailable = errors.New("official quality service is unavailable")
)

type Principal struct {
	UserID          uuid.UUID
	DeviceID        uuid.UUID
	PersonalSpaceID uuid.UUID
}

func (p Principal) valid() bool {
	return p.UserID != uuid.Nil && p.DeviceID != uuid.Nil && p.PersonalSpaceID != uuid.Nil
}

type AcceptEventCommand struct {
	Principal          Principal
	Envelope           PublicEnvelope
	SubjectPseudonym   []byte
	BindingProofDigest []byte
	AcceptedAt         time.Time
}

type Repository interface {
	ActiveConsent(context.Context, uuid.UUID, string, int64) (bool, error)
	ActiveDeviceKey(context.Context, Principal) (ed25519.PublicKey, error)
	EligibleBinding(context.Context, Principal, PublicEnvelope) (bool, error)
	AcceptEvent(context.Context, AcceptEventCommand) (replayed bool, err error)
}

type QualityLimiter interface {
	Allow(context.Context, Principal, string, []byte) error
}

type QualityScanner interface {
	Scan([]byte) error
}

type ServiceConfig struct {
	Repository    Repository
	Pseudonymizer *Pseudonymizer
	Limiter       QualityLimiter
	Scanner       QualityScanner
	Clock         func() time.Time
}

type Service struct {
	repository    Repository
	pseudonymizer *Pseudonymizer
	limiter       QualityLimiter
	scanner       QualityScanner
	clock         func() time.Time
}

type SubmitResult struct {
	EventID  uuid.UUID
	Replayed bool
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.Pseudonymizer == nil || config.Limiter == nil || config.Scanner == nil {
		return nil, errors.New("official quality service configuration is incomplete")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		repository: config.Repository, pseudonymizer: config.Pseudonymizer,
		limiter: config.Limiter, scanner: config.Scanner, clock: clock,
	}, nil
}

func (s *Service) Submit(ctx context.Context, principal Principal, envelope PublicEnvelope) (SubmitResult, error) {
	if s == nil || !principal.valid() {
		return SubmitResult{}, ErrInvalidRequest
	}
	now := s.clock().UTC()
	if !envelope.valid(now) {
		return SubmitResult{}, ErrInvalidRequest
	}
	purpose := envelope.Purpose()
	active, err := s.repository.ActiveConsent(ctx, principal.UserID, purpose, envelope.ConsentVersion)
	if err != nil {
		return SubmitResult{}, ErrServiceUnavailable
	}
	if !active {
		return SubmitResult{}, ErrConsentRequired
	}
	deviceKey, err := s.repository.ActiveDeviceKey(ctx, principal)
	if err != nil {
		return SubmitResult{}, ErrServiceUnavailable
	}
	signingBytes, err := envelope.SigningBytes()
	if err != nil || len(deviceKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(deviceKey, signingBytes, envelope.DeviceSignature) {
		return SubmitResult{}, ErrInvalidSignature
	}
	eligible, err := s.repository.EligibleBinding(ctx, principal, envelope)
	if err != nil {
		return SubmitResult{}, ErrServiceUnavailable
	}
	if !eligible {
		return SubmitResult{}, ErrIneligible
	}
	subject := s.pseudonymizer.Active(principal.UserID, purpose, envelope.Day())
	bindingDigest := s.pseudonymizer.BindingProofDigest(envelope.BindingProof, purpose, envelope.Day())
	if len(subject) != 32 || len(bindingDigest) != 32 {
		return SubmitResult{}, ErrServiceUnavailable
	}
	if err := s.limiter.Allow(ctx, principal, purpose, subject); err != nil {
		if errors.Is(err, ErrRateLimited) {
			return SubmitResult{}, ErrRateLimited
		}
		return SubmitResult{}, ErrServiceUnavailable
	}
	if err := s.scanner.Scan(signingBytes); err != nil {
		if errors.Is(err, ErrDLPRejected) {
			return SubmitResult{}, ErrDLPRejected
		}
		return SubmitResult{}, ErrServiceUnavailable
	}
	replayed, err := s.repository.AcceptEvent(ctx, AcceptEventCommand{
		Principal: principal, Envelope: envelope, SubjectPseudonym: subject,
		BindingProofDigest: bindingDigest, AcceptedAt: now,
	})
	if err != nil {
		if errors.Is(err, ErrConsentRequired) || errors.Is(err, ErrIneligible) || errors.Is(err, ErrConflict) {
			return SubmitResult{}, err
		}
		return SubmitResult{}, ErrServiceUnavailable
	}
	return SubmitResult{EventID: envelope.EventID, Replayed: replayed}, nil
}
