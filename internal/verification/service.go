package verification

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
)

const (
	challengeLifetime = 5 * time.Minute
	resendDelay       = time.Minute
	deliveryLeaseTTL  = 30 * time.Second
)

type Sender interface {
	SendVerification(ctx context.Context, destination, code string, purpose Purpose) error
}

type Repository interface {
	ExistsByIdempotency(ctx context.Context, hash []byte) (bool, error)
	Latest(ctx context.Context, targetHMACs [][]byte, purpose Purpose) (Challenge, bool, error)
	SaveAfterDelivery(ctx context.Context, challenge Challenge) error
	Consume(ctx context.Context, targetHMAC []byte, purpose Purpose, codeHMAC []byte, now time.Time) error
}

type Limiter interface {
	Allow(ctx context.Context, key string, policy Policy) (Decision, error)
}

type CaptchaVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

type DeliveryGuard interface {
	Acquire(ctx context.Context, key, owner string, ttl time.Duration) (bool, error)
	Release(ctx context.Context, key, owner string) error
}

type TargetIndexer interface {
	LookupCandidates(kind secure.IdentityKind, normalized string) []secure.LookupIndex
}

type ServiceConfig struct {
	Sender          Sender
	Repository      Repository
	Limiter         Limiter
	Captcha         CaptchaVerifier
	DeliveryGuard   DeliveryGuard
	TargetIndexer   TargetIndexer
	ActiveCodeKeyID string
	CodeKeys        map[string][]byte
	RequestHMACKey  []byte
	Clock           func() time.Time
	Logger          *slog.Logger
	Policies        ScopePolicies
}

type Service struct {
	sender          Sender
	repository      Repository
	limiter         Limiter
	captcha         CaptchaVerifier
	deliveryGuard   DeliveryGuard
	targetIndexer   TargetIndexer
	activeCodeKeyID string
	codeKeys        map[string][]byte
	requestHMACKey  []byte
	clock           func() time.Time
	logger          *slog.Logger
	policies        ScopePolicies
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Sender == nil || config.Repository == nil || config.Limiter == nil || config.Captcha == nil ||
		config.DeliveryGuard == nil || config.TargetIndexer == nil {
		return nil, errors.New("verification service dependencies are incomplete")
	}
	codeKeys, err := copyKeyRing(config.CodeKeys, 32)
	if err != nil {
		return nil, err
	}
	if _, ok := codeKeys[config.ActiveCodeKeyID]; !ok || strings.TrimSpace(config.ActiveCodeKeyID) == "" {
		return nil, errors.New("active verification code key is unavailable")
	}
	if len(config.RequestHMACKey) < 32 {
		return nil, errors.New("verification request HMAC key must contain at least 32 bytes")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	policies := config.Policies
	if !policies.valid() {
		policies = DefaultScopePolicies()
	}
	return &Service{
		sender:          config.Sender,
		repository:      config.Repository,
		limiter:         config.Limiter,
		captcha:         config.Captcha,
		deliveryGuard:   config.DeliveryGuard,
		targetIndexer:   config.TargetIndexer,
		activeCodeKeyID: config.ActiveCodeKeyID,
		codeKeys:        codeKeys,
		requestHMACKey:  append([]byte(nil), config.RequestHMACKey...),
		clock:           clock,
		logger:          logger,
		policies:        policies,
	}, nil
}

func (s *Service) Send(ctx context.Context, request SendRequest) error {
	normalized, candidates, err := s.prepareTarget(request.Kind, request.Destination, request.Purpose)
	if err != nil || !validSendMetadata(request) {
		return ErrInvalidRequest
	}
	idempotencyHash := s.requestHMAC(
		"idempotency",
		string(request.Purpose),
		string(request.Kind),
		normalized,
		request.IdempotencyKey,
	)
	exists, err := s.repository.ExistsByIdempotency(ctx, idempotencyHash)
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	if exists {
		return nil
	}

	owner, err := secure.RandomToken(32)
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	leaseKey := hex.EncodeToString(idempotencyHash)
	acquired, err := s.deliveryGuard.Acquire(ctx, leaseKey, owner, deliveryLeaseTTL)
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	if !acquired {
		return ErrRequestInProgress
	}
	defer func() {
		if err := s.deliveryGuard.Release(context.WithoutCancel(ctx), leaseKey, owner); err != nil {
			s.logger.Warn("verification delivery lease release failed", "purpose", request.Purpose, "kind", request.Kind)
		}
	}()

	exists, err = s.repository.ExistsByIdempotency(ctx, idempotencyHash)
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	if exists {
		return nil
	}
	targetHMACs := lookupHMACs(candidates)
	now := s.clock().UTC()
	latest, found, err := s.repository.Latest(ctx, targetHMACs, request.Purpose)
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	if found && now.Before(latest.ResendAfter) {
		return ErrResendTooSoon
	}

	captchaRequired, err := s.allowRequest(ctx, request, candidates[0].HMAC)
	if err != nil {
		return err
	}
	if captchaRequired {
		if strings.TrimSpace(request.CaptchaToken) == "" {
			return ErrCaptchaRequired
		}
		valid, err := s.captcha.Verify(ctx, request.CaptchaToken, request.IPAddress)
		if err != nil {
			return ErrTemporarilyUnavailable
		}
		if !valid {
			return ErrCaptchaRequired
		}
	}

	code, err := randomSixDigitCode()
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	challengeID, err := secure.RandomUUID()
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	challenge := Challenge{
		ID:                 challengeID,
		Purpose:            request.Purpose,
		IdentityKind:       request.Kind,
		TargetLookupKeyID:  candidates[0].KeyID,
		TargetLookupHMAC:   append([]byte(nil), candidates[0].HMAC...),
		CodeKeyID:          s.activeCodeKeyID,
		CodeHMAC:           codeHMAC(s.codeKeys[s.activeCodeKeyID], request.Purpose, candidates[0].HMAC, code),
		IdempotencyKeyHash: append([]byte(nil), idempotencyHash...),
		CreatedAt:          now,
		ExpiresAt:          now.Add(challengeLifetime),
		ResendAfter:        now.Add(resendDelay),
	}
	if err := s.sender.SendVerification(ctx, normalized, code, request.Purpose); err != nil {
		s.logger.Warn("verification delivery failed", "purpose", request.Purpose, "kind", request.Kind)
		return ErrDeliveryUnavailable
	}
	if err := s.repository.SaveAfterDelivery(ctx, challenge); err != nil {
		s.logger.Warn("verification challenge persistence failed", "purpose", request.Purpose, "kind", request.Kind)
		return ErrTemporarilyUnavailable
	}
	return nil
}

func (s *Service) Verify(ctx context.Context, request VerifyRequest) error {
	_, candidates, err := s.prepareTarget(request.Kind, request.Destination, request.Purpose)
	if err != nil || !validCode(request.Code) {
		return ErrInvalidVerification
	}
	now := s.clock().UTC()
	challenge, found, err := s.repository.Latest(ctx, lookupHMACs(candidates), request.Purpose)
	if err != nil {
		return ErrTemporarilyUnavailable
	}
	if !found || challenge.ConsumedAt != nil || challenge.InvalidatedAt != nil || !now.Before(challenge.ExpiresAt) {
		return ErrInvalidVerification
	}
	key, ok := s.codeKeys[challenge.CodeKeyID]
	if !ok {
		return ErrTemporarilyUnavailable
	}
	candidateCodeHMAC := codeHMAC(key, request.Purpose, challenge.TargetLookupHMAC, request.Code)
	if err := s.repository.Consume(ctx, challenge.TargetLookupHMAC, request.Purpose, candidateCodeHMAC, now); err != nil {
		if errors.Is(err, ErrChallengeNotFound) || errors.Is(err, ErrCodeMismatch) {
			return ErrInvalidVerification
		}
		return ErrTemporarilyUnavailable
	}
	return nil
}

func (s *Service) prepareTarget(kind secure.IdentityKind, destination string, purpose Purpose) (string, []secure.LookupIndex, error) {
	if !validPurpose(purpose) {
		return "", nil, ErrInvalidRequest
	}
	normalized, err := secure.NormalizeIdentity(kind, destination)
	if err != nil {
		return "", nil, ErrInvalidRequest
	}
	candidates := s.targetIndexer.LookupCandidates(kind, normalized)
	if len(candidates) == 0 {
		return "", nil, ErrTemporarilyUnavailable
	}
	return normalized, candidates, nil
}

func (s *Service) allowRequest(ctx context.Context, request SendRequest, targetHMAC []byte) (bool, error) {
	scopes := []struct {
		name   string
		value  []byte
		policy Policy
	}{
		{name: "identity", value: targetHMAC, policy: s.policies.Identity},
		{name: "ip", value: []byte(request.IPAddress), policy: s.policies.IP},
		{name: "device", value: []byte(request.DeviceID), policy: s.policies.Device},
	}
	captchaRequired := false
	for _, scope := range scopes {
		key := hex.EncodeToString(s.requestHMAC("limit", scope.name, string(scope.value)))
		decision, err := s.limiter.Allow(ctx, key, scope.policy)
		if err != nil {
			return false, ErrTemporarilyUnavailable
		}
		if !decision.Allowed {
			return false, ErrRateLimited
		}
		captchaRequired = captchaRequired || decision.CaptchaRequired
	}
	return captchaRequired, nil
}

func (s *Service) requestHMAC(parts ...string) []byte {
	mac := hmac.New(sha256.New, s.requestHMACKey)
	for _, part := range parts {
		_, _ = mac.Write([]byte(part))
		_, _ = mac.Write([]byte{0})
	}
	return mac.Sum(nil)
}

func codeHMAC(key []byte, purpose Purpose, targetHMAC []byte, code string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(targetHMAC)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(code))
	return mac.Sum(nil)
}

func randomSixDigitCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", errors.New("secure random source is unavailable")
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func validCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validSendMetadata(request SendRequest) bool {
	return len(request.IdempotencyKey) >= 8 && len(request.IdempotencyKey) <= 200 &&
		strings.TrimSpace(request.IPAddress) != "" && len(request.IPAddress) <= 128 &&
		strings.TrimSpace(request.DeviceID) != "" && len(request.DeviceID) <= 200
}

func lookupHMACs(candidates []secure.LookupIndex) [][]byte {
	values := make([][]byte, 0, len(candidates))
	for _, candidate := range candidates {
		values = append(values, candidate.HMAC)
	}
	return values
}

func copyKeyRing(keys map[string][]byte, minimumLength int) (map[string][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("verification code key ring is empty")
	}
	copied := make(map[string][]byte, len(keys))
	for keyID, key := range keys {
		if strings.TrimSpace(keyID) == "" || len(key) < minimumLength {
			return nil, errors.New("verification code key ring contains an invalid key")
		}
		copied[keyID] = append([]byte(nil), key...)
	}
	return copied, nil
}
