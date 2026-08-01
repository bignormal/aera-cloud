package account

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/bignormal/aera-cloud/internal/legal"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
)

const dummyPassword = "AgentEra constant shape dummy password"

type Passwords interface {
	Hash(string) (string, int, error)
	Verify(password, encoded string) (valid bool, needsRehash bool, err error)
}

type Repository interface {
	Profile(context.Context, uuid.UUID) (Profile, bool, error)
	Register(context.Context, RegistrationRecord) (Registration, error)
	FindCredential(context.Context, secure.IdentityKind, []secure.LookupIndex) (Credential, bool, error)
	FindCredentialByUserID(context.Context, uuid.UUID) (Credential, bool, error)
	ConsumeLoginReceipt(context.Context, LoginReceiptRecord) error
	UpdatePasswordHash(context.Context, uuid.UUID, string, int, time.Time) error
	ResetPassword(context.Context, PasswordResetRecord) error
	BindIdentity(context.Context, IdentityBindingRecord) error
	RemoveIdentity(context.Context, IdentityRemovalRecord) error
	ChangePassword(context.Context, PasswordChangeRecord) error
	RequestDeletion(context.Context, DeletionRequestRecord) error
	RecoverDeletion(context.Context, DeletionRecoveryRecord) error
}

type LoginLimiter interface {
	Allow(context.Context, []byte, string) (bool, error)
}

type DirectRegistrationLimiter interface {
	Allow(context.Context, string) (bool, error)
}

type ServiceConfig struct {
	Repository                Repository
	IdentityCodec             *secure.IdentityCodec
	Receipts                  *verification.ReceiptCodec
	Passwords                 Passwords
	Legal                     *legal.Service
	LoginLimiter              LoginLimiter
	DirectRegistration        bool
	DirectRegistrationLimiter DirectRegistrationLimiter
	Auditor                   audit.Recorder
	Clock                     func() time.Time
}

type Service struct {
	repository                Repository
	identity                  *secure.IdentityCodec
	receipts                  *verification.ReceiptCodec
	passwords                 Passwords
	legal                     *legal.Service
	loginLimiter              LoginLimiter
	directRegistration        bool
	directRegistrationLimiter DirectRegistrationLimiter
	auditor                   audit.Recorder
	clock                     func() time.Time
	dummyHash                 string
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.IdentityCodec == nil || config.Receipts == nil ||
		config.Passwords == nil || config.Legal == nil || config.LoginLimiter == nil || config.Auditor == nil {
		return nil, errors.New("account service dependencies are required")
	}
	if config.DirectRegistration && config.DirectRegistrationLimiter == nil {
		return nil, errors.New("direct registration limiter is required")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	dummyHash, _, err := config.Passwords.Hash(dummyPassword)
	if err != nil {
		return nil, errors.New("account password verifier could not be initialized")
	}
	return &Service{
		repository: config.Repository, identity: config.IdentityCodec, receipts: config.Receipts,
		passwords: config.Passwords, legal: config.Legal, loginLimiter: config.LoginLimiter,
		directRegistration: config.DirectRegistration, directRegistrationLimiter: config.DirectRegistrationLimiter,
		auditor: config.Auditor, clock: clock, dummyHash: dummyHash,
	}, nil
}

func (s *Service) Register(ctx context.Context, command RegisterCommand) (Registration, error) {
	if s == nil || s.legal.Validate(command.TermsVersion, command.PrivacyVersion) != nil {
		return Registration{}, ErrInvalidRequest
	}
	var (
		claims verification.ReceiptClaims
		direct bool
		err    error
	)
	if s.directRegistration {
		if command.Kind != secure.IdentityEmail || strings.TrimSpace(command.Identity) == "" ||
			command.VerificationReceipt != "" {
			return Registration{}, ErrInvalidRequest
		}
		normalized, normalizeErr := secure.NormalizeIdentity(command.Kind, command.Identity)
		if normalizeErr != nil {
			return Registration{}, ErrInvalidRequest
		}
		allowed, limiterErr := s.directRegistrationLimiter.Allow(ctx, loginIPAddress(ctx))
		if limiterErr != nil || !allowed {
			return Registration{}, ErrServiceUnavailable
		}
		claims = verification.ReceiptClaims{
			Kind: command.Kind, NormalizedIdentity: normalized, Purpose: verification.PurposeRegistration,
		}
		direct = true
	} else {
		if strings.TrimSpace(command.Identity) != "" {
			return Registration{}, ErrInvalidRequest
		}
		claims, err = s.receipts.Parse(command.VerificationReceipt, verification.PurposeRegistration)
		if err != nil || claims.Kind != command.Kind {
			return Registration{}, ErrVerificationRequired
		}
	}
	nickname, ok := normalizeNickname(command.Nickname)
	if !ok {
		return Registration{}, ErrInvalidRequest
	}
	passwordHash, paramsVersion, err := s.passwords.Hash(command.Password)
	if err != nil {
		return Registration{}, ErrInvalidRequest
	}
	sealed, err := s.identity.Seal(claims.Kind, claims.NormalizedIdentity)
	if err != nil {
		return Registration{}, ErrServiceUnavailable
	}
	identifiers, err := randomUUIDs(6)
	if err != nil {
		return Registration{}, ErrServiceUnavailable
	}
	record := RegistrationRecord{
		ReceiptClaims: claims, Direct: direct,
		UserID: identifiers[0], IdentityID: identifiers[1], PersonalSpaceID: identifiers[2],
		TermsAcceptanceID: identifiers[3], PrivacyAcceptanceID: identifiers[4], AuditEventID: identifiers[5],
		Nickname: nickname, SealedIdentity: sealed, PasswordHash: passwordHash, PasswordParamsVersion: paramsVersion,
		TermsVersion: command.TermsVersion, PrivacyVersion: command.PrivacyVersion, CreatedAt: s.clock().UTC(),
	}
	registration, err := s.repository.Register(ctx, record)
	if err == nil {
		return registration, nil
	}
	switch {
	case errors.Is(err, ErrReceiptUnavailable):
		return Registration{}, ErrVerificationRequired
	case errors.Is(err, ErrIdentityConflict):
		return Registration{}, ErrIdentityConflict
	default:
		return Registration{}, ErrServiceUnavailable
	}
}

func (s *Service) AuthenticatePassword(ctx context.Context, rawIdentity, password string) (Principal, error) {
	kind := identityKindForLogin(rawIdentity)
	normalized, normalizationErr := secure.NormalizeIdentity(kind, rawIdentity)
	lookupCandidates := s.identity.LookupCandidates(kind, normalized)
	limiterHMAC := invalidLoginLookupHMAC()
	if len(lookupCandidates) > 0 {
		limiterHMAC = lookupCandidates[0].HMAC
	}
	allowed, limiterErr := s.loginLimiter.Allow(ctx, limiterHMAC, loginIPAddress(ctx))
	if limiterErr != nil {
		return Principal{}, ErrServiceUnavailable
	}

	var credential Credential
	found := false
	var repositoryErr error
	if normalizationErr == nil && allowed {
		credential, found, repositoryErr = s.repository.FindCredential(ctx, kind, lookupCandidates)
	}
	encodedHash := s.dummyHash
	if found && repositoryErr == nil {
		encodedHash = credential.PasswordHash
	}
	valid, needsRehash, verifyErr := s.passwords.Verify(password, encodedHash)
	if repositoryErr != nil || verifyErr != nil {
		return Principal{}, ErrServiceUnavailable
	}
	if normalizationErr != nil || !allowed || !found || !valid {
		s.recordLoginAudit(ctx, nil, audit.OutcomeFailure, "invalid_credentials")
		return Principal{}, ErrInvalidCredentials
	}

	switch credential.Status {
	case "active":
	case "pending_deletion":
		s.recordLoginAudit(ctx, &credential.UserID, audit.OutcomeDenied, "account_pending_deletion")
		return Principal{}, ErrAccountPendingDeletion
	case "disabled":
		s.recordLoginAudit(ctx, &credential.UserID, audit.OutcomeDenied, "account_disabled")
		return Principal{}, ErrAccountDisabled
	default:
		return Principal{}, ErrServiceUnavailable
	}
	if needsRehash {
		hash, version, err := s.passwords.Hash(password)
		if err != nil || s.repository.UpdatePasswordHash(ctx, credential.UserID, hash, version, s.clock().UTC()) != nil {
			return Principal{}, ErrServiceUnavailable
		}
	}
	if err := s.recordLoginAudit(ctx, &credential.UserID, audit.OutcomeSuccess, ""); err != nil {
		return Principal{}, ErrServiceUnavailable
	}
	return Principal{UserID: credential.UserID, PersonalSpaceID: credential.PersonalSpaceID, Nickname: credential.Nickname}, nil
}

// AuthenticateVerification validates a login-purpose verification receipt
// without consuming it. The HTTP layer completes the receipt only after the
// browser session store has accepted the new session.
func (s *Service) AuthenticateVerification(ctx context.Context, verificationReceipt string) (Principal, error) {
	claims, err := s.receipts.Parse(verificationReceipt, verification.PurposeLogin)
	if err != nil {
		s.recordLoginAudit(ctx, nil, audit.OutcomeFailure, "invalid_credentials")
		return Principal{}, ErrVerificationRequired
	}
	lookupCandidates := s.identity.LookupCandidates(claims.Kind, claims.NormalizedIdentity)
	limiterHMAC := invalidLoginLookupHMAC()
	if len(lookupCandidates) > 0 {
		limiterHMAC = lookupCandidates[0].HMAC
	}
	allowed, limiterErr := s.loginLimiter.Allow(ctx, limiterHMAC, loginIPAddress(ctx))
	if limiterErr != nil {
		return Principal{}, ErrServiceUnavailable
	}
	if !allowed {
		s.recordLoginAudit(ctx, nil, audit.OutcomeFailure, "invalid_credentials")
		return Principal{}, ErrInvalidCredentials
	}
	credential, found, repositoryErr := s.repository.FindCredential(ctx, claims.Kind, lookupCandidates)
	if repositoryErr != nil {
		return Principal{}, ErrServiceUnavailable
	}
	if !found {
		s.recordLoginAudit(ctx, nil, audit.OutcomeFailure, "account_not_found")
		return Principal{}, ErrAccountNotFound
	}
	switch credential.Status {
	case "active":
	case "pending_deletion":
		s.recordLoginAudit(ctx, &credential.UserID, audit.OutcomeDenied, "account_pending_deletion")
		return Principal{}, ErrAccountPendingDeletion
	case "disabled":
		s.recordLoginAudit(ctx, &credential.UserID, audit.OutcomeDenied, "account_disabled")
		return Principal{}, ErrAccountDisabled
	default:
		return Principal{}, ErrServiceUnavailable
	}
	return Principal{UserID: credential.UserID, PersonalSpaceID: credential.PersonalSpaceID, Nickname: credential.Nickname}, nil
}

// CompleteVerificationLogin atomically consumes the receipt and records the
// successful browser login after the browser session has been staged.
func (s *Service) CompleteVerificationLogin(
	ctx context.Context,
	verificationReceipt string,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return ErrInvalidRequest
	}
	claims, err := s.receipts.Parse(
		verificationReceipt,
		verification.PurposeLogin,
	)
	if err != nil {
		return ErrVerificationRequired
	}
	identifiers, err := randomUUIDs(1)
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.ConsumeLoginReceipt(ctx, LoginReceiptRecord{
		ReceiptClaims: claims,
		UserID:        userID,
		AuditEventID:  identifiers[0],
		ConsumedAt:    s.clock().UTC(),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrReceiptUnavailable):
		return ErrVerificationRequired
	case errors.Is(err, ErrInvalidCredentials):
		return ErrInvalidCredentials
	case errors.Is(err, ErrAccountPendingDeletion):
		return ErrAccountPendingDeletion
	case errors.Is(err, ErrAccountDisabled):
		return ErrAccountDisabled
	default:
		return ErrServiceUnavailable
	}
}

func (s *Service) ResetPassword(ctx context.Context, verificationReceipt, password string) error {
	claims, err := s.receipts.Parse(verificationReceipt, verification.PurposePasswordReset)
	if err != nil {
		return ErrVerificationRequired
	}
	passwordHash, paramsVersion, err := s.passwords.Hash(password)
	if err != nil {
		return ErrInvalidRequest
	}
	auditEventID, err := uuid.NewRandom()
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.ResetPassword(ctx, PasswordResetRecord{
		ReceiptClaims: claims, PasswordHash: passwordHash, PasswordParamsVersion: paramsVersion,
		AuditEventID: auditEventID, ChangedAt: s.clock().UTC(),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrReceiptUnavailable), errors.Is(err, ErrAccountNotFound):
		return ErrVerificationRequired
	default:
		return ErrServiceUnavailable
	}
}

func (s *Service) BindIdentity(ctx context.Context, userID uuid.UUID, currentPassword, verificationReceipt string) error {
	if userID == uuid.Nil {
		return ErrInvalidRequest
	}
	if _, err := s.reauthenticateUser(ctx, userID, currentPassword, "active"); err != nil {
		return err
	}
	claims, err := s.receipts.Parse(verificationReceipt, verification.PurposeBindIdentity)
	if err != nil {
		return ErrVerificationRequired
	}
	sealed, err := s.identity.Seal(claims.Kind, claims.NormalizedIdentity)
	if err != nil {
		return ErrServiceUnavailable
	}
	identifiers, err := randomUUIDs(2)
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.BindIdentity(ctx, IdentityBindingRecord{
		ReceiptClaims: claims, UserID: userID, IdentityID: identifiers[0], AuditEventID: identifiers[1],
		SealedIdentity: sealed, CreatedAt: s.clock().UTC(),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrReceiptUnavailable):
		return ErrVerificationRequired
	case errors.Is(err, ErrIdentityConflict):
		return ErrIdentityConflict
	case errors.Is(err, ErrAccountNotFound):
		return ErrInvalidRequest
	default:
		return ErrServiceUnavailable
	}
}

func (s *Service) recordLoginAudit(ctx context.Context, actorUserID *uuid.UUID, outcome audit.Outcome, reasonCode string) error {
	return s.auditor.Record(ctx, audit.Event{
		EventType: "browser_login", ActorUserID: actorUserID, Outcome: outcome,
		ReasonCode: reasonCode, OccurredAt: s.clock().UTC(),
	})
}

func normalizeNickname(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 80 {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return value, true
}

func identityKindForLogin(raw string) secure.IdentityKind {
	if strings.Contains(raw, "@") {
		return secure.IdentityEmail
	}
	return secure.IdentityPhone
}

func invalidLoginLookupHMAC() []byte {
	digest := sha256.Sum256([]byte("agentera.invalid-login-identity.v1"))
	return digest[:]
}

func randomUUIDs(count int) ([]uuid.UUID, error) {
	identifiers := make([]uuid.UUID, count)
	for index := range identifiers {
		generated, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		identifiers[index] = generated
	}
	return identifiers, nil
}

type loginIPAddressKey struct{}

func WithLoginIPAddress(ctx context.Context, ipAddress string) context.Context {
	return context.WithValue(ctx, loginIPAddressKey{}, strings.TrimSpace(ipAddress))
}

func loginIPAddress(ctx context.Context) string {
	value, _ := ctx.Value(loginIPAddressKey{}).(string)
	return value
}
