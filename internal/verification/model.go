package verification

import (
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
)

type Purpose string

const (
	PurposeRegistration     Purpose = "registration"
	PurposeLogin            Purpose = "login"
	PurposePasswordReset    Purpose = "password_reset"
	PurposeBindIdentity     Purpose = "bind_identity"
	PurposeAccountDeletion  Purpose = "account_deletion"
	PurposeDeletionRecovery Purpose = "deletion_recovery"
)

var (
	ErrInvalidRequest         = errors.New("verification request is invalid")
	ErrResendTooSoon          = errors.New("verification resend is not available yet")
	ErrRateLimited            = errors.New("verification rate limit exceeded")
	ErrCaptchaRequired        = errors.New("CAPTCHA verification is required")
	ErrDeliveryUnavailable    = errors.New("verification delivery is unavailable")
	ErrTemporarilyUnavailable = errors.New("verification service is temporarily unavailable")
	ErrRequestInProgress      = errors.New("verification request is already in progress")
	ErrInvalidVerification    = errors.New("verification code is invalid or expired")

	ErrChallengeNotFound = errors.New("verification challenge was not found")
	ErrCodeMismatch      = errors.New("verification code does not match")
)

type Challenge struct {
	ID                 uuid.UUID
	Purpose            Purpose
	IdentityKind       secure.IdentityKind
	TargetLookupKeyID  string
	TargetLookupHMAC   []byte
	CodeKeyID          string
	CodeHMAC           []byte
	IdempotencyKeyHash []byte
	ExpiresAt          time.Time
	ResendAfter        time.Time
	FailedAttempts     int
	ConsumedAt         *time.Time
	InvalidatedAt      *time.Time
	CreatedAt          time.Time
}

type SendRequest struct {
	Kind           secure.IdentityKind
	Destination    string
	Purpose        Purpose
	IdempotencyKey string
	IPAddress      string
	DeviceID       string
	CaptchaToken   string
}

type VerifyRequest struct {
	Kind        secure.IdentityKind
	Destination string
	Purpose     Purpose
	Code        string
}

type VerificationResult struct {
	Receipt   string
	ExpiresAt time.Time
}

type DeliveryFailureMetadata struct {
	Provider    string
	Code        string
	RequestID   string
	RateLimited bool
}

type DeliveryFailure interface {
	error
	VerificationDeliveryFailure() DeliveryFailureMetadata
}

func validPurpose(purpose Purpose) bool {
	return purpose == PurposeRegistration || purpose == PurposeLogin || purpose == PurposePasswordReset ||
		purpose == PurposeBindIdentity || purpose == PurposeAccountDeletion || purpose == PurposeDeletionRecovery
}
