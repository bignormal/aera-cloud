package account

import (
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
)

var (
	ErrInvalidRequest         = errors.New("account request is invalid")
	ErrVerificationRequired   = errors.New("identity verification is required")
	ErrIdentityConflict       = errors.New("identity is already registered")
	ErrInvalidCredentials     = errors.New("credentials are invalid")
	ErrAccountPendingDeletion = errors.New("account is pending deletion")
	ErrAccountDisabled        = errors.New("account is disabled")
	ErrServiceUnavailable     = errors.New("account service is unavailable")
	ErrReceiptUnavailable     = errors.New("verification receipt is unavailable")
	ErrAccountNotFound        = errors.New("account was not found")
)

type RegisterCommand struct {
	Kind                secure.IdentityKind
	VerificationReceipt string
	Password            string
	Nickname            string
	TermsVersion        string
	PrivacyVersion      string
}

type Registration struct {
	UserID          uuid.UUID `json:"user_id"`
	PersonalSpaceID uuid.UUID `json:"personal_space_id"`
}

type Principal struct {
	UserID          uuid.UUID
	PersonalSpaceID uuid.UUID
	Nickname        string
}

type RegistrationRecord struct {
	ReceiptClaims         verification.ReceiptClaims
	UserID                uuid.UUID
	IdentityID            uuid.UUID
	PersonalSpaceID       uuid.UUID
	TermsAcceptanceID     uuid.UUID
	PrivacyAcceptanceID   uuid.UUID
	AuditEventID          uuid.UUID
	Nickname              string
	SealedIdentity        secure.SealedIdentity
	PasswordHash          string
	PasswordParamsVersion int
	TermsVersion          string
	PrivacyVersion        string
	CreatedAt             time.Time
}

type Credential struct {
	UserID          uuid.UUID
	PersonalSpaceID uuid.UUID
	Nickname        string
	Status          string
	PasswordHash    string
	ParamsVersion   int
}

type PasswordResetRecord struct {
	ReceiptClaims         verification.ReceiptClaims
	PasswordHash          string
	PasswordParamsVersion int
	AuditEventID          uuid.UUID
	ChangedAt             time.Time
}

type IdentityBindingRecord struct {
	ReceiptClaims  verification.ReceiptClaims
	UserID         uuid.UUID
	IdentityID     uuid.UUID
	AuditEventID   uuid.UUID
	SealedIdentity secure.SealedIdentity
	CreatedAt      time.Time
}
