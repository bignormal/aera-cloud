package account

import (
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
)

var (
	ErrInvalidRequest                    = errors.New("account request is invalid")
	ErrVerificationRequired              = errors.New("identity verification is required")
	ErrIdentityConflict                  = errors.New("identity is already registered")
	ErrInvalidCredentials                = errors.New("credentials are invalid")
	ErrAccountPendingDeletion            = errors.New("account is pending deletion")
	ErrAccountDisabled                   = errors.New("account is disabled")
	ErrServiceUnavailable                = errors.New("account service is unavailable")
	ErrReceiptUnavailable                = errors.New("verification receipt is unavailable")
	ErrAccountNotFound                   = errors.New("account was not found")
	ErrLastIdentity                      = errors.New("the last login identity cannot be removed")
	ErrDeletionWindowExpired             = errors.New("account deletion recovery window expired")
	ErrOrganizationOwnerTransferRequired = errors.New("organization ownership must be transferred before account deletion")
)

type OrganizationOwnerTransferRequiredError struct {
	OwnedOrganizationCount int
}

func (e *OrganizationOwnerTransferRequiredError) Error() string {
	return ErrOrganizationOwnerTransferRequired.Error()
}

func (e *OrganizationOwnerTransferRequiredError) Unwrap() error {
	return ErrOrganizationOwnerTransferRequired
}

type RegisterCommand struct {
	Kind                secure.IdentityKind
	Identity            string
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

// Profile contains only account-center metadata. Login identity values remain
// encrypted in storage and are never returned by this API.
type Profile struct {
	UserID              uuid.UUID             `json:"user_id"`
	PersonalSpaceID     uuid.UUID             `json:"personal_space_id"`
	Nickname            string                `json:"nickname,omitempty"`
	Status              string                `json:"status"`
	IdentityKinds       []secure.IdentityKind `json:"identity_kinds"`
	OwnedWorkspaceCount int                   `json:"owned_workspace_count"`
}

type RegistrationRecord struct {
	ReceiptClaims         verification.ReceiptClaims
	Direct                bool
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

type LoginReceiptRecord struct {
	ReceiptClaims verification.ReceiptClaims
	UserID        uuid.UUID
	AuditEventID  uuid.UUID
	ConsumedAt    time.Time
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

type IdentityRemovalRecord struct {
	UserID       uuid.UUID
	Kind         secure.IdentityKind
	AuditEventID uuid.UUID
	RemovedAt    time.Time
}

type PasswordChangeRecord struct {
	UserID                uuid.UUID
	CurrentSessionID      uuid.UUID
	PasswordHash          string
	PasswordParamsVersion int
	AuditEventID          uuid.UUID
	ChangedAt             time.Time
}

type DeletionRequestRecord struct {
	ReceiptClaims verification.ReceiptClaims
	UserID        uuid.UUID
	AuditEventID  uuid.UUID
	RequestedAt   time.Time
}

type DeletionRecoveryRecord struct {
	ReceiptClaims verification.ReceiptClaims
	UserID        uuid.UUID
	AuditEventID  uuid.UUID
	RecoveredAt   time.Time
}
