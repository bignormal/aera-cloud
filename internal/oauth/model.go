package oauth

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const DesktopClientID = "agentera-studio"

var (
	ErrInvalidRequest        = errors.New("OAuth request is invalid")
	ErrInvalidAuthorization  = errors.New("OAuth authorization is invalid or expired")
	ErrAuthorizationReplayed = errors.New("OAuth authorization was already consumed")
	ErrDeviceLimitReached    = errors.New("active device limit reached")
	ErrDeviceConflict        = errors.New("device identity conflicts with another owner")
	ErrUnavailable           = errors.New("OAuth service is unavailable")
)

type BeginRequest struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	InstallationID      uuid.UUID
	DevicePublicKey     []byte
	DeviceDisplayName   string
	DevicePlatform      string
	AppVersion          string
}

type BeginResponse struct {
	RequestID uuid.UUID
	ExpiresAt time.Time
}

type ApprovalResponse struct {
	RedirectURI string
}

type ExchangeRequest struct {
	AuthorizationCode string
	CodeVerifier      string
	InstallationID    uuid.UUID
	DeviceProof       []byte
}

type AuthorizationRecord struct {
	ID                   uuid.UUID
	ClientID             string
	RedirectURI          string
	CodeChallenge        string
	CodeChallengeMethod  string
	StateEncryptionKeyID string
	StateNonce           []byte
	StateCiphertext      []byte
	StateHash            []byte
	InstallationID       uuid.UUID
	DevicePublicKey      []byte
	DeviceKeyDigest      []byte
	DeviceDisplayName    string
	DevicePlatform       string
	AppVersion           string
	ExpiresAt            time.Time
	CreatedAt            time.Time
}

type ApprovalRecord struct {
	RequestID     uuid.UUID
	UserID        uuid.UUID
	CodeID        uuid.UUID
	CodeHash      []byte
	CodeExpiresAt time.Time
	ApprovedAt    time.Time
}

type ApprovedRequest struct {
	AuthorizationRecord
}

type Grant struct {
	AuthorizationRecord
	UserID          uuid.UUID
	PersonalSpaceID uuid.UUID
}
