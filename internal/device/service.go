package device

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidDevice      = errors.New("device request is invalid")
	ErrDeviceLimitReached = errors.New("active device limit reached")
	ErrDeviceConflict     = errors.New("device identity conflicts with an existing installation")
	ErrDeviceNotFound     = errors.New("device was not found")
	ErrAccountUnavailable = errors.New("device account is unavailable")
	ErrUnavailable        = errors.New("device service is unavailable")
	ErrSelfRevokeReplay   = errors.New("device self-revocation nonce was already used")
	versionPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
)

type Device struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	InstallationID uuid.UUID
	PublicKey      []byte
	DisplayName    string
	Platform       string
	AppVersion     string
	Status         string
	LastSeenAt     time.Time
}

type PublicDevice struct {
	ID          uuid.UUID `json:"device_id"`
	DisplayName string    `json:"display_name"`
	Platform    string    `json:"platform"`
	AppVersion  string    `json:"app_version"`
	Status      string    `json:"status"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	Current     bool      `json:"current"`
}

type SelfRevokeCommand struct {
	DeviceID       uuid.UUID
	InstallationID uuid.UUID
	Timestamp      int64
	Nonce          []byte
	Signature      []byte
}

type SelfRevocationRecord struct {
	UserID         uuid.UUID
	DeviceID       uuid.UUID
	InstallationID uuid.UUID
	NonceHash      []byte
	AuditEventID   uuid.UUID
	RevokedAt      time.Time
}

type AuthorizeCommand struct {
	UserID         uuid.UUID
	InstallationID uuid.UUID
	PublicKey      []byte
	DisplayName    string
	Platform       string
	AppVersion     string
}

type AuthorizationRecord struct {
	DeviceID       uuid.UUID
	AuditEventID   uuid.UUID
	UserID         uuid.UUID
	InstallationID uuid.UUID
	PublicKey      []byte
	DisplayName    string
	Platform       string
	AppVersion     string
	AuthorizedAt   time.Time
}

type Repository interface {
	Authorize(context.Context, AuthorizationRecord, int) (Device, error)
	AuthorizeInTx(context.Context, pgx.Tx, AuthorizationRecord, int) (Device, error)
	Revoke(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, time.Time) error
	List(context.Context, uuid.UUID) ([]Device, error)
	FindForSelfRevoke(context.Context, uuid.UUID) (Device, error)
	SelfRevoke(context.Context, SelfRevocationRecord) error
}

type ServiceConfig struct {
	Repository  Repository
	ActiveLimit int
	Clock       func() time.Time
}

type Service struct {
	repository  Repository
	activeLimit int
	clock       func() time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.ActiveLimit <= 0 || config.ActiveLimit > 20 {
		return nil, errors.New("device service configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{repository: config.Repository, activeLimit: config.ActiveLimit, clock: clock}, nil
}

func (s *Service) Authorize(ctx context.Context, command AuthorizeCommand) (Device, error) {
	record, err := s.authorizationRecord(command)
	if err != nil {
		return Device{}, err
	}
	return s.repository.Authorize(ctx, record, s.activeLimit)
}

func (s *Service) AuthorizeInTx(ctx context.Context, tx pgx.Tx, command AuthorizeCommand) (Device, error) {
	if tx == nil {
		return Device{}, ErrUnavailable
	}
	record, err := s.authorizationRecord(command)
	if err != nil {
		return Device{}, err
	}
	return s.repository.AuthorizeInTx(ctx, tx, record, s.activeLimit)
}

func (s *Service) authorizationRecord(command AuthorizeCommand) (AuthorizationRecord, error) {
	displayName, valid := cleanDisplayName(command.DisplayName)
	if s == nil || command.UserID == uuid.Nil || command.InstallationID == uuid.Nil ||
		len(command.PublicKey) != ed25519.PublicKeySize || !valid || !validPlatform(command.Platform) ||
		!versionPattern.MatchString(command.AppVersion) {
		return AuthorizationRecord{}, ErrInvalidDevice
	}
	deviceID, err := secure.RandomUUID()
	if err != nil {
		return AuthorizationRecord{}, ErrUnavailable
	}
	auditEventID, err := secure.RandomUUID()
	if err != nil {
		return AuthorizationRecord{}, ErrUnavailable
	}
	return AuthorizationRecord{
		DeviceID: deviceID, AuditEventID: auditEventID, UserID: command.UserID,
		InstallationID: command.InstallationID, PublicKey: append([]byte(nil), command.PublicKey...),
		DisplayName: displayName, Platform: command.Platform, AppVersion: command.AppVersion,
		AuthorizedAt: s.clock().UTC(),
	}, nil
}

func (s *Service) Revoke(ctx context.Context, userID, deviceID uuid.UUID) error {
	if s == nil || userID == uuid.Nil || deviceID == uuid.Nil {
		return ErrInvalidDevice
	}
	auditEventID, err := secure.RandomUUID()
	if err != nil {
		return ErrUnavailable
	}
	return s.repository.Revoke(ctx, userID, deviceID, auditEventID, s.clock().UTC())
}

func (s *Service) List(ctx context.Context, userID, currentDeviceID uuid.UUID) ([]PublicDevice, error) {
	if s == nil || userID == uuid.Nil {
		return nil, ErrInvalidDevice
	}
	devices, err := s.repository.List(ctx, userID)
	if err != nil {
		return nil, err
	}
	public := make([]PublicDevice, 0, len(devices))
	for _, found := range devices {
		if found.Status != "active" {
			continue
		}
		public = append(public, PublicDevice{
			ID: found.ID, DisplayName: found.DisplayName, Platform: found.Platform,
			AppVersion: found.AppVersion, Status: found.Status, LastSeenAt: found.LastSeenAt,
			Current: found.ID == currentDeviceID,
		})
	}
	return public, nil
}

func (s *Service) SelfRevoke(ctx context.Context, command SelfRevokeCommand) error {
	if s == nil || command.DeviceID == uuid.Nil || command.InstallationID == uuid.Nil || command.Timestamp <= 0 ||
		len(command.Nonce) != 32 || len(command.Signature) != ed25519.SignatureSize {
		return ErrInvalidDevice
	}
	now := s.clock().UTC()
	delta := now.Sub(time.Unix(command.Timestamp, 0).UTC())
	if delta < -2*time.Minute || delta > 2*time.Minute {
		return ErrInvalidDevice
	}
	found, err := s.repository.FindForSelfRevoke(ctx, command.DeviceID)
	if err != nil {
		return err
	}
	if found.ID != command.DeviceID || found.InstallationID != command.InstallationID ||
		len(found.PublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(found.PublicKey, selfRevokeDigest(command), command.Signature) {
		return ErrInvalidDevice
	}
	nonceHash := sha256.Sum256(append([]byte("agentera-self-revoke-nonce.v1\x00"), command.Nonce...))
	auditEventID, err := secure.RandomUUID()
	if err != nil {
		return ErrUnavailable
	}
	return s.repository.SelfRevoke(ctx, SelfRevocationRecord{
		UserID: found.UserID, DeviceID: found.ID, InstallationID: found.InstallationID,
		NonceHash: nonceHash[:], AuditEventID: auditEventID, RevokedAt: now,
	})
}

func selfRevokeDigest(command SelfRevokeCommand) []byte {
	message := []byte("agentera-self-revoke\x00" + command.DeviceID.String() + "\x00" +
		command.InstallationID.String() + "\x00" + strconv.FormatInt(command.Timestamp, 10) + "\x00")
	message = append(message, command.Nonce...)
	digest := sha256.Sum256(message)
	return digest[:]
}

func cleanDisplayName(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 100 {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return value, true
}

func validPlatform(platform string) bool {
	return platform == "darwin" || platform == "windows" || platform == "linux"
}
