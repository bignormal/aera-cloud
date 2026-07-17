package device

import (
	"context"
	"crypto/ed25519"
	"errors"
	"regexp"
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
