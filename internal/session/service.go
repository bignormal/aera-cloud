package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/entitlement"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const refreshLifetime = 30 * 24 * time.Hour

var (
	ErrSessionRevoked = errors.New("session is revoked")
	ErrUnavailable    = errors.New("session service is unavailable")
)

type Binding struct {
	UserID          uuid.UUID
	DeviceID        uuid.UUID
	InstallationID  uuid.UUID
	PersonalSpaceID uuid.UUID
}

type TokenSet struct {
	AccessToken        string    `json:"access_token"`
	AccessExpiresAt    time.Time `json:"access_expires_at"`
	RefreshToken       string    `json:"refresh_token"`
	RefreshExpiresAt   time.Time `json:"refresh_expires_at"`
	OfflineEntitlement string    `json:"offline_entitlement"`
	OfflineExpiresAt   time.Time `json:"offline_expires_at"`
	UserID             uuid.UUID `json:"user_id"`
	PersonalSpaceID    uuid.UUID `json:"personal_space_id"`
	DeviceID           uuid.UUID `json:"device_id"`
	SessionID          uuid.UUID `json:"-"`
}

type CreateRecord struct {
	SessionID        uuid.UUID
	FamilyID         uuid.UUID
	Binding          Binding
	RefreshTokenHash []byte
	IssuedAt         time.Time
	ExpiresAt        time.Time
}

type SuccessorRecord struct {
	SessionID        uuid.UUID
	RefreshTokenHash []byte
	IssuedAt         time.Time
	ExpiresAt        time.Time
}

type Rotation struct {
	SessionID uuid.UUID
	FamilyID  uuid.UUID
	Binding   Binding
}

type Repository interface {
	Create(context.Context, CreateRecord) error
	CreateInTx(context.Context, pgx.Tx, CreateRecord) error
	Rotate(context.Context, []byte, SuccessorRecord, time.Time) (Rotation, error)
	RevokeFamily(context.Context, uuid.UUID, string, time.Time) error
	RevokeByToken(context.Context, []byte, time.Time) error
}

type AccessTokenIssuer interface {
	Issue(AccessBinding) (IssuedAccessToken, error)
}

type OfflineEntitlementIssuer interface {
	Issue(context.Context, entitlement.Binding) (entitlement.Issued, error)
	IssueInTx(context.Context, pgx.Tx, entitlement.Binding) (entitlement.Issued, error)
}

type ServiceConfig struct {
	Repository          Repository
	AccessTokens        AccessTokenIssuer
	OfflineEntitlements OfflineEntitlementIssuer
	RefreshHMACKey      []byte
	Clock               func() time.Time
}

type Service struct {
	repository          Repository
	accessTokens        AccessTokenIssuer
	offlineEntitlements OfflineEntitlementIssuer
	refreshHMACKey      []byte
	clock               func() time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.AccessTokens == nil || config.OfflineEntitlements == nil || len(config.RefreshHMACKey) < 32 {
		return nil, errors.New("session service configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		repository: config.Repository, accessTokens: config.AccessTokens,
		offlineEntitlements: config.OfflineEntitlements,
		refreshHMACKey:      append([]byte(nil), config.RefreshHMACKey...), clock: clock,
	}, nil
}

func (s *Service) Start(ctx context.Context, binding Binding) (TokenSet, error) {
	rotation, refreshToken, expiresAt, record, err := s.prepareStart(binding)
	if err != nil {
		return TokenSet{}, err
	}
	if err := s.repository.Create(ctx, record); err != nil {
		return TokenSet{}, err
	}
	return s.issueTokenSet(ctx, rotation, refreshToken, expiresAt, s.offlineEntitlements.Issue, true)
}

func (s *Service) StartInTx(ctx context.Context, tx pgx.Tx, binding Binding) (TokenSet, error) {
	if tx == nil {
		return TokenSet{}, ErrUnavailable
	}
	rotation, refreshToken, expiresAt, record, err := s.prepareStart(binding)
	if err != nil {
		return TokenSet{}, err
	}
	if err := s.repository.CreateInTx(ctx, tx, record); err != nil {
		return TokenSet{}, err
	}
	return s.issueTokenSet(ctx, rotation, refreshToken, expiresAt, func(ctx context.Context, binding entitlement.Binding) (entitlement.Issued, error) {
		return s.offlineEntitlements.IssueInTx(ctx, tx, binding)
	}, false)
}

func (s *Service) prepareStart(binding Binding) (Rotation, string, time.Time, CreateRecord, error) {
	if s == nil || !validBinding(binding) {
		return Rotation{}, "", time.Time{}, CreateRecord{}, ErrSessionRevoked
	}
	sessionID, err := secure.RandomUUID()
	if err != nil {
		return Rotation{}, "", time.Time{}, CreateRecord{}, ErrUnavailable
	}
	familyID, err := secure.RandomUUID()
	if err != nil {
		return Rotation{}, "", time.Time{}, CreateRecord{}, ErrUnavailable
	}
	refreshToken, refreshHash, err := s.newRefreshToken()
	if err != nil {
		return Rotation{}, "", time.Time{}, CreateRecord{}, ErrUnavailable
	}
	issuedAt := s.clock().UTC()
	expiresAt := issuedAt.Add(refreshLifetime)
	record := CreateRecord{
		SessionID: sessionID, FamilyID: familyID, Binding: binding, RefreshTokenHash: refreshHash,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	return Rotation{SessionID: sessionID, FamilyID: familyID, Binding: binding}, refreshToken, expiresAt, record, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (TokenSet, error) {
	secret, err := base64.RawURLEncoding.DecodeString(refreshToken)
	if err != nil || len(secret) != 32 {
		return TokenSet{}, ErrSessionRevoked
	}
	successorToken, successorHash, err := s.newRefreshToken()
	if err != nil {
		return TokenSet{}, ErrUnavailable
	}
	sessionID, err := secure.RandomUUID()
	if err != nil {
		return TokenSet{}, ErrUnavailable
	}
	now := s.clock().UTC()
	expiresAt := now.Add(refreshLifetime)
	rotation, err := s.repository.Rotate(ctx, s.refreshHash(secret), SuccessorRecord{
		SessionID: sessionID, RefreshTokenHash: successorHash, IssuedAt: now, ExpiresAt: expiresAt,
	}, now)
	if err != nil {
		return TokenSet{}, err
	}
	return s.issueTokenSet(ctx, rotation, successorToken, expiresAt, s.offlineEntitlements.Issue, true)
}

func (s *Service) Revoke(ctx context.Context, refreshToken string) error {
	secret, err := base64.RawURLEncoding.DecodeString(refreshToken)
	if s == nil || err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != refreshToken {
		return ErrSessionRevoked
	}
	return s.repository.RevokeByToken(ctx, s.refreshHash(secret), s.clock().UTC())
}

func (s *Service) issueTokenSet(
	ctx context.Context,
	rotation Rotation,
	refreshToken string,
	refreshExpiresAt time.Time,
	issueOffline func(context.Context, entitlement.Binding) (entitlement.Issued, error),
	revokeOnFailure bool,
) (TokenSet, error) {
	access, err := s.accessTokens.Issue(AccessBinding{
		UserID: rotation.Binding.UserID, SessionID: rotation.SessionID,
		DeviceID: rotation.Binding.DeviceID, PersonalSpaceID: rotation.Binding.PersonalSpaceID,
	})
	if err != nil {
		if revokeOnFailure {
			_ = s.repository.RevokeFamily(ctx, rotation.FamilyID, "token_issuance_failed", s.clock().UTC())
		}
		return TokenSet{}, ErrUnavailable
	}
	offline, err := issueOffline(ctx, entitlement.Binding{
		UserID: rotation.Binding.UserID, DeviceID: rotation.Binding.DeviceID,
		InstallationID: rotation.Binding.InstallationID, PersonalSpaceID: rotation.Binding.PersonalSpaceID,
	})
	if err != nil {
		if revokeOnFailure {
			_ = s.repository.RevokeFamily(ctx, rotation.FamilyID, "token_issuance_failed", s.clock().UTC())
		}
		return TokenSet{}, ErrUnavailable
	}
	return TokenSet{
		AccessToken: access.Serialized, AccessExpiresAt: access.ExpiresAt,
		RefreshToken: refreshToken, RefreshExpiresAt: refreshExpiresAt,
		OfflineEntitlement: offline.Serialized, OfflineExpiresAt: offline.ExpiresAt,
		UserID: rotation.Binding.UserID, PersonalSpaceID: rotation.Binding.PersonalSpaceID,
		DeviceID: rotation.Binding.DeviceID, SessionID: rotation.SessionID,
	}, nil
}

func (s *Service) newRefreshToken() (string, []byte, error) {
	secret, err := secure.RandomBytes(32)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(secret), s.refreshHash(secret), nil
}

func (s *Service) refreshHash(secret []byte) []byte {
	mac := hmac.New(sha256.New, s.refreshHMACKey)
	_, _ = mac.Write([]byte("agentera.refresh-token.v1\x00"))
	_, _ = mac.Write(secret)
	return mac.Sum(nil)
}

func validBinding(binding Binding) bool {
	return binding.UserID != uuid.Nil && binding.DeviceID != uuid.Nil &&
		binding.InstallationID != uuid.Nil && binding.PersonalSpaceID != uuid.Nil
}
