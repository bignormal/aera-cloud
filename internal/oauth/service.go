package oauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/device"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	authorizationRequestLifetime = 10 * time.Minute
	authorizationCodeLifetime    = 2 * time.Minute
)

type Repository interface {
	Save(context.Context, AuthorizationRecord) error
	Approve(context.Context, ApprovalRecord) (ApprovedRequest, error)
	Exchange(
		context.Context,
		[]byte,
		time.Time,
		func(context.Context, pgx.Tx, Grant) (session.TokenSet, error),
	) (session.TokenSet, error)
}

type DeviceAuthorizer interface {
	AuthorizeInTx(context.Context, pgx.Tx, device.AuthorizeCommand) (device.Device, error)
}

type SessionStarter interface {
	StartInTx(context.Context, pgx.Tx, session.Binding) (session.TokenSet, error)
}

type ServiceConfig struct {
	Repository          Repository
	Devices             DeviceAuthorizer
	Sessions            SessionStarter
	ActiveStateKeyID    string
	StateEncryptionKeys map[string][]byte
	StateHMACKey        []byte
	Clock               func() time.Time
}

type Service struct {
	repository       Repository
	devices          DeviceAuthorizer
	sessions         SessionStarter
	activeStateKeyID string
	stateKeys        map[string][]byte
	stateHMACKey     []byte
	clock            func() time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.Devices == nil || config.Sessions == nil ||
		strings.TrimSpace(config.ActiveStateKeyID) == "" || len(config.StateHMACKey) < 32 {
		return nil, errors.New("OAuth service configuration is invalid")
	}
	keys := make(map[string][]byte, len(config.StateEncryptionKeys))
	for keyID, key := range config.StateEncryptionKeys {
		if strings.TrimSpace(keyID) == "" || len(key) != 32 {
			return nil, errors.New("OAuth state encryption key is invalid")
		}
		keys[keyID] = append([]byte(nil), key...)
	}
	if _, ok := keys[config.ActiveStateKeyID]; !ok {
		return nil, errors.New("active OAuth state encryption key is unavailable")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		repository: config.Repository, devices: config.Devices, sessions: config.Sessions,
		activeStateKeyID: config.ActiveStateKeyID, stateKeys: keys,
		stateHMACKey: append([]byte(nil), config.StateHMACKey...), clock: clock,
	}, nil
}

func (s *Service) Begin(ctx context.Context, request BeginRequest) (BeginResponse, error) {
	if s == nil || !validBeginRequest(request) {
		return BeginResponse{}, ErrInvalidRequest
	}
	requestID, err := secure.RandomUUID()
	if err != nil {
		return BeginResponse{}, ErrUnavailable
	}
	nonce, ciphertext, err := s.encryptState(requestID, request.State)
	if err != nil {
		return BeginResponse{}, ErrUnavailable
	}
	now := s.clock().UTC()
	expiresAt := now.Add(authorizationRequestLifetime)
	deviceKeyDigest := sha256.Sum256(request.DevicePublicKey)
	record := AuthorizationRecord{
		ID: requestID, ClientID: request.ClientID, RedirectURI: request.RedirectURI,
		CodeChallenge: request.CodeChallenge, CodeChallengeMethod: request.CodeChallengeMethod,
		StateEncryptionKeyID: s.activeStateKeyID, StateNonce: nonce, StateCiphertext: ciphertext,
		StateHash: s.stateHash(request.State), InstallationID: request.InstallationID,
		DevicePublicKey: append([]byte(nil), request.DevicePublicKey...), DeviceKeyDigest: deviceKeyDigest[:],
		DeviceDisplayName: strings.TrimSpace(request.DeviceDisplayName), DevicePlatform: request.DevicePlatform,
		AppVersion: request.AppVersion, ExpiresAt: expiresAt, CreatedAt: now,
	}
	if err := s.repository.Save(ctx, record); err != nil {
		return BeginResponse{}, ErrUnavailable
	}
	return BeginResponse{RequestID: requestID, ExpiresAt: expiresAt}, nil
}

func (s *Service) Approve(ctx context.Context, requestID, userID uuid.UUID) (ApprovalResponse, error) {
	if s == nil || requestID == uuid.Nil || userID == uuid.Nil {
		return ApprovalResponse{}, ErrInvalidRequest
	}
	codeSecret, err := secure.RandomBytes(32)
	if err != nil {
		return ApprovalResponse{}, ErrUnavailable
	}
	codeID, err := secure.RandomUUID()
	if err != nil {
		return ApprovalResponse{}, ErrUnavailable
	}
	now := s.clock().UTC()
	approved, err := s.repository.Approve(ctx, ApprovalRecord{
		RequestID: requestID, UserID: userID, CodeID: codeID, CodeHash: authorizationCodeHash(codeSecret),
		CodeExpiresAt: now.Add(authorizationCodeLifetime), ApprovedAt: now,
	})
	if err != nil {
		return ApprovalResponse{}, err
	}
	state, err := s.decryptState(approved.AuthorizationRecord)
	if err != nil {
		return ApprovalResponse{}, ErrUnavailable
	}
	redirect, err := url.Parse(approved.RedirectURI)
	if err != nil || !validRedirectURI(approved.RedirectURI) {
		return ApprovalResponse{}, ErrUnavailable
	}
	query := redirect.Query()
	query.Set("code", base64.RawURLEncoding.EncodeToString(codeSecret))
	query.Set("state", state)
	redirect.RawQuery = query.Encode()
	return ApprovalResponse{RedirectURI: redirect.String()}, nil
}

func (s *Service) Exchange(ctx context.Context, request ExchangeRequest) (session.TokenSet, error) {
	codeSecret, ok := secure.DecodeCanonicalBase64URL(request.AuthorizationCode)
	if s == nil || !ok || len(codeSecret) != 32 || request.InstallationID == uuid.Nil {
		return session.TokenSet{}, ErrInvalidAuthorization
	}
	return s.repository.Exchange(ctx, authorizationCodeHash(codeSecret), s.clock().UTC(), func(ctx context.Context, tx pgx.Tx, grant Grant) (session.TokenSet, error) {
		if !validVerifier(request.CodeVerifier) || grant.CodeChallengeMethod != "S256" ||
			request.InstallationID != grant.InstallationID || !matchesChallenge(request.CodeVerifier, grant.CodeChallenge) ||
			len(grant.DevicePublicKey) != ed25519.PublicKeySize || len(request.DeviceProof) != ed25519.SignatureSize ||
			!ed25519.Verify(grant.DevicePublicKey, deviceProofDigest(request.AuthorizationCode, request.CodeVerifier, request.InstallationID), request.DeviceProof) {
			return session.TokenSet{}, ErrInvalidAuthorization
		}
		authorized, err := s.devices.AuthorizeInTx(ctx, tx, device.AuthorizeCommand{
			UserID: grant.UserID, InstallationID: grant.InstallationID,
			PublicKey: grant.DevicePublicKey, DisplayName: grant.DeviceDisplayName,
			Platform: grant.DevicePlatform, AppVersion: grant.AppVersion,
		})
		if err != nil {
			if errors.Is(err, device.ErrDeviceLimitReached) {
				return session.TokenSet{}, ErrDeviceLimitReached
			}
			if errors.Is(err, device.ErrUnavailable) {
				return session.TokenSet{}, ErrUnavailable
			}
			return session.TokenSet{}, ErrInvalidAuthorization
		}
		return s.sessions.StartInTx(ctx, tx, session.Binding{
			UserID: grant.UserID, DeviceID: authorized.ID, InstallationID: grant.InstallationID,
			PersonalSpaceID: grant.PersonalSpaceID,
		})
	})
}

func validBeginRequest(request BeginRequest) bool {
	if request.ClientID != DesktopClientID || request.CodeChallengeMethod != "S256" || !validRedirectURI(request.RedirectURI) ||
		request.InstallationID == uuid.Nil || len(request.DevicePublicKey) != ed25519.PublicKeySize ||
		!validOpaqueState(request.State) || !validCodeChallenge(request.CodeChallenge) ||
		!validDeviceMetadata(request.DeviceDisplayName, request.DevicePlatform, request.AppVersion) {
		return false
	}
	return true
}

func validRedirectURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" ||
		parsed.Path != "/agentera/oauth/callback" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return false
	}
	if net.ParseIP(parsed.Hostname()) == nil {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	return err == nil && port > 0 && port <= 65535 && parsed.Host == net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func validOpaqueState(state string) bool {
	if !utf8.ValidString(state) || len(state) < 16 || len(state) > 1024 {
		return false
	}
	for _, character := range state {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validCodeChallenge(challenge string) bool {
	decoded, ok := secure.DecodeCanonicalBase64URL(challenge)
	return ok && len(decoded) == sha256.Size
}

func validVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, character := range verifier {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '.' || character == '_' || character == '~') {
			return false
		}
	}
	return true
}

func matchesChallenge(verifier, challenge string) bool {
	digest := sha256.Sum256([]byte(verifier))
	candidate := base64.RawURLEncoding.EncodeToString(digest[:])
	return len(candidate) == len(challenge) && subtle.ConstantTimeCompare([]byte(candidate), []byte(challenge)) == 1
}

func validDeviceMetadata(displayName, platform, appVersion string) bool {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || utf8.RuneCountInString(displayName) > 100 ||
		(platform != "darwin" && platform != "windows" && platform != "linux") ||
		appVersion == "" || len(appVersion) > 64 {
		return false
	}
	for _, character := range displayName + appVersion {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (s *Service) encryptState(requestID uuid.UUID, state string) ([]byte, []byte, error) {
	block, err := aes.NewCipher(s.stateKeys[s.activeStateKeyID])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := secure.RandomBytes(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, []byte(state), stateAAD(requestID)), nil
}

func (s *Service) decryptState(record AuthorizationRecord) (string, error) {
	key, ok := s.stateKeys[record.StateEncryptionKeyID]
	if !ok {
		return "", ErrInvalidAuthorization
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrInvalidAuthorization
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(record.StateNonce) != aead.NonceSize() {
		return "", ErrInvalidAuthorization
	}
	plaintext, err := aead.Open(nil, record.StateNonce, record.StateCiphertext, stateAAD(record.ID))
	if err != nil {
		return "", ErrInvalidAuthorization
	}
	state := string(plaintext)
	if !validOpaqueState(state) || !hmac.Equal(s.stateHash(state), record.StateHash) {
		return "", ErrInvalidAuthorization
	}
	return state, nil
}

func (s *Service) stateHash(state string) []byte {
	mac := hmac.New(sha256.New, s.stateHMACKey)
	_, _ = mac.Write([]byte("agentera.oauth-state.v1\x00"))
	_, _ = mac.Write([]byte(state))
	return mac.Sum(nil)
}

func stateAAD(requestID uuid.UUID) []byte {
	return []byte("agentera.oauth-state.v1\x00" + requestID.String())
}

func authorizationCodeHash(code []byte) []byte {
	digest := sha256.Sum256(append([]byte("agentera.authorization-code.v1\x00"), code...))
	return digest[:]
}

func deviceProofDigest(code, verifier string, installationID uuid.UUID) []byte {
	digest := sha256.Sum256([]byte(code + "\x00" + verifier + "\x00" + installationID.String()))
	return digest[:]
}
