package account

import (
	"context"
	"errors"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
)

func (s *Service) Profile(ctx context.Context, userID uuid.UUID) (Profile, error) {
	if s == nil || userID == uuid.Nil {
		return Profile{}, ErrInvalidRequest
	}
	profile, found, err := s.repository.Profile(ctx, userID)
	if err != nil {
		return Profile{}, ErrServiceUnavailable
	}
	if !found || profile.Status != "active" {
		return Profile{}, ErrAccountNotFound
	}
	return profile, nil
}

func (s *Service) RemoveIdentity(
	ctx context.Context,
	userID uuid.UUID,
	kind secure.IdentityKind,
	currentPassword string,
) error {
	if userID == uuid.Nil || (kind != secure.IdentityEmail && kind != secure.IdentityPhone) {
		return ErrInvalidRequest
	}
	if _, err := s.reauthenticateUser(ctx, userID, currentPassword, "active"); err != nil {
		return err
	}
	identifiers, err := randomUUIDs(1)
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.RemoveIdentity(ctx, IdentityRemovalRecord{
		UserID: userID, Kind: kind, AuditEventID: identifiers[0], RemovedAt: s.clock().UTC(),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrLastIdentity):
		return ErrLastIdentity
	case errors.Is(err, ErrAccountNotFound):
		return ErrInvalidRequest
	default:
		return ErrServiceUnavailable
	}
}

func (s *Service) ChangePassword(
	ctx context.Context,
	userID uuid.UUID,
	currentSessionID uuid.UUID,
	currentPassword string,
	newPassword string,
) error {
	if userID == uuid.Nil || currentSessionID == uuid.Nil {
		return ErrInvalidRequest
	}
	if _, err := s.reauthenticateUser(ctx, userID, currentPassword, "active"); err != nil {
		return err
	}
	passwordHash, paramsVersion, err := s.passwords.Hash(newPassword)
	if err != nil {
		return ErrInvalidRequest
	}
	identifiers, err := randomUUIDs(1)
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.ChangePassword(ctx, PasswordChangeRecord{
		UserID: userID, CurrentSessionID: currentSessionID,
		PasswordHash: passwordHash, PasswordParamsVersion: paramsVersion,
		AuditEventID: identifiers[0], ChangedAt: s.clock().UTC(),
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAccountNotFound) {
		return ErrInvalidRequest
	}
	return ErrServiceUnavailable
}

func (s *Service) RequestDeletion(
	ctx context.Context,
	userID uuid.UUID,
	currentPassword string,
	verificationReceipt string,
) error {
	if userID == uuid.Nil {
		return ErrInvalidRequest
	}
	if _, err := s.reauthenticateUser(ctx, userID, currentPassword, "active"); err != nil {
		return err
	}
	claims, err := s.receipts.Parse(verificationReceipt, verification.PurposeAccountDeletion)
	if err != nil {
		return ErrVerificationRequired
	}
	identifiers, err := randomUUIDs(1)
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.RequestDeletion(ctx, DeletionRequestRecord{
		ReceiptClaims: claims, UserID: userID, AuditEventID: identifiers[0], RequestedAt: s.clock().UTC(),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrReceiptUnavailable):
		return ErrVerificationRequired
	case errors.Is(err, ErrAccountNotFound):
		return ErrInvalidRequest
	default:
		return ErrServiceUnavailable
	}
}

func (s *Service) RecoverDeletion(
	ctx context.Context,
	rawIdentity string,
	password string,
	verificationReceipt string,
) error {
	kind := identityKindForLogin(rawIdentity)
	normalized, err := secure.NormalizeIdentity(kind, rawIdentity)
	if err != nil {
		return ErrInvalidCredentials
	}
	claims, err := s.receipts.Parse(verificationReceipt, verification.PurposeDeletionRecovery)
	if err != nil || claims.Kind != kind || claims.NormalizedIdentity != normalized {
		return ErrVerificationRequired
	}
	candidates := s.identity.LookupCandidates(kind, normalized)
	credential, found, err := s.repository.FindCredential(ctx, kind, candidates)
	if err != nil {
		return ErrServiceUnavailable
	}
	if !found {
		_, _, _ = s.passwords.Verify(password, s.dummyHash)
		return ErrInvalidCredentials
	}
	valid, _, err := s.passwords.Verify(password, credential.PasswordHash)
	if err != nil {
		return ErrServiceUnavailable
	}
	if !valid {
		return ErrInvalidCredentials
	}
	if credential.Status != "pending_deletion" {
		return ErrInvalidRequest
	}
	identifiers, err := randomUUIDs(1)
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.RecoverDeletion(ctx, DeletionRecoveryRecord{
		ReceiptClaims: claims, UserID: credential.UserID,
		AuditEventID: identifiers[0], RecoveredAt: s.clock().UTC(),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrReceiptUnavailable):
		return ErrVerificationRequired
	case errors.Is(err, ErrDeletionWindowExpired):
		return ErrDeletionWindowExpired
	default:
		return ErrServiceUnavailable
	}
}

func (s *Service) reauthenticateUser(
	ctx context.Context,
	userID uuid.UUID,
	password string,
	requiredStatus string,
) (Credential, error) {
	credential, found, err := s.repository.FindCredentialByUserID(ctx, userID)
	if err != nil {
		return Credential{}, ErrServiceUnavailable
	}
	encodedHash := s.dummyHash
	if found {
		encodedHash = credential.PasswordHash
	}
	valid, _, verifyErr := s.passwords.Verify(password, encodedHash)
	if verifyErr != nil {
		return Credential{}, ErrServiceUnavailable
	}
	if !found || !valid {
		return Credential{}, ErrInvalidCredentials
	}
	if credential.Status != requiredStatus {
		return Credential{}, ErrInvalidRequest
	}
	return credential, nil
}
