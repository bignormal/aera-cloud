package account

import (
	"context"
	"errors"
	"testing"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
)

func TestBindIdentityRequiresCurrentPasswordReauthentication(t *testing.T) {
	fixture := newAccountFixture(t)
	userID := uuid.New()
	fixture.repository.credential = Credential{UserID: userID, Status: "active", PasswordHash: "current-hash"}
	fixture.repository.found = true
	receipt := fixture.receipt(t, secure.IdentityPhone, "+8613800138000", verification.PurposeBindIdentity)
	fixture.passwords.verify = func(password, encoded string) (bool, bool, error) {
		return password == "current-password" && encoded == "current-hash", false, nil
	}

	if err := fixture.service.BindIdentity(context.Background(), userID, "wrong-password", receipt); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("BindIdentity(wrong password) error = %v", err)
	}
	if len(fixture.repository.bindings) != 0 {
		t.Fatal("identity binding reached the repository without reauthentication")
	}
	if err := fixture.service.BindIdentity(context.Background(), userID, "current-password", receipt); err != nil {
		t.Fatalf("BindIdentity() error = %v", err)
	}
	if len(fixture.repository.bindings) != 1 || fixture.repository.bindings[0].ReceiptClaims.Kind != secure.IdentityPhone {
		t.Fatalf("binding records = %+v", fixture.repository.bindings)
	}
}

func TestProfileReturnsOnlyRedactedIdentityMetadata(t *testing.T) {
	fixture := newAccountFixture(t)
	userID := uuid.New()
	fixture.repository.profile = Profile{
		UserID: userID, PersonalSpaceID: uuid.New(), Nickname: "Alice", Status: "active",
		IdentityKinds: []secure.IdentityKind{secure.IdentityEmail, secure.IdentityPhone},
	}
	fixture.repository.profileFound = true

	profile, err := fixture.service.Profile(context.Background(), userID)
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if profile.UserID != userID || len(profile.IdentityKinds) != 2 || profile.IdentityKinds[0] != secure.IdentityEmail {
		t.Fatalf("Profile() = %+v", profile)
	}
}

func TestRemoveIdentityRefusesTheLastLoginIdentity(t *testing.T) {
	fixture := newAccountFixture(t)
	userID := uuid.New()
	fixture.repository.credential = Credential{UserID: userID, Status: "active", PasswordHash: "current-hash"}
	fixture.repository.found = true
	fixture.repository.removeIdentityErr = ErrLastIdentity
	fixture.passwords.verify = func(password, encoded string) (bool, bool, error) { return true, false, nil }

	err := fixture.service.RemoveIdentity(context.Background(), userID, secure.IdentityEmail, "current-password")
	if !errors.Is(err, ErrLastIdentity) {
		t.Fatalf("RemoveIdentity() error = %v", err)
	}
}

func TestChangePasswordPreservesOnlyTheCurrentProductSession(t *testing.T) {
	fixture := newAccountFixture(t)
	userID := uuid.New()
	currentSessionID := uuid.New()
	fixture.repository.credential = Credential{UserID: userID, Status: "active", PasswordHash: "current-hash"}
	fixture.repository.found = true
	fixture.passwords.verify = func(password, encoded string) (bool, bool, error) {
		return password == "current-password" && encoded == "current-hash", false, nil
	}

	if err := fixture.service.ChangePassword(
		context.Background(), userID, currentSessionID, "current-password", "new correct horse battery",
	); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}
	if len(fixture.repository.passwordChanges) != 1 {
		t.Fatalf("password change records = %d", len(fixture.repository.passwordChanges))
	}
	record := fixture.repository.passwordChanges[0]
	if record.CurrentSessionID != currentSessionID || record.PasswordHash != "hash:new correct horse battery" {
		t.Fatalf("password change record = %+v", record)
	}
}

func TestDeletionRequestRequiresPasswordAndVerifiedBoundIdentity(t *testing.T) {
	fixture := newAccountFixture(t)
	userID := uuid.New()
	fixture.repository.credential = Credential{UserID: userID, Status: "active", PasswordHash: "current-hash"}
	fixture.repository.found = true
	fixture.passwords.verify = func(password, encoded string) (bool, bool, error) {
		return password == "current-password", false, nil
	}
	receipt := fixture.receipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeAccountDeletion)

	if err := fixture.service.RequestDeletion(context.Background(), userID, "wrong", receipt); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("RequestDeletion(wrong password) error = %v", err)
	}
	if err := fixture.service.RequestDeletion(context.Background(), userID, "current-password", receipt); err != nil {
		t.Fatalf("RequestDeletion() error = %v", err)
	}
	if len(fixture.repository.deletionRequests) != 1 || fixture.repository.deletionRequests[0].UserID != userID {
		t.Fatalf("deletion request records = %+v", fixture.repository.deletionRequests)
	}
}

func TestDeletionRecoveryRequiresPendingAccountPasswordAndFreshReceipt(t *testing.T) {
	fixture := newAccountFixture(t)
	userID := uuid.New()
	fixture.repository.credential = Credential{
		UserID: userID, Status: "pending_deletion", PasswordHash: "current-hash",
	}
	fixture.repository.found = true
	fixture.passwords.verify = func(password, encoded string) (bool, bool, error) {
		return password == "current-password", false, nil
	}
	receipt := fixture.receipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeDeletionRecovery)

	if err := fixture.service.RecoverDeletion(
		context.Background(), "alice@example.com", "current-password", receipt,
	); err != nil {
		t.Fatalf("RecoverDeletion() error = %v", err)
	}
	if len(fixture.repository.deletionRecoveries) != 1 || fixture.repository.deletionRecoveries[0].UserID != userID {
		t.Fatalf("deletion recovery records = %+v", fixture.repository.deletionRecoveries)
	}
}
