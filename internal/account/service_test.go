package account

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/bignormal/aera-cloud/internal/legal"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
)

func TestServiceRegisterBuildsAtomicRecordWithoutUsername(t *testing.T) {
	fixture := newAccountFixture(t)
	receipt := fixture.receipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration)

	registration, err := fixture.service.Register(context.Background(), RegisterCommand{
		Kind: secure.IdentityEmail, VerificationReceipt: receipt, Password: "correct horse battery staple",
		Nickname: "  Alice  ", TermsVersion: "terms-2026-07", PrivacyVersion: "privacy-2026-07",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if registration.UserID == uuid.Nil || registration.PersonalSpaceID == uuid.Nil {
		t.Fatalf("Registration = %+v", registration)
	}
	if len(fixture.repository.registrations) != 1 {
		t.Fatalf("registration records = %d", len(fixture.repository.registrations))
	}
	record := fixture.repository.registrations[0]
	if record.Nickname != "Alice" || record.TermsVersion != "terms-2026-07" || record.PrivacyVersion != "privacy-2026-07" {
		t.Fatalf("registration record = %+v", record)
	}
	if record.PasswordHash != "hash:correct horse battery staple" || record.PasswordParamsVersion != 7 {
		t.Fatalf("password record = %q v%d", record.PasswordHash, record.PasswordParamsVersion)
	}
	if bytes.Contains(record.SealedIdentity.Ciphertext, []byte("alice@example.com")) || len(record.SealedIdentity.LookupHMAC) != 32 {
		t.Fatal("registration persisted plaintext identity or missing lookup index")
	}
}

func TestServiceRegisterAllowsEmptyNicknameAndRejectsStaleLegalDocuments(t *testing.T) {
	fixture := newAccountFixture(t)
	receipt := fixture.receipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration)
	registration, err := fixture.service.Register(context.Background(), RegisterCommand{
		Kind: secure.IdentityEmail, VerificationReceipt: receipt, Password: "correct horse battery staple",
		TermsVersion: "terms-2026-07", PrivacyVersion: "privacy-2026-07",
	})
	if err != nil || registration.UserID == uuid.Nil {
		t.Fatalf("Register(empty nickname) = %+v, %v", registration, err)
	}
	if fixture.repository.registrations[0].Nickname != "" {
		t.Fatal("empty nickname was replaced with a generated username")
	}

	staleReceipt := fixture.receipt(t, secure.IdentityPhone, "+8613800138000", verification.PurposeRegistration)
	_, err = fixture.service.Register(context.Background(), RegisterCommand{
		Kind: secure.IdentityPhone, VerificationReceipt: staleReceipt, Password: "correct horse battery staple",
		TermsVersion: "terms-old", PrivacyVersion: "privacy-2026-07",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Register(stale legal) error = %v", err)
	}
	if len(fixture.repository.registrations) != 1 {
		t.Fatal("stale legal acceptance reached repository")
	}
}

func TestServiceDirectRegistrationStoresNormalizedUnverifiedEmailWithoutReceipt(t *testing.T) {
	fixture := newAccountFixture(t)
	directLimiter := &fakeDirectRegistrationLimiter{allowed: true}
	config := ServiceConfig{
		Repository: fixture.repository, IdentityCodec: fixture.identity, Receipts: fixture.receipts,
		Passwords: fixture.passwords, Legal: currentLegalService(t), LoginLimiter: fixture.limiter,
		Auditor: fixture.auditor, Clock: func() time.Time { return fixture.now },
	}
	setReflectedField(t, &config, "DirectRegistration", true)
	setReflectedField(t, &config, "DirectRegistrationLimiter", directLimiter)
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService(direct) error = %v", err)
	}

	command := RegisterCommand{
		Kind: secure.IdentityEmail, Password: "correct horse battery staple", Nickname: "  Alice  ",
		TermsVersion: "terms-2026-07", PrivacyVersion: "privacy-2026-07",
	}
	setReflectedField(t, &command, "Identity", " Alice@Example.COM ")
	registration, err := service.Register(
		WithLoginIPAddress(context.Background(), "203.0.113.10"),
		command,
	)
	if err != nil || registration.UserID == uuid.Nil {
		t.Fatalf("Register(direct) = %+v, %v", registration, err)
	}
	if directLimiter.calls != 1 || directLimiter.ipAddress != "203.0.113.10" {
		t.Fatalf("direct limiter = calls:%d IP:%q", directLimiter.calls, directLimiter.ipAddress)
	}
	if len(fixture.repository.registrations) != 1 {
		t.Fatalf("registration records = %d", len(fixture.repository.registrations))
	}
	record := fixture.repository.registrations[0]
	if record.ReceiptClaims.ChallengeID != uuid.Nil ||
		record.ReceiptClaims.Kind != secure.IdentityEmail ||
		record.ReceiptClaims.NormalizedIdentity != "alice@example.com" ||
		record.ReceiptClaims.Purpose != verification.PurposeRegistration {
		t.Fatalf("direct registration claims = %+v", record.ReceiptClaims)
	}
	if !reflectedBool(t, record, "Direct") {
		t.Fatal("direct registration record was not marked direct")
	}
	if len(fixture.repository.receiptsUsed) != 0 {
		t.Fatalf("direct registration consumed receipts = %+v", fixture.repository.receiptsUsed)
	}
}

func TestServiceDirectRegistrationFailsClosed(t *testing.T) {
	fixture := newAccountFixture(t)
	directLimiter := &fakeDirectRegistrationLimiter{allowed: true}
	config := ServiceConfig{
		Repository: fixture.repository, IdentityCodec: fixture.identity, Receipts: fixture.receipts,
		Passwords: fixture.passwords, Legal: currentLegalService(t), LoginLimiter: fixture.limiter,
		Auditor: fixture.auditor, Clock: func() time.Time { return fixture.now },
	}
	setReflectedField(t, &config, "DirectRegistration", true)
	setReflectedField(t, &config, "DirectRegistrationLimiter", directLimiter)

	directCommand := func() RegisterCommand {
		command := RegisterCommand{
			Kind: secure.IdentityEmail, Password: "correct horse battery staple",
			TermsVersion: "terms-2026-07", PrivacyVersion: "privacy-2026-07",
		}
		setReflectedField(t, &command, "Identity", "alice@example.com")
		return command
	}
	tests := []struct {
		name    string
		mutate  func(*RegisterCommand)
		limiter *fakeDirectRegistrationLimiter
		want    error
	}{
		{
			name: "phone", mutate: func(command *RegisterCommand) {
				command.Kind = secure.IdentityPhone
				setReflectedField(t, command, "Identity", "+8613800138000")
			}, limiter: directLimiter, want: ErrInvalidRequest,
		},
		{
			name: "receipt supplied", mutate: func(command *RegisterCommand) {
				command.VerificationReceipt = "must-not-be-accepted"
			}, limiter: directLimiter, want: ErrInvalidRequest,
		},
		{
			name: "invalid identity", mutate: func(command *RegisterCommand) {
				setReflectedField(t, command, "Identity", "not-an-email")
			}, limiter: directLimiter, want: ErrInvalidRequest,
		},
		{
			name: "rate denied", mutate: func(*RegisterCommand) {},
			limiter: &fakeDirectRegistrationLimiter{allowed: false}, want: ErrServiceUnavailable,
		},
		{
			name: "rate store unavailable", mutate: func(*RegisterCommand) {},
			limiter: &fakeDirectRegistrationLimiter{allowed: true, err: errors.New("redis detail")}, want: ErrServiceUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testConfig := config
			setReflectedField(t, &testConfig, "DirectRegistrationLimiter", test.limiter)
			testService, err := NewService(testConfig)
			if err != nil {
				t.Fatalf("NewService() error = %v", err)
			}
			command := directCommand()
			test.mutate(&command)
			_, err = testService.Register(
				WithLoginIPAddress(context.Background(), "203.0.113.10"),
				command,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("Register() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestServiceAuthenticateUsesSamePublicErrorForUnknownAndWrongPassword(t *testing.T) {
	fixture := newAccountFixture(t)
	fixture.repository.credential = Credential{
		UserID: uuid.New(), PersonalSpaceID: uuid.New(), Status: "active", PasswordHash: "valid-hash", ParamsVersion: 7,
	}
	fixture.passwords.verify = func(password, encoded string) (bool, bool, error) {
		return password == "right-password" && encoded == "valid-hash", false, nil
	}

	fixture.repository.found = false
	_, unknownErr := fixture.service.AuthenticatePassword(WithLoginIPAddress(context.Background(), "203.0.113.10"), "unknown@example.com", "wrong-password")
	unknownVerifyCalls := fixture.passwords.verifyCalls
	fixture.passwords.verifyCalls = 0
	fixture.repository.found = true
	_, wrongErr := fixture.service.AuthenticatePassword(WithLoginIPAddress(context.Background(), "203.0.113.10"), "alice@example.com", "wrong-password")
	wrongVerifyCalls := fixture.passwords.verifyCalls

	if !errors.Is(unknownErr, ErrInvalidCredentials) || !errors.Is(wrongErr, ErrInvalidCredentials) {
		t.Fatalf("unknown/wrong errors = %v / %v", unknownErr, wrongErr)
	}
	if unknownVerifyCalls != 1 || wrongVerifyCalls != 1 {
		t.Fatalf("password verification calls unknown/wrong = %d/%d", unknownVerifyCalls, wrongVerifyCalls)
	}
	if len(fixture.auditor.events) != 2 || fixture.auditor.events[0].ReasonCode != "invalid_credentials" || fixture.auditor.events[1].ReasonCode != "invalid_credentials" {
		t.Fatalf("audit events = %+v", fixture.auditor.events)
	}
}

func TestServiceAuthenticateAcceptsEmailOrPhoneLookupCandidates(t *testing.T) {
	fixture := newAccountFixture(t)
	fixture.repository.found = true
	fixture.repository.credential = Credential{
		UserID: uuid.New(), PersonalSpaceID: uuid.New(), Nickname: "Alice", Status: "active", PasswordHash: "valid-hash", ParamsVersion: 7,
	}
	fixture.passwords.verify = func(password, encoded string) (bool, bool, error) { return true, false, nil }

	for _, identity := range []string{"Alice@Example.COM", "138 0013 8000"} {
		principal, err := fixture.service.AuthenticatePassword(WithLoginIPAddress(context.Background(), "203.0.113.10"), identity, "right-password")
		if err != nil || principal.UserID != fixture.repository.credential.UserID {
			t.Fatalf("AuthenticatePassword(%q) = %+v, %v", identity, principal, err)
		}
	}
	if len(fixture.repository.lookupKinds) != 2 || fixture.repository.lookupKinds[0] != secure.IdentityEmail || fixture.repository.lookupKinds[1] != secure.IdentityPhone {
		t.Fatalf("lookup kinds = %+v", fixture.repository.lookupKinds)
	}
}

func TestServiceResetPasswordUsesReceiptAndRequestsSessionFamilyRevocation(t *testing.T) {
	fixture := newAccountFixture(t)
	receipt := fixture.receipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposePasswordReset)
	if err := fixture.service.ResetPassword(context.Background(), receipt, "new correct horse battery"); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	if len(fixture.repository.resets) != 1 {
		t.Fatalf("reset records = %d", len(fixture.repository.resets))
	}
	record := fixture.repository.resets[0]
	if record.ReceiptClaims.NormalizedIdentity != "alice@example.com" || record.PasswordHash != "hash:new correct horse battery" {
		t.Fatalf("reset record = %+v", record)
	}
	if !fixture.repository.revokeSessions {
		t.Fatal("password reset did not request all session families to be revoked")
	}
	if err := fixture.service.ResetPassword(context.Background(), receipt, "another correct password"); !errors.Is(err, ErrVerificationRequired) {
		t.Fatalf("replayed ResetPassword() error = %v", err)
	}
}

type accountFixture struct {
	now        time.Time
	identity   *secure.IdentityCodec
	receipts   *verification.ReceiptCodec
	passwords  *fakePasswords
	repository *fakeAccountRepository
	limiter    *fakeLoginLimiter
	auditor    *fakeAuditor
	service    *Service
}

func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()
	now := time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)
	identity, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: "enc-v1", EncryptionKeys: map[string][]byte{"enc-v1": bytes.Repeat([]byte{1}, 32)},
		ActiveLookupKeyID: "lookup-v1", LookupKeys: map[string][]byte{"lookup-v1": bytes.Repeat([]byte{2}, 32)},
	})
	if err != nil {
		t.Fatalf("NewIdentityCodec() error = %v", err)
	}
	receipts, err := verification.NewReceiptCodec(verification.ReceiptCodecConfig{
		IdentityCodec: identity, ActiveSigningKeyID: "receipt-v1",
		SigningKeys: map[string][]byte{"receipt-v1": bytes.Repeat([]byte{3}, 32)}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewReceiptCodec() error = %v", err)
	}
	legalService, err := legal.NewService("terms-2026-07", "privacy-2026-07")
	if err != nil {
		t.Fatalf("legal.NewService() error = %v", err)
	}
	fixture := &accountFixture{
		now: now, identity: identity, receipts: receipts,
		passwords: &fakePasswords{}, repository: &fakeAccountRepository{}, limiter: &fakeLoginLimiter{allowed: true}, auditor: &fakeAuditor{},
	}
	service, err := NewService(ServiceConfig{
		Repository: fixture.repository, IdentityCodec: identity, Receipts: receipts, Passwords: fixture.passwords,
		Legal: legalService, LoginLimiter: fixture.limiter, Auditor: fixture.auditor, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixture.passwords.hashCalls = 0
	fixture.service = service
	return fixture
}

func currentLegalService(t *testing.T) *legal.Service {
	t.Helper()
	service, err := legal.NewService("terms-2026-07", "privacy-2026-07")
	if err != nil {
		t.Fatalf("legal.NewService() error = %v", err)
	}
	return service
}

func (f *accountFixture) receipt(t *testing.T, kind secure.IdentityKind, normalized string, purpose verification.Purpose) string {
	t.Helper()
	id, err := secure.RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID() error = %v", err)
	}
	token, _, err := f.receipts.Issue(verification.Challenge{ID: id, IdentityKind: kind, Purpose: purpose}, normalized)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	return token
}

type fakePasswords struct {
	hashCalls   int
	verifyCalls int
	verify      func(password, encoded string) (bool, bool, error)
}

func (f *fakePasswords) Hash(password string) (string, int, error) {
	f.hashCalls++
	return "hash:" + password, 7, nil
}

func (f *fakePasswords) Verify(password, encoded string) (bool, bool, error) {
	f.verifyCalls++
	if f.verify != nil {
		return f.verify(password, encoded)
	}
	return false, false, nil
}

type fakeAccountRepository struct {
	registrations      []RegistrationRecord
	resets             []PasswordResetRecord
	credential         Credential
	found              bool
	lookupKinds        []secure.IdentityKind
	receiptsUsed       map[uuid.UUID]bool
	revokeSessions     bool
	bindings           []IdentityBindingRecord
	removeIdentityErr  error
	passwordChanges    []PasswordChangeRecord
	deletionRequests   []DeletionRequestRecord
	requestDeletionErr error
	deletionRecoveries []DeletionRecoveryRecord
	profile            Profile
	profileFound       bool
}

func (f *fakeAccountRepository) Profile(context.Context, uuid.UUID) (Profile, bool, error) {
	return f.profile, f.profileFound, nil
}

func (f *fakeAccountRepository) Register(_ context.Context, record RegistrationRecord) (Registration, error) {
	if !reflectedBoolValue(record, "Direct") {
		if f.receiptsUsed == nil {
			f.receiptsUsed = make(map[uuid.UUID]bool)
		}
		if f.receiptsUsed[record.ReceiptClaims.ChallengeID] {
			return Registration{}, ErrReceiptUnavailable
		}
		f.receiptsUsed[record.ReceiptClaims.ChallengeID] = true
	}
	f.registrations = append(f.registrations, record)
	return Registration{UserID: record.UserID, PersonalSpaceID: record.PersonalSpaceID}, nil
}

func (f *fakeAccountRepository) FindCredential(_ context.Context, kind secure.IdentityKind, _ []secure.LookupIndex) (Credential, bool, error) {
	f.lookupKinds = append(f.lookupKinds, kind)
	return f.credential, f.found, nil
}

func (f *fakeAccountRepository) FindCredentialByUserID(_ context.Context, userID uuid.UUID) (Credential, bool, error) {
	if !f.found || f.credential.UserID != userID {
		return Credential{}, false, nil
	}
	return f.credential, true, nil
}

func (f *fakeAccountRepository) UpdatePasswordHash(context.Context, uuid.UUID, string, int, time.Time) error {
	return nil
}

func (f *fakeAccountRepository) ResetPassword(_ context.Context, record PasswordResetRecord) error {
	if f.receiptsUsed == nil {
		f.receiptsUsed = make(map[uuid.UUID]bool)
	}
	if f.receiptsUsed[record.ReceiptClaims.ChallengeID] {
		return ErrReceiptUnavailable
	}
	f.receiptsUsed[record.ReceiptClaims.ChallengeID] = true
	f.resets = append(f.resets, record)
	f.revokeSessions = true
	return nil
}

func (f *fakeAccountRepository) BindIdentity(_ context.Context, record IdentityBindingRecord) error {
	f.bindings = append(f.bindings, record)
	return nil
}

func (f *fakeAccountRepository) RemoveIdentity(context.Context, IdentityRemovalRecord) error {
	return f.removeIdentityErr
}

func (f *fakeAccountRepository) ChangePassword(_ context.Context, record PasswordChangeRecord) error {
	f.passwordChanges = append(f.passwordChanges, record)
	return nil
}

func (f *fakeAccountRepository) RequestDeletion(_ context.Context, record DeletionRequestRecord) error {
	f.deletionRequests = append(f.deletionRequests, record)
	return f.requestDeletionErr
}

func (f *fakeAccountRepository) RecoverDeletion(_ context.Context, record DeletionRecoveryRecord) error {
	f.deletionRecoveries = append(f.deletionRecoveries, record)
	return nil
}

type fakeLoginLimiter struct {
	allowed bool
	err     error
}

type fakeDirectRegistrationLimiter struct {
	allowed   bool
	err       error
	calls     int
	ipAddress string
}

func (f *fakeDirectRegistrationLimiter) Allow(_ context.Context, rawIPAddress string) (bool, error) {
	f.calls++
	f.ipAddress = rawIPAddress
	return f.allowed, f.err
}

func setReflectedField(t *testing.T, target any, name string, value any) {
	t.Helper()
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("%T.%s does not exist", target, name)
	}
	field.Set(reflect.ValueOf(value))
}

func reflectedBool(t *testing.T, target any, name string) bool {
	t.Helper()
	field := reflect.ValueOf(target).FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.Bool {
		t.Fatalf("%T.%s is not a bool", target, name)
	}
	return field.Bool()
}

func reflectedBoolValue(target any, name string) bool {
	field := reflect.ValueOf(target).FieldByName(name)
	return field.IsValid() && field.Kind() == reflect.Bool && field.Bool()
}

func (f *fakeLoginLimiter) Allow(context.Context, []byte, string) (bool, error) {
	return f.allowed, f.err
}

type fakeAuditor struct {
	events []audit.Event
}

func (f *fakeAuditor) Record(_ context.Context, event audit.Event) error {
	f.events = append(f.events, event)
	return nil
}
