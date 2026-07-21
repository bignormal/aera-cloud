package organization

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOrganizationRepositoryCreateIsAtomicReplayableAndSafeToRead(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	owner := fixture.actor(t, 1, "Owner")
	outsider := fixture.actor(t, 2, "Outsider")
	command := fixture.createTransaction(owner, "Acme Research", 1, 3)

	created, err := fixture.repository.Create(fixture.ctx, command)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID != command.OrganizationID || created.DisplayName != "Acme Research" ||
		created.Status != OrganizationStatusActive || created.Role != RoleOwner || created.Revision != 1 ||
		created.MemberCount != 1 || created.DepartmentCount != 0 || created.CurrentPolicyVersion != 1 ||
		created.MutationState != MutationStateWritable || created.CurrentPolicyDigest == ([32]byte{}) {
		t.Fatalf("Create() = %+v", created)
	}

	fullPolicy, err := fixture.repository.CurrentPolicy(fixture.ctx, owner.UserID, created.ID, true)
	if err != nil {
		t.Fatalf("CurrentPolicy(Owner) error = %v", err)
	}
	if fullPolicy.ID != command.PolicySnapshotID || fullPolicy.PolicyVersion != 1 ||
		fullPolicy.Document.SchemaVersion != 1 || len(fullPolicy.Signature) != ed25519.SignatureSize {
		t.Fatalf("CurrentPolicy(Owner) = %+v", fullPolicy)
	}
	if err := fixture.verifier.VerifyPolicy(PolicyAttestation{
		Issuer: fullPolicy.Issuer, KeyID: fullPolicy.SigningKeyID, OrganizationID: created.ID,
		SnapshotID: fullPolicy.ID, PolicyVersion: fullPolicy.PolicyVersion,
		ContentDigest: fullPolicy.ContentDigest, Signature: fullPolicy.Signature,
	}); err != nil {
		t.Fatalf("verify persisted policy: %v", err)
	}

	replay := command
	replay.OrganizationID = uuid.New()
	replay.PolicySnapshotID = uuid.New()
	replayed, err := fixture.repository.Create(fixture.ctx, replay)
	if err != nil || replayed.ID != created.ID || replayed.CurrentPolicyDigest != created.CurrentPolicyDigest {
		t.Fatalf("Create(replay) = %+v, %v", replayed, err)
	}
	conflict := command
	conflict.DisplayName = "Different Organization"
	conflict.Idempotency.RequestDigest, err = CanonicalCreateRequestDigest(conflict.DisplayName)
	if err != nil {
		t.Fatalf("CanonicalCreateRequestDigest(conflict) error = %v", err)
	}
	if _, err := fixture.repository.Create(fixture.ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Create(conflicting replay) error = %v", err)
	}

	listed, err := fixture.repository.ListForActor(fixture.ctx, owner.UserID, Page{Limit: 20})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != created.ID || listed.Next != nil {
		t.Fatalf("ListForActor(Owner) = %+v, %v", listed, err)
	}
	got, err := fixture.repository.GetForActor(fixture.ctx, owner.UserID, created.ID)
	if err != nil || got.ID != created.ID || got.Role != RoleOwner {
		t.Fatalf("GetForActor(Owner) = %+v, %v", got, err)
	}
	outsideList, err := fixture.repository.ListForActor(fixture.ctx, outsider.UserID, Page{Limit: 20})
	if err != nil || len(outsideList.Items) != 0 {
		t.Fatalf("ListForActor(outsider) = %+v, %v", outsideList, err)
	}
	if _, err := fixture.repository.GetForActor(fixture.ctx, outsider.UserID, created.ID); !errors.Is(err, ErrOrganizationNotFound) {
		t.Fatalf("GetForActor(outsider) error = %v", err)
	}
	if _, err := fixture.repository.CurrentPolicy(fixture.ctx, outsider.UserID, created.ID, true); !errors.Is(err, ErrOrganizationNotFound) {
		t.Fatalf("CurrentPolicy(outsider) error = %v", err)
	}

	for table, want := range map[string]int{
		"organizations":                    1,
		"organization_memberships":         1,
		"organization_policy_snapshots":    1,
		"organization_idempotency_records": 1,
	} {
		var count int
		if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != want {
			t.Fatalf("%s rows = %d, error = %v", table, count, err)
		}
	}
	var auditCount int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM audit_events
		WHERE organization_id = $1 AND event_type = 'organization_created' AND object_id = $1
	`, created.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("create audit rows = %d, error = %v", auditCount, err)
	}
}

func TestCanonicalOrganizationCreateRequestDigestUsesNormalizedNameAndDomain(t *testing.T) {
	composed, err := CanonicalCreateRequestDigest("Caf\u00e9 Research")
	if err != nil {
		t.Fatalf("CanonicalCreateRequestDigest(composed) error = %v", err)
	}
	decomposed, err := CanonicalCreateRequestDigest("  Cafe\u0301 Research  ")
	if err != nil {
		t.Fatalf("CanonicalCreateRequestDigest(decomposed) error = %v", err)
	}
	if composed != decomposed {
		t.Fatalf("canonical digests differ: %x != %x", composed, decomposed)
	}
	plain := sha256.Sum256([]byte("Caf\u00e9 Research"))
	if composed == plain {
		t.Fatal("Organization create digest is not domain separated")
	}
}

func TestOrganizationRepositoryQuotaIncludesArchivedOwnership(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	owner := fixture.actor(t, 10, "Owner")
	firstCommand := fixture.createTransaction(owner, "Archived Holdings", 10, 1)
	first, err := fixture.repository.Create(fixture.ctx, firstCommand)
	if err != nil {
		t.Fatalf("Create(first) error = %v", err)
	}
	archivedAt := fixture.now.Add(time.Hour)
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations
		SET status = 'archived', revision = revision + 1, archived_at = $2, updated_at = $2
		WHERE id = $1
	`, first.ID, archivedAt); err != nil {
		t.Fatalf("archive fixture Organization: %v", err)
	}
	second := fixture.createTransaction(owner, "Second Organization", 11, 1)
	if _, err := fixture.repository.Create(fixture.ctx, second); !errors.Is(err, ErrOrganizationLimitReached) {
		t.Fatalf("Create(over archived quota) error = %v", err)
	}
}

func TestOrganizationRepositoryProjectsPolicyByRoleAndPagesSafeDirectories(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	owner := fixture.actor(t, 20, "Owner")
	admin := fixture.actor(t, 21, "Admin")
	auditor := fixture.actor(t, 22, "Auditor")
	member := fixture.actor(t, 23, "Member")
	created, err := fixture.repository.Create(fixture.ctx, fixture.createTransaction(owner, "Directory Organization", 20, 3))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	fixture.addMembership(t, created.ID, admin.UserID, RoleAdmin)
	fixture.addMembership(t, created.ID, auditor.UserID, RoleAuditor)
	fixture.addMembership(t, created.ID, member.UserID, RoleMember)

	for _, privileged := range []Actor{owner, admin, auditor} {
		policy, err := fixture.repository.CurrentPolicy(fixture.ctx, privileged.UserID, created.ID, true)
		if err != nil || policy.Document.SchemaVersion != 1 || len(policy.Signature) != ed25519.SignatureSize {
			t.Fatalf("CurrentPolicy(%s) = %+v, %v", privileged.UserID, policy, err)
		}
	}
	memberPolicy, err := fixture.repository.CurrentPolicy(fixture.ctx, member.UserID, created.ID, true)
	if err != nil || !reflect.DeepEqual(memberPolicy.Document, PolicyDocument{}) || memberPolicy.Signature != nil {
		t.Fatalf("CurrentPolicy(Member full request) = %+v, %v", memberPolicy, err)
	}
	ownerSummary, err := fixture.repository.CurrentPolicy(fixture.ctx, owner.UserID, created.ID, false)
	if err != nil || !reflect.DeepEqual(ownerSummary.Document, PolicyDocument{}) || ownerSummary.Signature != nil {
		t.Fatalf("CurrentPolicy(Owner summary) = %+v, %v", ownerSummary, err)
	}

	firstMembers, err := fixture.repository.ListMembers(fixture.ctx, member.UserID, created.ID, Page{Limit: 2})
	if err != nil || len(firstMembers.Items) != 2 || firstMembers.Next == nil {
		t.Fatalf("ListMembers(first) = %+v, %v", firstMembers, err)
	}
	secondMembers, err := fixture.repository.ListMembers(fixture.ctx, member.UserID, created.ID, Page{Limit: 2, After: firstMembers.Next})
	if err != nil || len(secondMembers.Items) != 2 || secondMembers.Next != nil {
		t.Fatalf("ListMembers(second) = %+v, %v", secondMembers, err)
	}

	departmentIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for index, departmentID := range departmentIDs {
		name := fmt.Sprintf("Department %d", index+1)
		_, nameKey, normalizeErr := NormalizeDepartmentName(name)
		if normalizeErr != nil {
			t.Fatalf("NormalizeDepartmentName() error = %v", normalizeErr)
		}
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			INSERT INTO organization_departments (
				organization_id, id, display_name, name_key, status, revision, created_at, updated_at
			) VALUES ($1, $2, $3, $4, 'active', 1, $5, $5)
		`, created.ID, departmentID, name, nameKey, fixture.now.Add(time.Duration(index)*time.Minute)); err != nil {
			t.Fatalf("seed Department: %v", err)
		}
	}
	departments, err := fixture.repository.ListDepartments(fixture.ctx, auditor.UserID, created.ID, Page{Limit: 2})
	if err != nil || len(departments.Items) != 2 || departments.Next == nil {
		t.Fatalf("ListDepartments(first) = %+v, %v", departments, err)
	}
	departments, err = fixture.repository.ListDepartments(fixture.ctx, auditor.UserID, created.ID, Page{Limit: 2, After: departments.Next})
	if err != nil || len(departments.Items) != 1 || departments.Next != nil {
		t.Fatalf("ListDepartments(second) = %+v, %v", departments, err)
	}
}

func TestOrganizationRepositoryCreateRollsBackOnSignerOrAuditFailure(t *testing.T) {
	for _, test := range []struct {
		name          string
		configure     func(*organizationRepositoryFixture, CreateTransaction)
		wantSignerErr bool
	}{
		{
			name: "signer failure", wantSignerErr: true,
			configure: func(fixture *organizationRepositoryFixture, _ CreateTransaction) {
				fixture.repository = NewPostgresRepository(fixture.postgres, failingPolicySigner{})
			},
		},
		{
			name: "audit failure",
			configure: func(fixture *organizationRepositoryFixture, command CreateTransaction) {
				if _, err := fixture.postgres.Exec(fixture.ctx, `
					INSERT INTO audit_events (id, event_type, outcome, metadata, created_at)
					VALUES ($1, 'browser_login', 'success', '{}'::jsonb, $2)
				`, command.Audit.EventID, fixture.now); err != nil {
					fixture.t.Fatalf("seed duplicate audit: %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOrganizationRepositoryFixture(t)
			owner := fixture.actor(t, 30, "Owner")
			command := fixture.createTransaction(owner, "Rollback Organization", 30, 3)
			test.configure(fixture, command)
			if _, err := fixture.repository.Create(fixture.ctx, command); !errors.Is(err, ErrServiceUnavailable) {
				t.Fatalf("Create() error = %v, want ErrServiceUnavailable", err)
			}
			for _, table := range []string{
				"organizations", "organization_memberships", "organization_policy_snapshots",
				"organization_idempotency_records",
			} {
				var count int
				if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("%s rows after rollback = %d, error = %v", table, count, err)
				}
			}
		})
	}
}

type organizationRepositoryFixture struct {
	t          *testing.T
	ctx        context.Context
	postgres   *pgxpool.Pool
	repository *PostgresRepository
	verifier   *Verifier
	now        time.Time
}

func newOrganizationRepositoryFixture(t *testing.T) *organizationRepositoryFixture {
	t.Helper()
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	t.Cleanup(postgres.Close)
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate Organization fixture: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, ed25519.SeedSize))
	signer, err := NewSigner(SigningConfig{
		Issuer: "https://accounts.example.com", ActiveKeyID: "organization-v1",
		SigningKeys: map[string]ed25519.PrivateKey{"organization-v1": privateKey},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	verifier, err := NewVerifier(VerifierConfig{
		Issuer: "https://accounts.example.com",
		Keys: map[string]VerificationKey{
			"organization-v1": {Purpose: PurposeOrganizationPolicy, PublicKey: privateKey.Public().(ed25519.PublicKey)},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return &organizationRepositoryFixture{
		t: t, ctx: ctx, postgres: postgres, repository: NewPostgresRepository(postgres, signer), verifier: verifier,
		now: time.Date(2026, 7, 21, 8, 0, 0, 0, time.UTC),
	}
}

func (f *organizationRepositoryFixture) actor(t *testing.T, discriminator byte, nickname string) Actor {
	t.Helper()
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, actor.UserID, nickname, f.now); err != nil {
		t.Fatalf("seed Organization actor: %v", err)
	}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Organization Test Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, actor.DeviceID, actor.UserID, uuid.New(), bytes.Repeat([]byte{discriminator}, 32), f.now); err != nil {
		t.Fatalf("seed Organization device: %v", err)
	}
	return actor
}

func (f *organizationRepositoryFixture) createTransaction(
	actor Actor,
	displayName string,
	discriminator byte,
	ownedLimit int,
) CreateTransaction {
	createdAt := f.now.Add(time.Duration(discriminator) * time.Minute)
	requestDigest, err := CanonicalCreateRequestDigest(displayName)
	if err != nil {
		f.t.Fatalf("CanonicalCreateRequestDigest(%q) error = %v", displayName, err)
	}
	return CreateTransaction{
		Actor: actor, OrganizationID: organizationTestUUID("organization", discriminator), DisplayName: displayName,
		OwnedLimit: ownedLimit, PolicySnapshotID: organizationTestUUID("policy", discriminator),
		Idempotency: IdempotencyEvidence{
			KeyDigest:     sha256.Sum256([]byte{discriminator, 1}),
			RequestDigest: requestDigest,
			ExpiresAt:     createdAt.Add(24 * time.Hour),
		},
		Audit:     AuditEvidence{EventID: organizationTestUUID("audit", discriminator), RequestID: fmt.Sprintf("organization-request-%d", discriminator)},
		CreatedAt: createdAt,
	}
}

func (f *organizationRepositoryFixture) addMembership(t *testing.T, organizationID, userID uuid.UUID, role Role) {
	t.Helper()
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO organization_memberships (
			organization_id, user_id, role, revision, joined_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, $4)
	`, organizationID, userID, role, f.now); err != nil {
		t.Fatalf("add Organization %s: %v", role, err)
	}
}

func organizationTestUUID(label string, discriminator byte) uuid.UUID {
	digest := sha256.Sum256([]byte("organization-repository-test-" + label + "-" + string([]byte{discriminator})))
	id, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

type failingPolicySigner struct{}

func (failingPolicySigner) SignPolicy(PolicySignatureInput) (PolicyAttestation, error) {
	return PolicyAttestation{}, errors.New("signer unavailable")
}
