package organization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceOrganizationInvitationIsSecretOnceFragmentOnlyAndActorBound(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 100)
	owner := actors[RoleOwner]
	member := fixture.actor(t, 106, "Invited Member")
	other := fixture.actor(t, 107, "Other Member")
	service := fixture.organizationService(t, 50)
	command := CreateInvitationCommand{
		OrganizationID: organization.ID, IdempotencyKey: "invitation-create-key", RequestID: "invitation-create",
	}
	created, err := service.CreateInvitation(t.Context(), owner, command)
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	if created.Token == "" || created.InviteURL != "agentera://organization-invitation#"+created.Token ||
		strings.Contains(created.InviteURL, "?") || created.Invitation.ID == uuid.Nil ||
		created.Invitation.Status != InvitationStatusPending {
		t.Fatalf("CreateInvitation() = %+v", created)
	}
	wantDigest := sha256.Sum256([]byte(created.Token))
	var storedDigest []byte
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT token_digest FROM organization_invitations WHERE id = $1
	`, created.Invitation.ID).Scan(&storedDigest); err != nil || !bytes.Equal(storedDigest, wantDigest[:]) {
		t.Fatalf("stored invitation digest = %x, error = %v", storedDigest, err)
	}
	var leaked bool
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT EXISTS (
			SELECT 1 FROM organization_invitations WHERE row_to_json(organization_invitations)::text LIKE '%' || $1 || '%'
			UNION ALL
			SELECT 1 FROM organization_idempotency_records WHERE row_to_json(organization_idempotency_records)::text LIKE '%' || $1 || '%'
			UNION ALL
			SELECT 1 FROM audit_events WHERE metadata::text LIKE '%' || $1 || '%'
		)
	`, created.Token).Scan(&leaked); err != nil || leaked {
		t.Fatalf("raw invitation persistence leak = %v, error = %v", leaked, err)
	}

	replayed, err := service.CreateInvitation(t.Context(), owner, command)
	if err != nil || replayed.Invitation.ID != created.Invitation.ID || replayed.Token != "" || replayed.InviteURL != "" {
		t.Fatalf("CreateInvitation(replay) = %+v, %v", replayed, err)
	}
	accepted, err := service.AcceptInvitation(t.Context(), member, AcceptInvitationCommand{
		Token: created.Token, IdempotencyKey: "invitation-accept-member", RequestID: "invitation-accept",
	})
	if err != nil || accepted.Organization.ID != organization.ID || accepted.Member.UserID != member.UserID ||
		accepted.Member.Role != RoleMember {
		t.Fatalf("AcceptInvitation() = %+v, %v", accepted, err)
	}
	replayedAcceptance, err := service.AcceptInvitation(t.Context(), member, AcceptInvitationCommand{
		Token: created.Token, IdempotencyKey: "invitation-accept-member", RequestID: "invitation-accept-replay",
	})
	if err != nil || replayedAcceptance.Member.UserID != member.UserID {
		t.Fatalf("AcceptInvitation(actor replay) = %+v, %v", replayedAcceptance, err)
	}
	if _, err := service.AcceptInvitation(t.Context(), other, AcceptInvitationCommand{
		Token: created.Token, IdempotencyKey: "invitation-accept-member", RequestID: "invitation-accept-other",
	}); !errors.Is(err, ErrInvitationUnavailable) {
		t.Fatalf("AcceptInvitation(other actor replay) error = %v", err)
	}
}

func TestServiceOrganizationInvitationRevokeExpiryExistingMemberAndConcurrentWinner(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 110)
	owner := actors[RoleOwner]
	first := fixture.actor(t, 116, "First Candidate")
	second := fixture.actor(t, 117, "Second Candidate")
	service := fixture.organizationService(t, 50)

	revoked, err := service.CreateInvitation(t.Context(), owner, CreateInvitationCommand{
		OrganizationID: organization.ID, IdempotencyKey: "invitation-revoke-create", RequestID: "invitation-revoke-create",
	})
	if err != nil {
		t.Fatalf("CreateInvitation(revoked) error = %v", err)
	}
	if err := service.RevokeInvitation(t.Context(), owner, RevokeInvitationCommand{
		OrganizationID: organization.ID, InvitationID: revoked.Invitation.ID, RequestID: "invitation-revoke",
	}); err != nil {
		t.Fatalf("RevokeInvitation() error = %v", err)
	}
	if _, err := service.AcceptInvitation(t.Context(), first, AcceptInvitationCommand{
		Token: revoked.Token, IdempotencyKey: "accept-revoked", RequestID: "accept-revoked",
	}); !errors.Is(err, ErrInvitationUnavailable) {
		t.Fatalf("AcceptInvitation(revoked) error = %v", err)
	}

	expiredSecret, err := NewInvitationSecret(bytes.NewReader(bytes.Repeat([]byte{0xe1}, 32)))
	if err != nil {
		t.Fatalf("NewInvitationSecret(expired) error = %v", err)
	}
	createdAt := fixture.now.Add(-8 * 24 * time.Hour)
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_invitations (
			id, organization_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, uuid.New(), organization.ID, expiredSecret.Digest[:], owner.UserID, createdAt, createdAt.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("seed expired invitation: %v", err)
	}
	if _, err := service.AcceptInvitation(t.Context(), first, AcceptInvitationCommand{
		Token: expiredSecret.RawToken, IdempotencyKey: "accept-expired", RequestID: "accept-expired",
	}); !errors.Is(err, ErrInvitationUnavailable) {
		t.Fatalf("AcceptInvitation(expired) error = %v", err)
	}

	existing, err := service.CreateInvitation(t.Context(), owner, CreateInvitationCommand{
		OrganizationID: organization.ID, IdempotencyKey: "invitation-existing-create", RequestID: "invitation-existing-create",
	})
	if err != nil {
		t.Fatalf("CreateInvitation(existing) error = %v", err)
	}
	existingAcceptance, err := service.AcceptInvitation(t.Context(), owner, AcceptInvitationCommand{
		Token: existing.Token, IdempotencyKey: "accept-existing", RequestID: "accept-existing",
	})
	if err != nil || existingAcceptance.Member.Role != RoleOwner {
		t.Fatalf("AcceptInvitation(existing Owner) = %+v, %v", existingAcceptance, err)
	}

	concurrent, err := service.CreateInvitation(t.Context(), owner, CreateInvitationCommand{
		OrganizationID: organization.ID, IdempotencyKey: "invitation-race-create", RequestID: "invitation-race-create",
	})
	if err != nil {
		t.Fatalf("CreateInvitation(concurrent) error = %v", err)
	}
	candidates := []Actor{first, second}
	start := make(chan struct{})
	results := make(chan error, len(candidates))
	for index, candidate := range candidates {
		index, candidate := index, candidate
		go func() {
			<-start
			_, acceptErr := service.AcceptInvitation(t.Context(), candidate, AcceptInvitationCommand{
				Token: concurrent.Token, IdempotencyKey: fmt.Sprintf("accept-race-%d", index),
				RequestID: fmt.Sprintf("accept-race-%d", index),
			})
			results <- acceptErr
		}()
	}
	close(start)
	successes := 0
	unavailable := 0
	for range candidates {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvitationUnavailable):
			unavailable++
		default:
			t.Fatalf("concurrent AcceptInvitation error = %v", err)
		}
	}
	if successes != 1 || unavailable != 1 {
		t.Fatalf("concurrent invitation successes=%d unavailable=%d", successes, unavailable)
	}
}

func TestServiceOrganizationArchiveRestoreRevokesInvitationsWithoutRevival(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 120)
	owner := actors[RoleOwner]
	service := fixture.organizationService(t, 50)
	invitation, err := service.CreateInvitation(t.Context(), owner, CreateInvitationCommand{
		OrganizationID: organization.ID, IdempotencyKey: "archive-invitation-create", RequestID: "archive-invitation-create",
	})
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	archived, err := service.Archive(t.Context(), owner, ArchiveCommand{
		OrganizationID: organization.ID, ExpectedRevision: organization.Revision,
		IdempotencyKey: "organization-archive", RequestID: "organization-archive",
	})
	if err != nil || archived.Status != OrganizationStatusArchived || archived.Revision != 2 {
		t.Fatalf("Archive() = %+v, %v", archived, err)
	}
	replayed, err := service.Archive(t.Context(), owner, ArchiveCommand{
		OrganizationID: organization.ID, ExpectedRevision: organization.Revision,
		IdempotencyKey: "organization-archive", RequestID: "organization-archive-replay",
	})
	if err != nil || replayed.ID != archived.ID || replayed.Revision != archived.Revision {
		t.Fatalf("Archive(replay) = %+v, %v", replayed, err)
	}
	var invitationStatus string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT status FROM organization_invitations WHERE id = $1
	`, invitation.Invitation.ID).Scan(&invitationStatus); err != nil || invitationStatus != "revoked" {
		t.Fatalf("archived invitation status = %q, error = %v", invitationStatus, err)
	}
	restored, err := service.Restore(t.Context(), owner, RestoreCommand{
		OrganizationID: organization.ID, ExpectedRevision: archived.Revision,
		IdempotencyKey: "organization-restore", RequestID: "organization-restore",
	})
	if err != nil || restored.Status != OrganizationStatusActive || restored.Revision != 3 || restored.ArchivedAt != nil {
		t.Fatalf("Restore() = %+v, %v", restored, err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT status FROM organization_invitations WHERE id = $1
	`, invitation.Invitation.ID).Scan(&invitationStatus); err != nil || invitationStatus != "revoked" {
		t.Fatalf("restored invitation status = %q, error = %v", invitationStatus, err)
	}
}

func TestServiceOrganizationDissolutionIsGuardedTerminalAndReplaySafe(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	owner := fixture.actor(t, 130, "Dissolution Owner")
	outsider := fixture.actor(t, 131, "Dissolution Outsider")
	organization, err := fixture.repository.Create(fixture.ctx, fixture.createTransaction(owner, "Terminal Research", 130, 3))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	fixture.repository.assetGuard = stubOrganizationAssetGuard{}
	service := fixture.organizationService(t, 50)
	archived, err := service.Archive(t.Context(), owner, ArchiveCommand{
		OrganizationID: organization.ID, ExpectedRevision: 1,
		IdempotencyKey: "dissolve-archive", RequestID: "dissolve-archive",
	})
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	command := DissolveCommand{
		OrganizationID: organization.ID, DisplayName: organization.DisplayName,
		ExpectedRevision: archived.Revision, Confirmation: DissolveOrganizationConfirmation,
		IdempotencyKey: "organization-dissolve", RequestID: "organization-dissolve",
	}
	dissolved, err := service.Dissolve(t.Context(), owner, command)
	if err != nil || dissolved.Status != OrganizationStatusDissolved || dissolved.MutationState != MutationStateDissolved ||
		dissolved.Revision != 3 || strings.Contains(dissolved.DisplayName, organization.DisplayName) {
		t.Fatalf("Dissolve() = %+v, %v", dissolved, err)
	}
	replayed, err := service.Dissolve(t.Context(), owner, command)
	if err != nil || replayed.ID != dissolved.ID || replayed.Status != OrganizationStatusDissolved {
		t.Fatalf("Dissolve(replay) = %+v, %v", replayed, err)
	}
	if _, err := service.Dissolve(t.Context(), outsider, command); !errors.Is(err, ErrOrganizationNotFound) {
		t.Fatalf("Dissolve(outsider replay) error = %v", err)
	}
	for table, want := range map[string]int{
		"organization_memberships":      0,
		"organization_departments":      0,
		"organization_invitations":      0,
		"organization_policy_snapshots": 1,
	} {
		var count int
		if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM `+table+` WHERE organization_id = $1`, organization.ID).Scan(&count); err != nil || count != want {
			t.Fatalf("%s rows after dissolution = %d, error = %v", table, count, err)
		}
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations SET status = 'active', dissolved_at = NULL, archived_at = NULL WHERE id = $1
	`, organization.ID); err == nil {
		t.Fatal("dissolved Organization returned to active")
	}
}

func TestServiceOrganizationDissolutionPreconditionsFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *organizationRepositoryFixture, *Service, Actor, OrganizationSummary)
	}{
		{
			name: "asset blocker",
			setup: func(_ *testing.T, fixture *organizationRepositoryFixture, _ *Service, _ Actor, _ OrganizationSummary) {
				fixture.repository.assetGuard = stubOrganizationAssetGuard{blockers: []string{"organization_agent_definition"}}
			},
		},
		{
			name: "additional member",
			setup: func(t *testing.T, fixture *organizationRepositoryFixture, _ *Service, _ Actor, organization OrganizationSummary) {
				member := fixture.actor(t, 142, "Remaining Member")
				fixture.addMembership(t, organization.ID, member.UserID, RoleMember)
			},
		},
		{
			name: "pending invitation",
			setup: func(t *testing.T, fixture *organizationRepositoryFixture, _ *Service, owner Actor, organization OrganizationSummary) {
				secret, err := NewInvitationSecret(bytes.NewReader(bytes.Repeat([]byte{0xd1}, 32)))
				if err != nil {
					t.Fatalf("NewInvitationSecret() error = %v", err)
				}
				createdAt := fixture.now.Add(2 * time.Hour)
				if _, err := fixture.postgres.Exec(fixture.ctx, `
					INSERT INTO organization_invitations (
						id, organization_id, token_digest, created_by_user_id, status, created_at, expires_at
					) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
				`, uuid.New(), organization.ID, secret.Digest[:], owner.UserID, createdAt, createdAt.Add(7*24*time.Hour)); err != nil {
					t.Fatalf("seed pending invitation: %v", err)
				}
			},
		},
		{
			name: "assigned Department",
			setup: func(t *testing.T, fixture *organizationRepositoryFixture, service *Service, owner Actor, organization OrganizationSummary) {
				if _, err := fixture.postgres.Exec(fixture.ctx, `UPDATE organizations SET status = 'active', archived_at = NULL WHERE id = $1`, organization.ID); err != nil {
					t.Fatalf("temporarily activate fixture: %v", err)
				}
				department, err := service.CreateDepartment(t.Context(), owner, CreateDepartmentCommand{
					OrganizationID: organization.ID, DisplayName: "Assigned", RequestID: "dissolve-department-create",
				})
				if err != nil {
					t.Fatalf("CreateDepartment() error = %v", err)
				}
				if _, err := service.PatchMember(t.Context(), owner, PatchMemberCommand{
					OrganizationID: organization.ID, UserID: owner.UserID,
					ChangeDepartment: true, DepartmentID: &department.ID,
					ExpectedRevision: 1, RequestID: "dissolve-department-assign",
				}); !errors.Is(err, ErrOrganizationForbidden) {
					t.Fatalf("Owner assignment expected current Owner protection, error = %v", err)
				}
				if _, err := fixture.postgres.Exec(fixture.ctx, `
					UPDATE organization_memberships SET department_id = $2 WHERE organization_id = $1 AND user_id = $3
				`, organization.ID, department.ID, owner.UserID); err != nil {
					t.Fatalf("seed assigned Owner Department: %v", err)
				}
				if _, err := fixture.postgres.Exec(fixture.ctx, `
					UPDATE organizations SET status = 'archived', archived_at = $2 WHERE id = $1
				`, organization.ID, fixture.now.Add(3*time.Hour)); err != nil {
					t.Fatalf("re-archive fixture: %v", err)
				}
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOrganizationRepositoryFixture(t)
			owner := fixture.actor(t, byte(140+index*4), "Blocked Owner")
			organization, err := fixture.repository.Create(fixture.ctx, fixture.createTransaction(owner, "Blocked Dissolution", byte(140+index*4), 3))
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			fixture.repository.assetGuard = stubOrganizationAssetGuard{}
			service := fixture.organizationService(t, 50)
			archived, err := service.Archive(t.Context(), owner, ArchiveCommand{
				OrganizationID: organization.ID, ExpectedRevision: 1,
				IdempotencyKey: fmt.Sprintf("blocked-archive-%d", index), RequestID: fmt.Sprintf("blocked-archive-%d", index),
			})
			if err != nil {
				t.Fatalf("Archive() error = %v", err)
			}
			test.setup(t, fixture, service, owner, organization)
			_, err = service.Dissolve(t.Context(), owner, DissolveCommand{
				OrganizationID: organization.ID, DisplayName: organization.DisplayName,
				ExpectedRevision: archived.Revision, Confirmation: DissolveOrganizationConfirmation,
				IdempotencyKey: fmt.Sprintf("blocked-dissolve-%d", index), RequestID: fmt.Sprintf("blocked-dissolve-%d", index),
			})
			if !errors.Is(err, ErrDissolutionBlocked) {
				t.Fatalf("Dissolve(%s) error = %v", test.name, err)
			}
		})
	}
}

func TestServiceOrganizationLifecycleRequiresOwnerExactConfirmationAndAvailableGuard(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 150)
	service := fixture.organizationService(t, 50)
	if _, err := service.Archive(t.Context(), actors[RoleAdmin], ArchiveCommand{
		OrganizationID: organization.ID, ExpectedRevision: organization.Revision,
		IdempotencyKey: "archive-by-admin", RequestID: "archive-by-admin",
	}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("Archive(Admin) error = %v", err)
	}
	archived, err := service.Archive(t.Context(), actors[RoleOwner], ArchiveCommand{
		OrganizationID: organization.ID, ExpectedRevision: organization.Revision,
		IdempotencyKey: "archive-exact", RequestID: "archive-exact",
	})
	if err != nil {
		t.Fatalf("Archive(Owner) error = %v", err)
	}
	if _, err := service.Restore(t.Context(), actors[RoleAdmin], RestoreCommand{
		OrganizationID: organization.ID, ExpectedRevision: archived.Revision,
		IdempotencyKey: "restore-by-admin", RequestID: "restore-by-admin",
	}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("Restore(Admin) error = %v", err)
	}
	base := DissolveCommand{
		OrganizationID: organization.ID, DisplayName: organization.DisplayName,
		ExpectedRevision: archived.Revision, Confirmation: DissolveOrganizationConfirmation,
		IdempotencyKey: "dissolve-exact", RequestID: "dissolve-exact",
	}
	wrongConfirmation := base
	wrongConfirmation.Confirmation = "DISSOLVE"
	if _, err := service.Dissolve(t.Context(), actors[RoleOwner], wrongConfirmation); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Dissolve(wrong confirmation) error = %v", err)
	}
	wrongName := base
	wrongName.DisplayName = "Different Organization"
	if _, err := service.Dissolve(t.Context(), actors[RoleOwner], wrongName); !errors.Is(err, ErrOrganizationConflict) {
		t.Fatalf("Dissolve(wrong display name) error = %v", err)
	}
	nonExactName := base
	nonExactName.DisplayName = "  " + organization.DisplayName + "  "
	if _, err := service.Dissolve(t.Context(), actors[RoleOwner], nonExactName); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Dissolve(non-exact display name) error = %v", err)
	}
	wrongRevision := base
	wrongRevision.ExpectedRevision++
	if _, err := service.Dissolve(t.Context(), actors[RoleOwner], wrongRevision); !errors.Is(err, ErrOrganizationConflict) {
		t.Fatalf("Dissolve(wrong revision) error = %v", err)
	}
	if _, err := service.Dissolve(t.Context(), actors[RoleOwner], base); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("Dissolve(missing asset guard) error = %v", err)
	}
	fixture.repository.assetGuard = stubOrganizationAssetGuard{err: errors.New("asset service unavailable")}
	if _, err := service.Dissolve(t.Context(), actors[RoleOwner], base); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("Dissolve(failing asset guard) error = %v", err)
	}
}

func TestServiceOrganizationRestoreRechecksOwnedQuota(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	owner := fixture.actor(t, 155, "Quota Owner")
	organizations := make([]OrganizationSummary, 0, 4)
	for index := 0; index < 4; index++ {
		discriminator := byte(155 + index)
		organization, err := fixture.repository.Create(fixture.ctx, fixture.createTransaction(
			owner, fmt.Sprintf("Quota Organization %d", index+1), discriminator, 10,
		))
		if err != nil {
			t.Fatalf("Create(%d) error = %v", index, err)
		}
		organizations = append(organizations, organization)
	}
	service := fixture.organizationService(t, 50)
	archived, err := service.Archive(t.Context(), owner, ArchiveCommand{
		OrganizationID: organizations[0].ID, ExpectedRevision: organizations[0].Revision,
		IdempotencyKey: "quota-archive", RequestID: "quota-archive",
	})
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	if _, err := service.Restore(t.Context(), owner, RestoreCommand{
		OrganizationID: archived.ID, ExpectedRevision: archived.Revision,
		IdempotencyKey: "quota-restore", RequestID: "quota-restore",
	}); !errors.Is(err, ErrOrganizationLimitReached) {
		t.Fatalf("Restore(over quota) error = %v", err)
	}
}

type stubOrganizationAssetGuard struct {
	blockers []string
	err      error
}

func (s stubOrganizationAssetGuard) DissolutionBlockers(_ context.Context, _ uuid.UUID) ([]string, error) {
	return append([]string(nil), s.blockers...), s.err
}

func TestServiceOrganizationPolicyPublicationIsMonotonicAndRoleGated(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 160)
	service := fixture.organizationService(t, 50)
	secondDocument := DefaultPolicyDocument()
	secondDocument.Tools.Allowlist = []string{"browser.open", "files.read"}
	second, err := service.PublishPolicy(t.Context(), actors[RoleOwner], PublishPolicyCommand{
		OrganizationID: organization.ID, Document: secondDocument,
		ExpectedOrganizationRevision: organization.Revision, ExpectedPolicyVersion: 2,
		IdempotencyKey: "policy-publish-v2", RequestID: "policy-publish-v2",
	})
	if err != nil || second.PolicyVersion != 2 || second.Document.SchemaVersion != 1 || len(second.Signature) == 0 {
		t.Fatalf("PublishPolicy(v2) = %+v, %v", second, err)
	}
	replayed, err := service.PublishPolicy(t.Context(), actors[RoleOwner], PublishPolicyCommand{
		OrganizationID: organization.ID, Document: secondDocument,
		ExpectedOrganizationRevision: organization.Revision, ExpectedPolicyVersion: 2,
		IdempotencyKey: "policy-publish-v2", RequestID: "policy-publish-v2-replay",
	})
	if err != nil || replayed.ID != second.ID || replayed.PolicyVersion != 2 {
		t.Fatalf("PublishPolicy(replay) = %+v, %v", replayed, err)
	}
	conflictingDocument := DefaultPolicyDocument()
	conflictingDocument.Tools.Allowlist = []string{"different.tool"}
	if _, err := service.PublishPolicy(t.Context(), actors[RoleOwner], PublishPolicyCommand{
		OrganizationID: organization.ID, Document: conflictingDocument,
		ExpectedOrganizationRevision: organization.Revision, ExpectedPolicyVersion: 2,
		IdempotencyKey: "policy-publish-v2", RequestID: "policy-publish-v2-conflict",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("PublishPolicy(conflicting replay) error = %v", err)
	}
	thirdDocument := DefaultPolicyDocument()
	thirdDocument.OfficialAgents.Installation = OfficialAgentInstallationBlocked
	third, err := service.PublishPolicy(t.Context(), actors[RoleAdmin], PublishPolicyCommand{
		OrganizationID: organization.ID, Document: thirdDocument,
		ExpectedOrganizationRevision: 2, ExpectedPolicyVersion: 3,
		IdempotencyKey: "policy-publish-v3", RequestID: "policy-publish-v3",
	})
	if err != nil || third.PolicyVersion != 3 {
		t.Fatalf("PublishPolicy(v3 Admin) = %+v, %v", third, err)
	}
	if _, err := service.PublishPolicy(t.Context(), actors[RoleOwner], PublishPolicyCommand{
		OrganizationID: organization.ID, Document: DefaultPolicyDocument(),
		ExpectedOrganizationRevision: 3, ExpectedPolicyVersion: 5,
		IdempotencyKey: "policy-version-gap", RequestID: "policy-version-gap",
	}); !errors.Is(err, ErrPolicyVersionConflict) {
		t.Fatalf("PublishPolicy(version gap) error = %v", err)
	}
	for _, role := range []Role{RoleAuditor, RoleMember} {
		_, err := service.PublishPolicy(t.Context(), actors[role], PublishPolicyCommand{
			OrganizationID: organization.ID, Document: DefaultPolicyDocument(),
			ExpectedOrganizationRevision: 3, ExpectedPolicyVersion: 4,
			IdempotencyKey: "policy-forbidden-" + string(role), RequestID: "policy-forbidden-" + string(role),
		})
		if !errors.Is(err, ErrOrganizationForbidden) {
			t.Fatalf("PublishPolicy(%s) error = %v", role, err)
		}
	}
	firstPage, err := service.ListPolicySnapshots(t.Context(), actors[RoleAuditor], organization.ID, Page{Limit: 2})
	if err != nil || len(firstPage.Items) != 2 || firstPage.Items[0].PolicyVersion != 3 || firstPage.Next == nil {
		t.Fatalf("ListPolicySnapshots(first) = %+v, %v", firstPage, err)
	}
	secondPage, err := service.ListPolicySnapshots(t.Context(), actors[RoleAuditor], organization.ID, Page{Limit: 2, After: firstPage.Next})
	if err != nil || len(secondPage.Items) != 1 || secondPage.Items[0].PolicyVersion != 1 || secondPage.Next != nil {
		t.Fatalf("ListPolicySnapshots(second) = %+v, %v", secondPage, err)
	}
	detail, err := service.GetPolicySnapshot(t.Context(), actors[RoleAdmin], second.ID)
	if err != nil || detail.ID != second.ID || detail.Document.SchemaVersion != 1 || len(detail.Signature) == 0 {
		t.Fatalf("GetPolicySnapshot(Admin) = %+v, %v", detail, err)
	}
	if _, err := service.ListPolicySnapshots(t.Context(), actors[RoleMember], organization.ID, Page{Limit: 20}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("ListPolicySnapshots(Member) error = %v", err)
	}
	if _, err := service.GetPolicySnapshot(t.Context(), actors[RoleMember], second.ID); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("GetPolicySnapshot(Member) error = %v", err)
	}
	if _, err := service.ListPolicySnapshots(t.Context(), actors["outsider"], organization.ID, Page{Limit: 20}); !errors.Is(err, ErrOrganizationNotFound) {
		t.Fatalf("ListPolicySnapshots(outsider) error = %v", err)
	}
}

func TestServiceOrganizationPolicyPublicationRaceHasOneWinner(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	owner := fixture.actor(t, 170, "Policy Race Owner")
	organization, err := fixture.repository.Create(fixture.ctx, fixture.createTransaction(owner, "Policy Race", 170, 3))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	service := fixture.organizationService(t, 50)
	start := make(chan struct{})
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			document := DefaultPolicyDocument()
			document.Tools.Allowlist = []string{fmt.Sprintf("tool.%d", index)}
			_, publishErr := service.PublishPolicy(t.Context(), owner, PublishPolicyCommand{
				OrganizationID: organization.ID, Document: document,
				ExpectedOrganizationRevision: 1, ExpectedPolicyVersion: 2,
				IdempotencyKey: fmt.Sprintf("policy-race-%d", index), RequestID: fmt.Sprintf("policy-race-%d", index),
			})
			results <- publishErr
		}()
	}
	close(start)
	successes := 0
	conflicts := 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrPolicyVersionConflict), errors.Is(err, ErrOrganizationConflict):
			conflicts++
		default:
			t.Fatalf("concurrent PublishPolicy error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("policy race successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestServiceOrganizationPolicyPublicationRollsBackOnSignerOrAuditFailure(t *testing.T) {
	for index, test := range []struct {
		name      string
		configure func(*testing.T, *organizationRepositoryFixture) func() (uuid.UUID, error)
	}{
		{
			name: "signer failure",
			configure: func(_ *testing.T, fixture *organizationRepositoryFixture) func() (uuid.UUID, error) {
				fixture.repository.signer = failingPolicySigner{}
				return uuid.NewRandom
			},
		},
		{
			name: "audit failure",
			configure: func(t *testing.T, fixture *organizationRepositoryFixture) func() (uuid.UUID, error) {
				snapshotID := uuid.New()
				auditID := uuid.New()
				if _, err := fixture.postgres.Exec(fixture.ctx, `
					INSERT INTO audit_events (id, event_type, outcome, metadata, created_at)
					VALUES ($1, 'browser_login', 'success', '{}'::jsonb, $2)
				`, auditID, fixture.now); err != nil {
					t.Fatalf("seed duplicate audit: %v", err)
				}
				ids := []uuid.UUID{snapshotID, auditID}
				return func() (uuid.UUID, error) {
					value := ids[0]
					ids = ids[1:]
					return value, nil
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOrganizationRepositoryFixture(t)
			owner := fixture.actor(t, byte(190+index), "Rollback Policy Owner")
			organization, err := fixture.repository.Create(fixture.ctx, fixture.createTransaction(
				owner, "Rollback Policy", byte(190+index), 3,
			))
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			newUUID := test.configure(t, fixture)
			service, err := NewService(ServiceConfig{
				Repository: fixture.repository, OwnedLimit: 3, DepartmentLimit: 50,
				MemberLimit: 500, PendingInvitationLimit: 100,
				Clock: func() time.Time { return fixture.now.Add(12 * time.Hour) }, NewUUID: newUUID,
			})
			if err != nil {
				t.Fatalf("NewService() error = %v", err)
			}
			if _, err := service.PublishPolicy(t.Context(), owner, PublishPolicyCommand{
				OrganizationID: organization.ID, Document: DefaultPolicyDocument(),
				ExpectedOrganizationRevision: 1, ExpectedPolicyVersion: 2,
				IdempotencyKey: "policy-rollback", RequestID: "policy-rollback",
			}); !errors.Is(err, ErrServiceUnavailable) {
				t.Fatalf("PublishPolicy() error = %v", err)
			}
			var policyCount int
			var revision int64
			if err := fixture.postgres.QueryRow(fixture.ctx, `
				SELECT (SELECT count(*) FROM organization_policy_snapshots WHERE organization_id = $1), revision
				FROM organizations WHERE id = $1
			`, organization.ID).Scan(&policyCount, &revision); err != nil || policyCount != 1 || revision != 1 {
				t.Fatalf("rollback policy_count=%d revision=%d error=%v", policyCount, revision, err)
			}
		})
	}
}

func TestServiceOrganizationAuditIsPrivilegedAndKeysetPaged(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 180)
	service := fixture.organizationService(t, 50)
	if _, err := service.Rename(t.Context(), actors[RoleOwner], RenameCommand{
		OrganizationID: organization.ID, DisplayName: "Audited Organization",
		ExpectedRevision: organization.Revision, RequestID: "audit-rename",
	}); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if _, err := service.CreateDepartment(t.Context(), actors[RoleAdmin], CreateDepartmentCommand{
		OrganizationID: organization.ID, DisplayName: "Audited Department", RequestID: "audit-department",
	}); err != nil {
		t.Fatalf("CreateDepartment() error = %v", err)
	}
	for _, role := range []Role{RoleOwner, RoleAdmin, RoleAuditor} {
		first, err := service.ListAudit(t.Context(), actors[role], organization.ID, Page{Limit: 2})
		if err != nil || len(first.Items) != 2 || first.Next == nil || first.Items[0].ActorDisplay == nil {
			t.Fatalf("ListAudit(%s first) = %+v, %v", role, first, err)
		}
		second, err := service.ListAudit(t.Context(), actors[role], organization.ID, Page{Limit: 2, After: first.Next})
		if err != nil || len(second.Items) != 1 || second.Next != nil {
			t.Fatalf("ListAudit(%s second) = %+v, %v", role, second, err)
		}
	}
	if _, err := service.ListAudit(t.Context(), actors[RoleMember], organization.ID, Page{Limit: 20}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("ListAudit(Member) error = %v", err)
	}
	if _, err := service.ListAudit(t.Context(), actors["outsider"], organization.ID, Page{Limit: 20}); !errors.Is(err, ErrOrganizationNotFound) {
		t.Fatalf("ListAudit(outsider) error = %v", err)
	}
}

func TestServiceOrganizationRoleMatrixRecomputesAuthorizationInTransaction(t *testing.T) {
	type operation struct {
		name    string
		allowed map[Role]bool
		invoke  func(*testing.T, *Service, Actor, OrganizationSummary, map[Role]Actor) error
	}
	operations := []operation{
		{
			name: "rename", allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, _ map[Role]Actor) error {
				_, err := service.Rename(t.Context(), actor, RenameCommand{
					OrganizationID: organization.ID, DisplayName: "Renamed Organization",
					ExpectedRevision: organization.Revision, RequestID: "matrix-rename",
				})
				return err
			},
		},
		{
			name: "create department", allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, _ map[Role]Actor) error {
				_, err := service.CreateDepartment(t.Context(), actor, CreateDepartmentCommand{
					OrganizationID: organization.ID, DisplayName: "Research", RequestID: "matrix-department",
				})
				return err
			},
		},
		{
			name: "rename department", allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, actors map[Role]Actor) error {
				department, err := service.CreateDepartment(t.Context(), actors[RoleOwner], CreateDepartmentCommand{
					OrganizationID: organization.ID, DisplayName: "Original Department", RequestID: "matrix-rename-department-seed",
				})
				if err != nil {
					t.Fatalf("seed Department: %v", err)
				}
				_, err = service.RenameDepartment(t.Context(), actor, RenameDepartmentCommand{
					OrganizationID: organization.ID, DepartmentID: department.ID, DisplayName: "Renamed Department",
					ExpectedRevision: 1, RequestID: "matrix-rename-department",
				})
				return err
			},
		},
		{
			name: "archive department", allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, actors map[Role]Actor) error {
				department, err := service.CreateDepartment(t.Context(), actors[RoleOwner], CreateDepartmentCommand{
					OrganizationID: organization.ID, DisplayName: "Archive Department", RequestID: "matrix-archive-department-seed",
				})
				if err != nil {
					t.Fatalf("seed Department: %v", err)
				}
				_, err = service.ArchiveDepartment(t.Context(), actor, DepartmentLifecycleCommand{
					OrganizationID: organization.ID, DepartmentID: department.ID,
					ExpectedRevision: 1, RequestID: "matrix-archive-department",
				})
				return err
			},
		},
		{
			name: "restore department", allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, actors map[Role]Actor) error {
				department, err := service.CreateDepartment(t.Context(), actors[RoleOwner], CreateDepartmentCommand{
					OrganizationID: organization.ID, DisplayName: "Restore Department", RequestID: "matrix-restore-department-seed",
				})
				if err != nil {
					t.Fatalf("seed Department: %v", err)
				}
				department, err = service.ArchiveDepartment(t.Context(), actors[RoleOwner], DepartmentLifecycleCommand{
					OrganizationID: organization.ID, DepartmentID: department.ID,
					ExpectedRevision: 1, RequestID: "matrix-restore-department-archive",
				})
				if err != nil {
					t.Fatalf("archive Department fixture: %v", err)
				}
				_, err = service.RestoreDepartment(t.Context(), actor, DepartmentLifecycleCommand{
					OrganizationID: organization.ID, DepartmentID: department.ID,
					ExpectedRevision: department.Revision, RequestID: "matrix-restore-department",
				})
				return err
			},
		},
		{
			name: "patch member", allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, actors map[Role]Actor) error {
				_, err := service.PatchMember(t.Context(), actor, PatchMemberCommand{
					OrganizationID: organization.ID, UserID: actors[RoleMember].UserID,
					Role: rolePointer(RoleAuditor), ExpectedRevision: 1, RequestID: "matrix-patch-member",
				})
				return err
			},
		},
		{
			name: "remove member", allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, actors map[Role]Actor) error {
				return service.RemoveMember(t.Context(), actor, RemoveMemberCommand{
					OrganizationID: organization.ID, UserID: actors[RoleMember].UserID,
					ExpectedRevision: 1, RequestID: "matrix-remove-member",
				})
			},
		},
		{
			name: "transfer Owner", allowed: map[Role]bool{RoleOwner: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, actors map[Role]Actor) error {
				target := actors[RoleAdmin]
				if target.UserID == actor.UserID {
					target = actors[RoleOwner]
				}
				_, err := service.TransferOwner(t.Context(), actor, OwnerTransferCommand{
					OrganizationID: organization.ID, TargetUserID: target.UserID,
					ExpectedOrganizationRevision: organization.Revision,
					ExpectedOwnerRevision:        1, ExpectedTargetRevision: 1,
					Confirmation: TransferOrganizationOwnerConfirmation, RequestID: "matrix-transfer",
				})
				return err
			},
		},
		{
			name: "leave", allowed: map[Role]bool{RoleAdmin: true, RoleAuditor: true, RoleMember: true},
			invoke: func(t *testing.T, service *Service, actor Actor, organization OrganizationSummary, _ map[Role]Actor) error {
				return service.Leave(t.Context(), actor, LeaveCommand{
					OrganizationID: organization.ID, RequestID: "matrix-leave",
				})
			},
		},
	}
	roles := []Role{RoleOwner, RoleAdmin, RoleAuditor, RoleMember, "outsider"}
	for _, operation := range operations {
		for _, role := range roles {
			t.Run(operation.name+"/"+string(role), func(t *testing.T) {
				fixture := newOrganizationRepositoryFixture(t)
				actors, organization := fixture.organizationWithRoles(t, byte(len(operation.name)+len(role)))
				actor := actors[role]
				service := fixture.organizationService(t, 50)
				err := operation.invoke(t, service, actor, organization, actors)
				switch {
				case operation.allowed[role] && err != nil:
					t.Fatalf("%s by %s error = %v", operation.name, role, err)
				case !operation.allowed[role] && role == "outsider" && !errors.Is(err, ErrOrganizationNotFound):
					t.Fatalf("%s by outsider error = %v", operation.name, err)
				case !operation.allowed[role] && role != "outsider" && !errors.Is(err, ErrOrganizationForbidden):
					t.Fatalf("%s by %s error = %v", operation.name, role, err)
				}
			})
		}
	}
}

func TestServiceMembershipAuthorizationRevisionAndDepartmentIsolation(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 60)
	service := fixture.organizationService(t, 50)
	member := actors[RoleMember]
	admin := actors[RoleAdmin]
	owner := actors[RoleOwner]

	patched, err := service.PatchMember(t.Context(), admin, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: member.UserID, Role: rolePointer(RoleAuditor),
		ExpectedRevision: 1, RequestID: "member-to-auditor",
	})
	if err != nil || patched.Role != RoleAuditor || patched.Revision != 2 {
		t.Fatalf("PatchMember(Member to Auditor) = %+v, %v", patched, err)
	}
	if _, err := service.PatchMember(t.Context(), admin, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: member.UserID, Role: rolePointer(RoleMember),
		ExpectedRevision: 1, RequestID: "stale-member",
	}); !errors.Is(err, ErrMembershipConflict) {
		t.Fatalf("PatchMember(stale) error = %v", err)
	}
	if _, err := service.PatchMember(t.Context(), admin, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: admin.UserID, Role: rolePointer(RoleMember),
		ExpectedRevision: 1, RequestID: "admin-mutates-admin",
	}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("PatchMember(Admin target) error = %v", err)
	}
	if _, err := service.PatchMember(t.Context(), owner, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: owner.UserID, Role: rolePointer(RoleMember),
		ExpectedRevision: 1, RequestID: "owner-demotes-self",
	}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("PatchMember(Owner self) error = %v", err)
	}
	if _, err := service.PatchMember(t.Context(), admin, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: member.UserID, Role: rolePointer(RoleAdmin),
		ExpectedRevision: 2, RequestID: "admin-promotes-admin",
	}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("PatchMember(Admin promotion) error = %v", err)
	}
	promoted, err := service.PatchMember(t.Context(), owner, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: member.UserID, Role: rolePointer(RoleAdmin),
		ExpectedRevision: 2, RequestID: "owner-promotes-admin",
	})
	if err != nil || promoted.Role != RoleAdmin || promoted.Revision != 3 {
		t.Fatalf("PatchMember(Owner promotion) = %+v, %v", promoted, err)
	}

	otherCommand := fixture.createTransaction(owner, "Other Organization", 61, 3)
	other, err := fixture.repository.Create(fixture.ctx, otherCommand)
	if err != nil {
		t.Fatalf("Create(other Organization) error = %v", err)
	}
	otherDepartment, err := service.CreateDepartment(t.Context(), owner, CreateDepartmentCommand{
		OrganizationID: other.ID, DisplayName: "Other Department", RequestID: "other-department",
	})
	if err != nil {
		t.Fatalf("CreateDepartment(other) error = %v", err)
	}
	if _, err := service.PatchMember(t.Context(), owner, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: actors[RoleAuditor].UserID,
		ChangeDepartment: true, DepartmentID: &otherDepartment.ID,
		ExpectedRevision: 1, RequestID: "cross-organization-department",
	}); !errors.Is(err, ErrMembershipConflict) {
		t.Fatalf("PatchMember(cross Organization Department) error = %v", err)
	}
	if err := service.RemoveMember(t.Context(), admin, RemoveMemberCommand{
		OrganizationID: organization.ID, UserID: admin.UserID, ExpectedRevision: 1, RequestID: "admin-removes-admin",
	}); !errors.Is(err, ErrOrganizationForbidden) {
		t.Fatalf("RemoveMember(Admin target) error = %v", err)
	}
}

func TestServiceArchivedOrganizationAllowsOnlyOwnerTransferFromThisSlice(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 65)
	owner := actors[RoleOwner]
	admin := actors[RoleAdmin]
	member := actors[RoleMember]
	service := fixture.organizationService(t, 50)
	archivedAt := fixture.now.Add(time.Hour)
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations
		SET status = 'archived', revision = 2, archived_at = $2, updated_at = $2
		WHERE id = $1
	`, organization.ID, archivedAt); err != nil {
		t.Fatalf("archive Organization fixture: %v", err)
	}
	operations := []struct {
		name   string
		invoke func() error
	}{
		{name: "rename", invoke: func() error {
			_, err := service.Rename(t.Context(), owner, RenameCommand{
				OrganizationID: organization.ID, DisplayName: "Blocked Rename", ExpectedRevision: 2, RequestID: "archived-rename",
			})
			return err
		}},
		{name: "patch member", invoke: func() error {
			_, err := service.PatchMember(t.Context(), owner, PatchMemberCommand{
				OrganizationID: organization.ID, UserID: member.UserID, Role: rolePointer(RoleAuditor),
				ExpectedRevision: 1, RequestID: "archived-patch",
			})
			return err
		}},
		{name: "remove member", invoke: func() error {
			return service.RemoveMember(t.Context(), owner, RemoveMemberCommand{
				OrganizationID: organization.ID, UserID: member.UserID, ExpectedRevision: 1, RequestID: "archived-remove",
			})
		}},
		{name: "leave", invoke: func() error {
			return service.Leave(t.Context(), member, LeaveCommand{OrganizationID: organization.ID, RequestID: "archived-leave"})
		}},
		{name: "create department", invoke: func() error {
			_, err := service.CreateDepartment(t.Context(), owner, CreateDepartmentCommand{
				OrganizationID: organization.ID, DisplayName: "Blocked Department", RequestID: "archived-department",
			})
			return err
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.invoke(); !errors.Is(err, ErrOrganizationArchived) {
				t.Fatalf("archived %s error = %v", operation.name, err)
			}
		})
	}
	transferred, err := service.TransferOwner(t.Context(), owner, OwnerTransferCommand{
		OrganizationID: organization.ID, TargetUserID: admin.UserID,
		ExpectedOrganizationRevision: 2, ExpectedOwnerRevision: 1, ExpectedTargetRevision: 1,
		Confirmation: TransferOrganizationOwnerConfirmation, RequestID: "archived-transfer",
	})
	if err != nil || transferred.Status != OrganizationStatusArchived || transferred.Role != RoleAdmin || transferred.Revision != 3 {
		t.Fatalf("TransferOwner(archived) = %+v, %v", transferred, err)
	}
}

func TestServiceDepartmentQuotaUniquenessArchiveAndRestore(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 70)
	owner := actors[RoleOwner]
	service := fixture.organizationService(t, 50)

	department, err := service.CreateDepartment(t.Context(), owner, CreateDepartmentCommand{
		OrganizationID: organization.ID, DisplayName: "Caf\u00e9", RequestID: "department-cafe",
	})
	if err != nil {
		t.Fatalf("CreateDepartment() error = %v", err)
	}
	if _, err := service.CreateDepartment(t.Context(), owner, CreateDepartmentCommand{
		OrganizationID: organization.ID, DisplayName: "Cafe\u0301", RequestID: "department-duplicate",
	}); !errors.Is(err, ErrOrganizationConflict) {
		t.Fatalf("CreateDepartment(normalized duplicate) error = %v", err)
	}
	service = fixture.organizationService(t, 1)
	if _, err := service.CreateDepartment(t.Context(), owner, CreateDepartmentCommand{
		OrganizationID: organization.ID, DisplayName: "Second Department", RequestID: "department-over-quota",
	}); !errors.Is(err, ErrDepartmentLimitReached) {
		t.Fatalf("CreateDepartment(over quota) error = %v", err)
	}

	member := actors[RoleMember]
	assigned, err := service.PatchMember(t.Context(), owner, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: member.UserID,
		ChangeDepartment: true, DepartmentID: &department.ID,
		ExpectedRevision: 1, RequestID: "department-assign",
	})
	if err != nil || assigned.DepartmentID == nil || *assigned.DepartmentID != department.ID {
		t.Fatalf("PatchMember(assign) = %+v, %v", assigned, err)
	}
	if _, err := service.ArchiveDepartment(t.Context(), owner, DepartmentLifecycleCommand{
		OrganizationID: organization.ID, DepartmentID: department.ID,
		ExpectedRevision: 1, RequestID: "department-not-empty",
	}); !errors.Is(err, ErrDepartmentNotEmpty) {
		t.Fatalf("ArchiveDepartment(non-empty) error = %v", err)
	}
	if _, err := service.PatchMember(t.Context(), owner, PatchMemberCommand{
		OrganizationID: organization.ID, UserID: member.UserID,
		ChangeDepartment: true, ClearDepartment: true,
		ExpectedRevision: 2, RequestID: "department-clear",
	}); err != nil {
		t.Fatalf("PatchMember(clear Department) error = %v", err)
	}
	archived, err := service.ArchiveDepartment(t.Context(), owner, DepartmentLifecycleCommand{
		OrganizationID: organization.ID, DepartmentID: department.ID,
		ExpectedRevision: 1, RequestID: "department-archive",
	})
	if err != nil || archived.Status != DepartmentStatusArchived || archived.Revision != 2 {
		t.Fatalf("ArchiveDepartment() = %+v, %v", archived, err)
	}
	replacement, err := service.CreateDepartment(t.Context(), owner, CreateDepartmentCommand{
		OrganizationID: organization.ID, DisplayName: "Caf\u00e9", RequestID: "department-replacement",
	})
	if err != nil || replacement.Status != DepartmentStatusActive {
		t.Fatalf("CreateDepartment(replacement) = %+v, %v", replacement, err)
	}
	if _, err := service.RestoreDepartment(t.Context(), owner, DepartmentLifecycleCommand{
		OrganizationID: organization.ID, DepartmentID: department.ID,
		ExpectedRevision: 2, RequestID: "department-restore-over-quota",
	}); !errors.Is(err, ErrDepartmentLimitReached) {
		t.Fatalf("RestoreDepartment(over quota) error = %v", err)
	}
	service = fixture.organizationService(t, 50)
	if _, err := service.RestoreDepartment(t.Context(), owner, DepartmentLifecycleCommand{
		OrganizationID: organization.ID, DepartmentID: department.ID,
		ExpectedRevision: 2, RequestID: "department-restore-collision",
	}); !errors.Is(err, ErrOrganizationConflict) {
		t.Fatalf("RestoreDepartment(name collision) error = %v", err)
	}
}

func TestServiceConcurrentMemberChangesHaveOneRevisionWinner(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 80)
	service := fixture.organizationService(t, 50)
	owner := actors[RoleOwner]
	member := actors[RoleMember]
	commands := []PatchMemberCommand{
		{OrganizationID: organization.ID, UserID: member.UserID, Role: rolePointer(RoleAuditor), ExpectedRevision: 1, RequestID: "race-auditor"},
		{OrganizationID: organization.ID, UserID: member.UserID, Role: rolePointer(RoleAdmin), ExpectedRevision: 1, RequestID: "race-admin"},
	}
	start := make(chan struct{})
	results := make(chan error, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			_, err := service.PatchMember(t.Context(), owner, command)
			results <- err
		}()
	}
	close(start)
	successes := 0
	conflicts := 0
	for range commands {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrMembershipConflict):
			conflicts++
		default:
			t.Fatalf("concurrent PatchMember error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent PatchMember successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestServiceConcurrentOwnerTransfersCommitExactlyOneOwner(t *testing.T) {
	fixture := newOrganizationRepositoryFixture(t)
	actors, organization := fixture.organizationWithRoles(t, 90)
	owner := actors[RoleOwner]
	firstAdmin := actors[RoleAdmin]
	secondAdmin := fixture.actor(t, 96, "Second Admin")
	fixture.addMembership(t, organization.ID, secondAdmin.UserID, RoleAdmin)
	service := fixture.organizationService(t, 50)
	commands := []OwnerTransferCommand{
		{
			OrganizationID: organization.ID, TargetUserID: firstAdmin.UserID,
			ExpectedOrganizationRevision: 1, ExpectedOwnerRevision: 1, ExpectedTargetRevision: 1,
			Confirmation: TransferOrganizationOwnerConfirmation, RequestID: "transfer-first",
		},
		{
			OrganizationID: organization.ID, TargetUserID: secondAdmin.UserID,
			ExpectedOrganizationRevision: 1, ExpectedOwnerRevision: 1, ExpectedTargetRevision: 1,
			Confirmation: TransferOrganizationOwnerConfirmation, RequestID: "transfer-second",
		},
	}
	start := make(chan struct{})
	results := make(chan error, len(commands))
	var wait sync.WaitGroup
	for _, command := range commands {
		command := command
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := service.TransferOwner(t.Context(), owner, command)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	failures := 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrOrganizationConflict) || errors.Is(err, ErrOrganizationForbidden) {
			failures++
		} else {
			t.Fatalf("concurrent TransferOwner error = %v", err)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent Owner transfers successes=%d failures=%d", successes, failures)
	}
	var ownerCount int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM organization_memberships WHERE organization_id = $1 AND role = 'owner'
	`, organization.ID).Scan(&ownerCount); err != nil || ownerCount != 1 {
		t.Fatalf("Owner rows after race = %d, error = %v", ownerCount, err)
	}
}

func (f *organizationRepositoryFixture) organizationService(t *testing.T, departmentLimit int) *Service {
	t.Helper()
	service, err := NewService(ServiceConfig{
		Repository: f.repository, OwnedLimit: 3, DepartmentLimit: departmentLimit, MemberLimit: 500, PendingInvitationLimit: 100,
		Clock:   func() time.Time { return f.now.Add(12 * time.Hour) },
		NewUUID: uuid.NewRandom,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func (f *organizationRepositoryFixture) organizationWithRoles(
	t *testing.T,
	discriminator byte,
) (map[Role]Actor, OrganizationSummary) {
	t.Helper()
	actors := map[Role]Actor{
		RoleOwner:   f.actor(t, discriminator, "Owner"),
		RoleAdmin:   f.actor(t, discriminator+1, "Admin"),
		RoleAuditor: f.actor(t, discriminator+2, "Auditor"),
		RoleMember:  f.actor(t, discriminator+3, "Member"),
		"outsider":  f.actor(t, discriminator+4, "Outsider"),
	}
	organization, err := f.repository.Create(f.ctx, f.createTransaction(
		actors[RoleOwner], fmt.Sprintf("Matrix Organization %d", discriminator), discriminator, 3,
	))
	if err != nil {
		t.Fatalf("Create(matrix Organization) error = %v", err)
	}
	f.addMembership(t, organization.ID, actors[RoleAdmin].UserID, RoleAdmin)
	f.addMembership(t, organization.ID, actors[RoleAuditor].UserID, RoleAuditor)
	f.addMembership(t, organization.ID, actors[RoleMember].UserID, RoleMember)
	return actors, organization
}

func rolePointer(role Role) *Role {
	return &role
}
