package organization

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

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
		Repository: f.repository, DepartmentLimit: departmentLimit,
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
