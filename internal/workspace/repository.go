package workspace

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	operationWorkspaceCreate  = "workspace_create"
	operationInvitationCreate = "workspace_invitation_create"
	operationInvitationAccept = "workspace_invitation_accept"
)

type IdempotencyReplay string

const (
	IdempotencyFresh    IdempotencyReplay = "fresh"
	IdempotencyReplayed IdempotencyReplay = "replayed"
)

type IdempotencyEvidence struct {
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
	ExpiresAt     time.Time
}

type AuditEvidence struct {
	EventID   uuid.UUID
	RequestID string
}

type CreateCommand struct {
	WorkspaceID      uuid.UUID
	DisplayName      string
	ActiveOwnedLimit int
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	CreatedAt        time.Time
}

type RenameCommand struct {
	WorkspaceID      uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	Audit            AuditEvidence
	UpdatedAt        time.Time
}

type RevisionCommand struct {
	WorkspaceID      uuid.UUID
	ExpectedRevision int64
	ActiveOwnedLimit int
	Audit            AuditEvidence
	ChangedAt        time.Time
}

type Member struct {
	UserID   uuid.UUID
	Nickname string
	Role     Role
	Revision int64
	JoinedAt time.Time
}

type ChangeRoleCommand struct {
	WorkspaceID      uuid.UUID
	UserID           uuid.UUID
	Role             Role
	ExpectedRevision int64
	Audit            AuditEvidence
	ChangedAt        time.Time
}

type RemoveMemberCommand struct {
	WorkspaceID      uuid.UUID
	UserID           uuid.UUID
	ExpectedRevision int64
	Audit            AuditEvidence
	RemovedAt        time.Time
}

type InvitationStatus string

const (
	InvitationStatusPending  InvitationStatus = "pending"
	InvitationStatusAccepted InvitationStatus = "accepted"
	InvitationStatusRevoked  InvitationStatus = "revoked"
	InvitationStatusExpired  InvitationStatus = "expired"
)

type Invitation struct {
	ID               uuid.UUID
	Status           InvitationStatus
	CreatedByUserID  *uuid.UUID
	AcceptedByUserID *uuid.UUID
	CreatedAt        time.Time
	ExpiresAt        time.Time
	AcceptedAt       *time.Time
	RevokedAt        *time.Time
}

type InvitationCreation struct {
	Invitation Invitation
	Secret     *InvitationSecret
}

type Acceptance struct {
	Workspace Workspace
	Member    Member
}

type CreateInvitationCommand struct {
	InvitationID       uuid.UUID
	WorkspaceID        uuid.UUID
	Secret             InvitationSecret
	PendingInviteLimit int
	Idempotency        IdempotencyEvidence
	Audit              AuditEvidence
	CreatedAt          time.Time
}

type RevokeInvitationCommand struct {
	WorkspaceID  uuid.UUID
	InvitationID uuid.UUID
	Audit        AuditEvidence
	RevokedAt    time.Time
}

type AcceptInvitationCommand struct {
	TokenDigest [sha256.Size]byte
	MemberLimit int
	Idempotency IdempotencyEvidence
	Audit       AuditEvidence
	AcceptedAt  time.Time
}

type Repository interface {
	Create(context.Context, Actor, CreateCommand) (Workspace, IdempotencyReplay, error)
	List(context.Context, Actor) ([]Workspace, error)
	Rename(context.Context, Actor, RenameCommand) (Workspace, error)
	Archive(context.Context, Actor, RevisionCommand) (Workspace, error)
	Restore(context.Context, Actor, RevisionCommand) (Workspace, error)
	ListMembers(context.Context, Actor, uuid.UUID) ([]Member, error)
	ChangeMemberRole(context.Context, Actor, ChangeRoleCommand) (Member, error)
	RemoveMember(context.Context, Actor, RemoveMemberCommand) error
	Leave(context.Context, Actor, uuid.UUID) error
	ListInvitations(context.Context, Actor, uuid.UUID) ([]Invitation, error)
	CreateInvitation(context.Context, Actor, CreateInvitationCommand) (InvitationCreation, IdempotencyReplay, error)
	RevokeInvitation(context.Context, Actor, RevokeInvitationCommand) error
	AcceptInvitation(context.Context, Actor, AcceptInvitationCommand) (Acceptance, error)
}

type PostgresRepository struct {
	postgres *pgxpool.Pool
	clock    func() time.Time
	newUUID  func() (uuid.UUID, error)
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres, clock: time.Now, newUUID: uuid.NewRandom}
}

func (r *PostgresRepository) Create(
	ctx context.Context,
	actor Actor,
	command CreateCommand,
) (Workspace, IdempotencyReplay, error) {
	if r == nil || r.postgres == nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	if err := actor.Validate(); err != nil {
		return Workspace{}, "", err
	}
	displayName, err := NormalizeDisplayName(command.DisplayName)
	if err != nil || !validCreateCommand(command) {
		return Workspace{}, "", ErrInvalidRequest
	}

	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := lockActiveActor(ctx, tx, actor); err != nil {
		return Workspace{}, "", err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, workspaceIdempotencyLockID(
		actor,
		operationWorkspaceCreate,
		command.Idempotency.KeyDigest,
	)); err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}

	resourceID, found, err := readWorkspaceIdempotency(ctx, tx, actor, command.Idempotency)
	if err != nil {
		return Workspace{}, "", err
	}
	if found {
		workspace, err := loadWorkspace(ctx, tx, actor, resourceID, false)
		if err != nil {
			return Workspace{}, "", err
		}
		if err := commitWorkspaceTransaction(ctx, tx); err != nil {
			return Workspace{}, "", err
		}
		return workspace, IdempotencyReplayed, nil
	}

	var activeOwned int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM workspaces WHERE owner_user_id = $1 AND status = 'active'
	`, actor.UserID).Scan(&activeOwned); err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	if activeOwned >= command.ActiveOwnedLimit {
		return Workspace{}, "", ErrWorkspaceLimitReached
	}
	createdAt := command.CreatedAt.UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspaces (
			id, owner_user_id, display_name, status, revision, created_at, updated_at
		) VALUES ($1, $2, $3, 'active', 1, $4, $4)
	`, command.WorkspaceID, actor.UserID, displayName, createdAt); err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, command.WorkspaceID, actor.UserID, createdAt); err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_idempotency_records (
			actor_user_id, workspace_id, operation, key_digest, request_digest,
			resource_type, resource_id, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'workspace', $2, $6, $7)
	`, actor.UserID, command.WorkspaceID, operationWorkspaceCreate, command.Idempotency.KeyDigest[:],
		command.Idempotency.RequestDigest[:], createdAt, command.Idempotency.ExpiresAt.UTC()); err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_created", command.WorkspaceID, createdAt,
		map[string]string{"workspace_id": command.WorkspaceID.String()},
	); err != nil {
		return Workspace{}, "", err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, false)
	if err != nil {
		return Workspace{}, "", err
	}
	if err := commitWorkspaceTransaction(ctx, tx); err != nil {
		return Workspace{}, "", err
	}
	return workspace, IdempotencyFresh, nil
}

func (r *PostgresRepository) List(ctx context.Context, actor Actor) ([]Workspace, error) {
	if r == nil || r.postgres == nil {
		return nil, ErrServiceUnavailable
	}
	if err := actor.Validate(); err != nil {
		return nil, err
	}
	if err := requireActiveActor(ctx, r.postgres, actor); err != nil {
		return nil, err
	}
	rows, err := r.postgres.Query(ctx, workspaceListQuery, actor.UserID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rows.Close()
	workspaces := make([]Workspace, 0)
	for rows.Next() {
		workspace, scanErr := scanWorkspace(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		workspaces = append(workspaces, workspace)
	}
	if rows.Err() != nil {
		return nil, ErrServiceUnavailable
	}
	return workspaces, nil
}

func (r *PostgresRepository) Rename(
	ctx context.Context,
	actor Actor,
	command RenameCommand,
) (Workspace, error) {
	if r == nil || r.postgres == nil {
		return Workspace{}, ErrServiceUnavailable
	}
	if err := actor.Validate(); err != nil {
		return Workspace{}, err
	}
	displayName, err := NormalizeDisplayName(command.DisplayName)
	if err != nil || !validRenameCommand(command) {
		return Workspace{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return Workspace{}, err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, true)
	if err != nil {
		return Workspace{}, err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return Workspace{}, ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status == WorkspaceStatusArchived {
		return Workspace{}, ErrWorkspaceArchived
	}
	if workspace.ActorRole != RoleOwner && workspace.ActorRole != RoleAdmin {
		return Workspace{}, ErrWorkspaceForbidden
	}
	if workspace.Revision != command.ExpectedRevision {
		return Workspace{}, ErrWorkspaceConflict
	}
	updatedAt := command.UpdatedAt.UTC()
	if updatedAt.Before(workspace.UpdatedAt) {
		return Workspace{}, ErrInvalidRequest
	}
	result, err := tx.Exec(ctx, `
		UPDATE workspaces
		SET display_name = $2, revision = revision + 1, updated_at = $3
		WHERE id = $1 AND revision = $4
	`, command.WorkspaceID, displayName, updatedAt, command.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return Workspace{}, ErrServiceUnavailable
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_renamed", command.WorkspaceID, updatedAt,
		map[string]string{"workspace_id": command.WorkspaceID.String()},
	); err != nil {
		return Workspace{}, err
	}
	workspace, err = loadWorkspace(ctx, tx, actor, command.WorkspaceID, false)
	if err != nil {
		return Workspace{}, err
	}
	if err := commitWorkspaceTransaction(ctx, tx); err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

func (r *PostgresRepository) Archive(
	ctx context.Context,
	actor Actor,
	command RevisionCommand,
) (Workspace, error) {
	if !validRevisionCommand(r, actor, command) {
		return Workspace{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return Workspace{}, err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, true)
	if err != nil {
		return Workspace{}, err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return Workspace{}, ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status == WorkspaceStatusArchived {
		return Workspace{}, ErrWorkspaceArchived
	}
	if workspace.ActorRole != RoleOwner {
		return Workspace{}, ErrWorkspaceForbidden
	}
	if workspace.Revision != command.ExpectedRevision {
		return Workspace{}, ErrWorkspaceConflict
	}
	changedAt := command.ChangedAt.UTC()
	if changedAt.Before(workspace.UpdatedAt) {
		return Workspace{}, ErrInvalidRequest
	}
	result, err := tx.Exec(ctx, `
		UPDATE workspaces
		SET status = 'archived', revision = revision + 1, updated_at = $2, archived_at = $2
		WHERE id = $1 AND revision = $3
	`, command.WorkspaceID, changedAt, command.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return Workspace{}, ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE workspace_invitations
		SET status = 'revoked', revoked_at = $2
		WHERE workspace_id = $1 AND status = 'pending'
	`, command.WorkspaceID, changedAt); err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_archived", command.WorkspaceID, changedAt,
		map[string]string{"workspace_id": command.WorkspaceID.String()},
	); err != nil {
		return Workspace{}, err
	}
	workspace, err = loadWorkspace(ctx, tx, actor, command.WorkspaceID, false)
	if err != nil {
		return Workspace{}, err
	}
	if err := commitWorkspaceTransaction(ctx, tx); err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

func (r *PostgresRepository) Restore(
	ctx context.Context,
	actor Actor,
	command RevisionCommand,
) (Workspace, error) {
	if !validRevisionCommand(r, actor, command) {
		return Workspace{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return Workspace{}, err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, true)
	if err != nil {
		return Workspace{}, err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return Workspace{}, ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status != WorkspaceStatusArchived {
		return Workspace{}, ErrWorkspaceConflict
	}
	if workspace.ActorRole != RoleOwner {
		return Workspace{}, ErrWorkspaceForbidden
	}
	if workspace.Revision != command.ExpectedRevision {
		return Workspace{}, ErrWorkspaceConflict
	}
	changedAt := command.ChangedAt.UTC()
	if changedAt.Before(workspace.UpdatedAt) {
		return Workspace{}, ErrInvalidRequest
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, actor.UserID); err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	var activeOwned int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM workspaces WHERE owner_user_id = $1 AND status = 'active'
	`, actor.UserID).Scan(&activeOwned); err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	if activeOwned >= command.ActiveOwnedLimit {
		return Workspace{}, ErrWorkspaceLimitReached
	}
	result, err := tx.Exec(ctx, `
		UPDATE workspaces
		SET status = 'active', revision = revision + 1, updated_at = $2, archived_at = NULL
		WHERE id = $1 AND revision = $3
	`, command.WorkspaceID, changedAt, command.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return Workspace{}, ErrServiceUnavailable
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_restored", command.WorkspaceID, changedAt,
		map[string]string{"workspace_id": command.WorkspaceID.String()},
	); err != nil {
		return Workspace{}, err
	}
	workspace, err = loadWorkspace(ctx, tx, actor, command.WorkspaceID, false)
	if err != nil {
		return Workspace{}, err
	}
	if err := commitWorkspaceTransaction(ctx, tx); err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

func (r *PostgresRepository) ListMembers(
	ctx context.Context,
	actor Actor,
	workspaceID uuid.UUID,
) ([]Member, error) {
	if r == nil || r.postgres == nil {
		return nil, ErrServiceUnavailable
	}
	if err := actor.Validate(); err != nil || workspaceID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	if err := requireActiveActor(ctx, r.postgres, actor); err != nil {
		return nil, err
	}
	if _, err := loadWorkspace(ctx, r.postgres, actor, workspaceID, false); err != nil {
		return nil, err
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT m.user_id, COALESCE(u.nickname, ''), m.role, m.revision, m.joined_at
		FROM workspace_memberships m
		JOIN users u ON u.id = m.user_id
		WHERE m.workspace_id = $1
		ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
			lower(COALESCE(u.nickname, '')), m.user_id
	`, workspaceID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rows.Close()
	members := make([]Member, 0)
	for rows.Next() {
		member, scanErr := scanMember(rows)
		if scanErr != nil {
			return nil, ErrServiceUnavailable
		}
		members = append(members, member)
	}
	if rows.Err() != nil {
		return nil, ErrServiceUnavailable
	}
	return members, nil
}

func (r *PostgresRepository) ChangeMemberRole(
	ctx context.Context,
	actor Actor,
	command ChangeRoleCommand,
) (Member, error) {
	if !validChangeRoleCommand(r, actor, command) {
		return Member{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Member{}, ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return Member{}, err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, true)
	if err != nil {
		return Member{}, err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return Member{}, ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status == WorkspaceStatusArchived {
		return Member{}, ErrWorkspaceArchived
	}
	if workspace.ActorRole != RoleOwner {
		return Member{}, ErrWorkspaceForbidden
	}
	target, err := loadMember(ctx, tx, command.WorkspaceID, command.UserID, true)
	if err != nil {
		return Member{}, err
	}
	if target.Role == RoleOwner {
		return Member{}, ErrWorkspaceForbidden
	}
	if target.Revision != command.ExpectedRevision || target.Role == command.Role {
		return Member{}, ErrMembershipConflict
	}
	changedAt := command.ChangedAt.UTC()
	result, err := tx.Exec(ctx, `
		UPDATE workspace_memberships
		SET role = $3, revision = revision + 1, updated_at = $4
		WHERE workspace_id = $1 AND user_id = $2 AND revision = $5
	`, command.WorkspaceID, command.UserID, command.Role, changedAt, command.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return Member{}, ErrServiceUnavailable
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_member_role_changed", command.WorkspaceID, changedAt,
		map[string]string{
			"workspace_id": command.WorkspaceID.String(), "membership_user_id": command.UserID.String(),
			"role": string(command.Role), "previous_role": string(target.Role),
		},
	); err != nil {
		return Member{}, err
	}
	member, err := loadMember(ctx, tx, command.WorkspaceID, command.UserID, false)
	if err != nil {
		return Member{}, err
	}
	if err := commitWorkspaceTransaction(ctx, tx); err != nil {
		return Member{}, err
	}
	return member, nil
}

func (r *PostgresRepository) RemoveMember(
	ctx context.Context,
	actor Actor,
	command RemoveMemberCommand,
) error {
	if !validRemoveMemberCommand(r, actor, command) {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, true)
	if err != nil {
		return err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status == WorkspaceStatusArchived {
		return ErrWorkspaceArchived
	}
	if workspace.ActorRole != RoleOwner && workspace.ActorRole != RoleAdmin {
		return ErrWorkspaceForbidden
	}
	target, err := loadMember(ctx, tx, command.WorkspaceID, command.UserID, true)
	if err != nil {
		return err
	}
	if target.Role == RoleOwner || (workspace.ActorRole == RoleAdmin && target.Role != RoleMember) {
		return ErrWorkspaceForbidden
	}
	if target.Revision != command.ExpectedRevision {
		return ErrMembershipConflict
	}
	result, err := tx.Exec(ctx, `
		DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2 AND revision = $3
	`, command.WorkspaceID, command.UserID, command.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return ErrServiceUnavailable
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_member_removed", command.WorkspaceID, command.RemovedAt.UTC(),
		map[string]string{
			"workspace_id": command.WorkspaceID.String(), "membership_user_id": command.UserID.String(),
			"role": string(target.Role),
		},
	); err != nil {
		return err
	}
	return commitWorkspaceTransaction(ctx, tx)
}

func (r *PostgresRepository) Leave(ctx context.Context, actor Actor, workspaceID uuid.UUID) error {
	if r == nil || r.postgres == nil || actor.Validate() != nil || workspaceID == uuid.Nil {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, workspaceID, true)
	if err != nil {
		return err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status == WorkspaceStatusArchived {
		return ErrWorkspaceArchived
	}
	if workspace.ActorRole == RoleOwner {
		return ErrWorkspaceForbidden
	}
	result, err := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2`, workspaceID, actor.UserID)
	if err != nil || result.RowsAffected() != 1 {
		return ErrServiceUnavailable
	}
	eventID, err := r.generateUUID()
	if err != nil {
		return ErrServiceUnavailable
	}
	leftAt := r.now()
	if err := recordWorkspaceAudit(
		ctx, tx, actor, AuditEvidence{EventID: eventID}, "workspace_member_left", workspaceID, leftAt,
		map[string]string{
			"workspace_id": workspaceID.String(), "membership_user_id": actor.UserID.String(),
			"role": string(workspace.ActorRole),
		},
	); err != nil {
		return err
	}
	return commitWorkspaceTransaction(ctx, tx)
}

func (r *PostgresRepository) ListInvitations(
	ctx context.Context,
	actor Actor,
	workspaceID uuid.UUID,
) ([]Invitation, error) {
	if r == nil || r.postgres == nil || actor.Validate() != nil || workspaceID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	if err := requireActiveActor(ctx, r.postgres, actor); err != nil {
		return nil, err
	}
	workspace, err := loadWorkspace(ctx, r.postgres, actor, workspaceID, false)
	if err != nil {
		return nil, err
	}
	if workspace.ActorRole != RoleOwner && workspace.ActorRole != RoleAdmin {
		return nil, ErrWorkspaceForbidden
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT id, status, created_by_user_id, accepted_by_user_id,
			created_at, expires_at, accepted_at, revoked_at
		FROM workspace_invitations
		WHERE workspace_id = $1
		ORDER BY created_at DESC, id
	`, workspaceID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rows.Close()
	now := r.now()
	invitations := make([]Invitation, 0)
	for rows.Next() {
		invitation, scanErr := scanInvitation(rows, now)
		if scanErr != nil {
			return nil, ErrServiceUnavailable
		}
		invitations = append(invitations, invitation)
	}
	if rows.Err() != nil {
		return nil, ErrServiceUnavailable
	}
	return invitations, nil
}

func (r *PostgresRepository) CreateInvitation(
	ctx context.Context,
	actor Actor,
	command CreateInvitationCommand,
) (InvitationCreation, IdempotencyReplay, error) {
	if !validCreateInvitationCommand(r, actor, command) {
		return InvitationCreation{}, "", ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return InvitationCreation{}, "", ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return InvitationCreation{}, "", err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, true)
	if err != nil {
		return InvitationCreation{}, "", err
	}
	if workspace.ActorRole != RoleOwner && workspace.ActorRole != RoleAdmin {
		return InvitationCreation{}, "", ErrWorkspaceForbidden
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, workspaceIdempotencyLockID(
		actor,
		operationInvitationCreate,
		command.Idempotency.KeyDigest,
	)); err != nil {
		return InvitationCreation{}, "", ErrServiceUnavailable
	}
	storedWorkspaceID, resourceID, found, err := readOperationIdempotency(
		ctx, tx, actor, operationInvitationCreate, command.Idempotency,
	)
	if err != nil {
		return InvitationCreation{}, "", err
	}
	if found {
		if storedWorkspaceID != command.WorkspaceID {
			return InvitationCreation{}, "", ErrIdempotencyConflict
		}
		invitation, err := loadInvitation(ctx, tx, storedWorkspaceID, resourceID, r.now())
		if err != nil {
			return InvitationCreation{}, "", err
		}
		if err := commitWorkspaceTransaction(ctx, tx); err != nil {
			return InvitationCreation{}, "", err
		}
		return InvitationCreation{Invitation: invitation}, IdempotencyReplayed, nil
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return InvitationCreation{}, "", ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status == WorkspaceStatusArchived {
		return InvitationCreation{}, "", ErrWorkspaceArchived
	}
	createdAt := command.CreatedAt.UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE workspace_invitations
		SET status = 'expired'
		WHERE workspace_id = $1 AND status = 'pending' AND expires_at <= $2
	`, command.WorkspaceID, createdAt); err != nil {
		return InvitationCreation{}, "", ErrServiceUnavailable
	}
	var pending int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM workspace_invitations
		WHERE workspace_id = $1 AND status = 'pending'
	`, command.WorkspaceID).Scan(&pending); err != nil {
		return InvitationCreation{}, "", ErrServiceUnavailable
	}
	if pending >= command.PendingInviteLimit {
		return InvitationCreation{}, "", ErrInvitationLimitReached
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, command.InvitationID, command.WorkspaceID, command.Secret.Digest[:], actor.UserID,
		createdAt, createdAt.Add(7*24*time.Hour)); err != nil {
		return InvitationCreation{}, "", ErrServiceUnavailable
	}
	if err := insertOperationIdempotency(
		ctx, tx, actor, command.WorkspaceID, operationInvitationCreate, command.Idempotency,
		"workspace_invitation", command.InvitationID, createdAt,
	); err != nil {
		return InvitationCreation{}, "", err
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_invitation_created", command.WorkspaceID, createdAt,
		map[string]string{
			"workspace_id": command.WorkspaceID.String(), "invitation_id": command.InvitationID.String(),
		},
	); err != nil {
		return InvitationCreation{}, "", err
	}
	invitation, err := loadInvitation(ctx, tx, command.WorkspaceID, command.InvitationID, createdAt)
	if err != nil {
		return InvitationCreation{}, "", err
	}
	secret := command.Secret
	if err := commitWorkspaceTransaction(ctx, tx); err != nil {
		return InvitationCreation{}, "", err
	}
	return InvitationCreation{Invitation: invitation, Secret: &secret}, IdempotencyFresh, nil
}

func (r *PostgresRepository) RevokeInvitation(
	ctx context.Context,
	actor Actor,
	command RevokeInvitationCommand,
) error {
	if !validRevokeInvitationCommand(r, actor, command) {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, command.WorkspaceID, true)
	if err != nil {
		return err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return ErrWorkspaceOwnerUnavailable
	}
	if workspace.Status == WorkspaceStatusArchived {
		return ErrWorkspaceArchived
	}
	if workspace.ActorRole != RoleOwner && workspace.ActorRole != RoleAdmin {
		return ErrWorkspaceForbidden
	}
	var status string
	err = tx.QueryRow(ctx, `
		SELECT status FROM workspace_invitations
		WHERE id = $1 AND workspace_id = $2
		FOR UPDATE
	`, command.InvitationID, command.WorkspaceID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != string(InvitationStatusPending)) {
		return ErrInvitationUnavailable
	}
	if err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE workspace_invitations SET status = 'revoked', revoked_at = $2 WHERE id = $1
	`, command.InvitationID, command.RevokedAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_invitation_revoked", command.WorkspaceID, command.RevokedAt.UTC(),
		map[string]string{
			"workspace_id": command.WorkspaceID.String(), "invitation_id": command.InvitationID.String(),
		},
	); err != nil {
		return err
	}
	return commitWorkspaceTransaction(ctx, tx)
}

func (r *PostgresRepository) AcceptInvitation(
	ctx context.Context,
	actor Actor,
	command AcceptInvitationCommand,
) (Acceptance, error) {
	if !validAcceptInvitationCommand(r, actor, command) {
		return Acceptance{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Acceptance{}, ErrServiceUnavailable
	}
	defer rollbackWorkspaceTransaction(tx)
	if err := requireActiveActor(ctx, tx, actor); err != nil {
		return Acceptance{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, workspaceIdempotencyLockID(
		actor,
		operationInvitationAccept,
		command.Idempotency.KeyDigest,
	)); err != nil {
		return Acceptance{}, ErrServiceUnavailable
	}
	storedWorkspaceID, _, found, err := readOperationIdempotency(
		ctx, tx, actor, operationInvitationAccept, command.Idempotency,
	)
	if err != nil {
		return Acceptance{}, err
	}
	if found {
		workspace, err := loadWorkspace(ctx, tx, actor, storedWorkspaceID, false)
		if err != nil {
			return Acceptance{}, err
		}
		member, err := loadMember(ctx, tx, storedWorkspaceID, actor.UserID, false)
		if err != nil {
			return Acceptance{}, err
		}
		if err := commitWorkspaceTransaction(ctx, tx); err != nil {
			return Acceptance{}, err
		}
		return Acceptance{Workspace: workspace, Member: member}, nil
	}

	var invitationID uuid.UUID
	var workspaceID uuid.UUID
	var invitationStatus string
	var expiresAt time.Time
	var workspaceStatus string
	var ownerStatus string
	var ownerMatches bool
	err = tx.QueryRow(ctx, `
		SELECT i.id, i.workspace_id, i.status, i.expires_at, w.status, owner.status,
			(SELECT count(*) = 1 FROM workspace_memberships fixed_owner
			 WHERE fixed_owner.workspace_id = w.id AND fixed_owner.role = 'owner'
			   AND fixed_owner.user_id = w.owner_user_id)
		FROM workspace_invitations i
		JOIN workspaces w ON w.id = i.workspace_id
		JOIN users owner ON owner.id = w.owner_user_id
		WHERE i.token_digest = $1
		FOR UPDATE OF i, w
	`, command.TokenDigest[:]).Scan(
		&invitationID, &workspaceID, &invitationStatus, &expiresAt, &workspaceStatus, &ownerStatus, &ownerMatches,
	)
	acceptedAt := command.AcceptedAt.UTC()
	if errors.Is(err, pgx.ErrNoRows) ||
		(err == nil && (invitationStatus != string(InvitationStatusPending) || !acceptedAt.Before(expiresAt) ||
			workspaceStatus != string(WorkspaceStatusActive) || ownerStatus != "active" || !ownerMatches)) {
		return Acceptance{}, ErrInvitationUnavailable
	}
	if err != nil {
		return Acceptance{}, ErrServiceUnavailable
	}

	member, memberFound, err := findMember(ctx, tx, workspaceID, actor.UserID, true)
	if err != nil {
		return Acceptance{}, err
	}
	if !memberFound {
		var memberCount int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM workspace_memberships WHERE workspace_id = $1
		`, workspaceID).Scan(&memberCount); err != nil {
			return Acceptance{}, ErrServiceUnavailable
		}
		if memberCount >= command.MemberLimit {
			return Acceptance{}, ErrMemberLimitReached
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
			VALUES ($1, $2, 'member', 1, $3, $3)
		`, workspaceID, actor.UserID, acceptedAt); err != nil {
			return Acceptance{}, ErrServiceUnavailable
		}
		member, err = loadMember(ctx, tx, workspaceID, actor.UserID, false)
		if err != nil {
			return Acceptance{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE workspace_invitations
		SET status = 'accepted', accepted_by_user_id = $2, accepted_at = $3
		WHERE id = $1
	`, invitationID, actor.UserID, acceptedAt); err != nil {
		return Acceptance{}, ErrServiceUnavailable
	}
	if err := insertOperationIdempotency(
		ctx, tx, actor, workspaceID, operationInvitationAccept, command.Idempotency,
		"workspace_membership", actor.UserID, acceptedAt,
	); err != nil {
		return Acceptance{}, err
	}
	if err := recordWorkspaceAudit(
		ctx, tx, actor, command.Audit, "workspace_invitation_accepted", workspaceID, acceptedAt,
		map[string]string{
			"workspace_id": workspaceID.String(), "invitation_id": invitationID.String(),
			"membership_user_id": actor.UserID.String(), "role": string(member.Role),
		},
	); err != nil {
		return Acceptance{}, err
	}
	workspace, err := loadWorkspace(ctx, tx, actor, workspaceID, false)
	if err != nil {
		return Acceptance{}, err
	}
	if err := commitWorkspaceTransaction(ctx, tx); err != nil {
		return Acceptance{}, err
	}
	return Acceptance{Workspace: workspace, Member: member}, nil
}

const workspaceSelectColumns = `
	w.id, w.display_name, w.status, w.revision, w.created_at, w.updated_at, w.archived_at,
	m.role,
	(SELECT count(*) FROM workspace_memberships members WHERE members.workspace_id = w.id),
	owner.status,
	(SELECT count(*) = 1 FROM workspace_memberships fixed_owner
	 WHERE fixed_owner.workspace_id = w.id AND fixed_owner.role = 'owner'
	   AND fixed_owner.user_id = w.owner_user_id)
`

const workspaceListQuery = `
	SELECT ` + workspaceSelectColumns + `
	FROM workspace_memberships m
	JOIN workspaces w ON w.id = m.workspace_id
	JOIN users owner ON owner.id = w.owner_user_id
	WHERE m.user_id = $1
	ORDER BY lower(w.display_name), w.id
`

func loadWorkspace(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	actor Actor,
	workspaceID uuid.UUID,
	forUpdate bool,
) (Workspace, error) {
	query := `
		SELECT ` + workspaceSelectColumns + `
		FROM workspace_memberships m
		JOIN workspaces w ON w.id = m.workspace_id
		JOIN users owner ON owner.id = w.owner_user_id
		WHERE m.user_id = $1 AND w.id = $2
	`
	if forUpdate {
		query += ` FOR UPDATE OF w, m`
	}
	workspace, err := scanWorkspace(queryer.QueryRow(ctx, query, actor.UserID, workspaceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Workspace{}, ErrWorkspaceNotFound
	}
	return workspace, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanWorkspace(row rowScanner) (Workspace, error) {
	var workspace Workspace
	var status string
	var role string
	var ownerStatus string
	var ownerMatches bool
	var archivedAt pgtype.Timestamptz
	if err := row.Scan(
		&workspace.ID,
		&workspace.DisplayName,
		&status,
		&workspace.Revision,
		&workspace.CreatedAt,
		&workspace.UpdatedAt,
		&archivedAt,
		&role,
		&workspace.MemberCount,
		&ownerStatus,
		&ownerMatches,
	); err != nil {
		return Workspace{}, err
	}
	if !ownerMatches {
		return Workspace{}, ErrServiceUnavailable
	}
	workspace.Status = WorkspaceStatus(status)
	workspace.ActorRole = Role(role)
	switch workspace.Status {
	case WorkspaceStatusArchived:
		workspace.MutationState = MutationStateArchived
	case WorkspaceStatusActive:
		if ownerStatus == "active" {
			workspace.MutationState = MutationStateWritable
		} else {
			workspace.MutationState = MutationStateOwnerUnavailable
		}
	}
	if archivedAt.Valid {
		value := archivedAt.Time
		workspace.ArchivedAt = &value
	}
	normalized, err := NormalizeWorkspace(workspace)
	if err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	return normalized, nil
}

func scanMember(row rowScanner) (Member, error) {
	var member Member
	var role string
	if err := row.Scan(
		&member.UserID,
		&member.Nickname,
		&role,
		&member.Revision,
		&member.JoinedAt,
	); err != nil {
		return Member{}, err
	}
	parsedRole, err := ParseRole(role)
	if err != nil || member.UserID == uuid.Nil || member.Revision <= 0 || member.JoinedAt.IsZero() {
		return Member{}, ErrServiceUnavailable
	}
	member.Role = parsedRole
	member.JoinedAt = member.JoinedAt.UTC()
	return member, nil
}

func findMember(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	workspaceID uuid.UUID,
	userID uuid.UUID,
	forUpdate bool,
) (Member, bool, error) {
	query := `
		SELECT m.user_id, COALESCE(u.nickname, ''), m.role, m.revision, m.joined_at
		FROM workspace_memberships m
		JOIN users u ON u.id = m.user_id
		WHERE m.workspace_id = $1 AND m.user_id = $2
	`
	if forUpdate {
		query += ` FOR UPDATE OF m`
	}
	member, err := scanMember(queryer.QueryRow(ctx, query, workspaceID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, false, nil
	}
	if err != nil {
		return Member{}, false, ErrServiceUnavailable
	}
	return member, true, nil
}

func loadMember(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	workspaceID uuid.UUID,
	userID uuid.UUID,
	forUpdate bool,
) (Member, error) {
	member, found, err := findMember(ctx, queryer, workspaceID, userID, forUpdate)
	if err != nil {
		return Member{}, err
	}
	if !found {
		return Member{}, ErrWorkspaceNotFound
	}
	return member, nil
}

func scanInvitation(row rowScanner, now time.Time) (Invitation, error) {
	var invitation Invitation
	var status string
	var createdBy pgtype.UUID
	var acceptedBy pgtype.UUID
	var acceptedAt pgtype.Timestamptz
	var revokedAt pgtype.Timestamptz
	if err := row.Scan(
		&invitation.ID,
		&status,
		&createdBy,
		&acceptedBy,
		&invitation.CreatedAt,
		&invitation.ExpiresAt,
		&acceptedAt,
		&revokedAt,
	); err != nil {
		return Invitation{}, err
	}
	if invitation.ID == uuid.Nil || invitation.CreatedAt.IsZero() || invitation.ExpiresAt.IsZero() ||
		!invitation.ExpiresAt.Equal(invitation.CreatedAt.Add(7*24*time.Hour)) {
		return Invitation{}, ErrServiceUnavailable
	}
	switch InvitationStatus(status) {
	case InvitationStatusPending, InvitationStatusAccepted, InvitationStatusRevoked, InvitationStatusExpired:
		invitation.Status = InvitationStatus(status)
	default:
		return Invitation{}, ErrServiceUnavailable
	}
	if createdBy.Valid {
		value := uuid.UUID(createdBy.Bytes)
		if value == uuid.Nil {
			return Invitation{}, ErrServiceUnavailable
		}
		invitation.CreatedByUserID = &value
	}
	if acceptedBy.Valid {
		value := uuid.UUID(acceptedBy.Bytes)
		if value == uuid.Nil {
			return Invitation{}, ErrServiceUnavailable
		}
		invitation.AcceptedByUserID = &value
	}
	if acceptedAt.Valid {
		value := acceptedAt.Time.UTC()
		invitation.AcceptedAt = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time.UTC()
		invitation.RevokedAt = &value
	}
	if invitation.Status == InvitationStatusPending && !now.UTC().Before(invitation.ExpiresAt.UTC()) {
		invitation.Status = InvitationStatusExpired
	}
	invitation.CreatedAt = invitation.CreatedAt.UTC()
	invitation.ExpiresAt = invitation.ExpiresAt.UTC()
	return invitation, nil
}

func loadInvitation(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	workspaceID uuid.UUID,
	invitationID uuid.UUID,
	now time.Time,
) (Invitation, error) {
	invitation, err := scanInvitation(queryer.QueryRow(ctx, `
		SELECT id, status, created_by_user_id, accepted_by_user_id,
			created_at, expires_at, accepted_at, revoked_at
		FROM workspace_invitations
		WHERE workspace_id = $1 AND id = $2
	`, workspaceID, invitationID), now)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrInvitationUnavailable
	}
	if err != nil {
		return Invitation{}, ErrServiceUnavailable
	}
	return invitation, nil
}

func readOperationIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	evidence IdempotencyEvidence,
) (uuid.UUID, uuid.UUID, bool, error) {
	var workspaceID uuid.UUID
	var requestDigest []byte
	var resourceID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT workspace_id, request_digest, resource_id
		FROM workspace_idempotency_records
		WHERE actor_user_id = $1 AND operation = $2 AND key_digest = $3
	`, actor.UserID, operation, evidence.KeyDigest[:]).Scan(&workspaceID, &requestDigest, &resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, false, ErrServiceUnavailable
	}
	if workspaceID == uuid.Nil || resourceID == uuid.Nil || len(requestDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(requestDigest, evidence.RequestDigest[:]) != 1 {
		if len(requestDigest) == sha256.Size {
			return uuid.Nil, uuid.Nil, false, ErrIdempotencyConflict
		}
		return uuid.Nil, uuid.Nil, false, ErrServiceUnavailable
	}
	return workspaceID, resourceID, true, nil
}

func insertOperationIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	workspaceID uuid.UUID,
	operation string,
	evidence IdempotencyEvidence,
	resourceType string,
	resourceID uuid.UUID,
	createdAt time.Time,
) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_idempotency_records (
			actor_user_id, workspace_id, operation, key_digest, request_digest,
			resource_type, resource_id, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, actor.UserID, workspaceID, operation, evidence.KeyDigest[:], evidence.RequestDigest[:],
		resourceType, resourceID, createdAt.UTC(), evidence.ExpiresAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func requireActiveActor(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	actor Actor,
) error {
	var authorized bool
	if err := queryer.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM users u
			JOIN devices d ON d.user_id = u.id
			WHERE u.id = $1 AND u.status = 'active'
			  AND d.id = $2 AND d.status = 'active'
		)
	`, actor.UserID, actor.DeviceID).Scan(&authorized); err != nil {
		return ErrServiceUnavailable
	}
	if !authorized {
		return ErrSessionRevoked
	}
	return nil
}

func lockActiveActor(ctx context.Context, tx pgx.Tx, actor Actor) error {
	var status string
	err := tx.QueryRow(ctx, `
		SELECT u.status
		FROM users u
		JOIN devices d ON d.user_id = u.id
		WHERE u.id = $1 AND d.id = $2 AND d.status = 'active'
		FOR UPDATE OF u
	`, actor.UserID, actor.DeviceID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != "active") {
		return ErrSessionRevoked
	}
	if err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func readWorkspaceIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	evidence IdempotencyEvidence,
) (uuid.UUID, bool, error) {
	var requestDigest []byte
	var resourceID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT request_digest, resource_id
		FROM workspace_idempotency_records
		WHERE actor_user_id = $1 AND operation = $2 AND key_digest = $3
	`, actor.UserID, operationWorkspaceCreate, evidence.KeyDigest[:]).Scan(&requestDigest, &resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, ErrServiceUnavailable
	}
	if len(requestDigest) != sha256.Size || subtle.ConstantTimeCompare(requestDigest, evidence.RequestDigest[:]) != 1 {
		return uuid.Nil, false, ErrIdempotencyConflict
	}
	return resourceID, true, nil
}

func workspaceIdempotencyLockID(actor Actor, operation string, keyDigest [sha256.Size]byte) int64 {
	payload := make([]byte, 0, 16+len(operation)+sha256.Size+32)
	payload = append(payload, []byte("agentera.workspace-idempotency.v1\x00")...)
	payload = append(payload, actor.UserID[:]...)
	payload = append(payload, []byte(operation)...)
	payload = append(payload, 0)
	payload = append(payload, keyDigest[:]...)
	digest := sha256.Sum256(payload)
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func recordWorkspaceAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	evidence AuditEvidence,
	eventType string,
	workspaceID uuid.UUID,
	occurredAt time.Time,
	metadata map[string]string,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	actorID := actor.UserID
	deviceID := actor.DeviceID
	objectID := workspaceID
	if err := recorder.Record(ctx, audit.Event{
		ID: evidence.EventID, EventType: eventType, ActorUserID: &actorID, DeviceID: &deviceID,
		ObjectType: "workspace", ObjectID: &objectID, Outcome: audit.OutcomeSuccess,
		RequestID: evidence.RequestID, Metadata: metadata, OccurredAt: occurredAt.UTC(),
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func validCreateCommand(command CreateCommand) bool {
	return command.WorkspaceID != uuid.Nil && command.ActiveOwnedLimit > 0 && !command.CreatedAt.IsZero() &&
		command.Audit.EventID != uuid.Nil && command.Audit.RequestID != "" && !command.Idempotency.ExpiresAt.IsZero() &&
		command.Idempotency.ExpiresAt.Equal(command.CreatedAt.Add(24*time.Hour))
}

func validRenameCommand(command RenameCommand) bool {
	return command.WorkspaceID != uuid.Nil && command.ExpectedRevision > 0 && !command.UpdatedAt.IsZero() &&
		command.Audit.EventID != uuid.Nil && command.Audit.RequestID != ""
}

func validRevisionCommand(r *PostgresRepository, actor Actor, command RevisionCommand) bool {
	return r != nil && r.postgres != nil && actor.Validate() == nil && command.WorkspaceID != uuid.Nil &&
		command.ExpectedRevision > 0 && command.ActiveOwnedLimit > 0 && !command.ChangedAt.IsZero() &&
		command.Audit.EventID != uuid.Nil && command.Audit.RequestID != ""
}

func validChangeRoleCommand(r *PostgresRepository, actor Actor, command ChangeRoleCommand) bool {
	return r != nil && r.postgres != nil && actor.Validate() == nil && command.WorkspaceID != uuid.Nil &&
		command.UserID != uuid.Nil && (command.Role == RoleAdmin || command.Role == RoleMember) &&
		command.ExpectedRevision > 0 && !command.ChangedAt.IsZero() && command.Audit.EventID != uuid.Nil &&
		command.Audit.RequestID != ""
}

func validRemoveMemberCommand(r *PostgresRepository, actor Actor, command RemoveMemberCommand) bool {
	return r != nil && r.postgres != nil && actor.Validate() == nil && command.WorkspaceID != uuid.Nil &&
		command.UserID != uuid.Nil && command.ExpectedRevision > 0 && !command.RemovedAt.IsZero() &&
		command.Audit.EventID != uuid.Nil && command.Audit.RequestID != ""
}

func validCreateInvitationCommand(r *PostgresRepository, actor Actor, command CreateInvitationCommand) bool {
	if r == nil || r.postgres == nil || actor.Validate() != nil || command.InvitationID == uuid.Nil ||
		command.WorkspaceID == uuid.Nil || command.PendingInviteLimit <= 0 || command.CreatedAt.IsZero() ||
		command.Audit.EventID == uuid.Nil || command.Audit.RequestID == "" || command.Idempotency.ExpiresAt.IsZero() ||
		!command.Idempotency.ExpiresAt.Equal(command.CreatedAt.Add(24*time.Hour)) {
		return false
	}
	digest, err := InvitationDigest(command.Secret.RawToken)
	return err == nil && subtle.ConstantTimeCompare(digest[:], command.Secret.Digest[:]) == 1
}

func validRevokeInvitationCommand(r *PostgresRepository, actor Actor, command RevokeInvitationCommand) bool {
	return r != nil && r.postgres != nil && actor.Validate() == nil && command.WorkspaceID != uuid.Nil &&
		command.InvitationID != uuid.Nil && !command.RevokedAt.IsZero() && command.Audit.EventID != uuid.Nil &&
		command.Audit.RequestID != ""
}

func validAcceptInvitationCommand(r *PostgresRepository, actor Actor, command AcceptInvitationCommand) bool {
	return r != nil && r.postgres != nil && actor.Validate() == nil && command.MemberLimit > 0 &&
		!command.AcceptedAt.IsZero() && command.Audit.EventID != uuid.Nil && command.Audit.RequestID != "" &&
		!command.Idempotency.ExpiresAt.IsZero() &&
		command.Idempotency.ExpiresAt.Equal(command.AcceptedAt.Add(24*time.Hour))
}

func (r *PostgresRepository) now() time.Time {
	if r == nil || r.clock == nil {
		return time.Now().UTC()
	}
	return r.clock().UTC()
}

func (r *PostgresRepository) generateUUID() (uuid.UUID, error) {
	if r == nil || r.newUUID == nil {
		return uuid.NewRandom()
	}
	value, err := r.newUUID()
	if err != nil || value == uuid.Nil {
		return uuid.Nil, ErrServiceUnavailable
	}
	return value, nil
}

var _ Repository = (*PostgresRepository)(nil)

func rollbackWorkspaceTransaction(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}

func commitWorkspaceTransaction(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}
