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

const operationWorkspaceCreate = "workspace_create"

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

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
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
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, workspaceIdempotencyLockID(actor, command.Idempotency.KeyDigest)); err != nil {
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

func workspaceIdempotencyLockID(actor Actor, keyDigest [sha256.Size]byte) int64 {
	payload := make([]byte, 0, 16+len(operationWorkspaceCreate)+sha256.Size+32)
	payload = append(payload, []byte("agentera.workspace-idempotency.v1\x00")...)
	payload = append(payload, actor.UserID[:]...)
	payload = append(payload, []byte(operationWorkspaceCreate)...)
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

func rollbackWorkspaceTransaction(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}

func commitWorkspaceTransaction(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}
