package agentcontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidRepositoryCommand             = errors.New("Agent control repository command is invalid")
	ErrNotFound                             = errors.New("Agent control object was not found")
	ErrServiceUnavailable                   = errors.New("Agent control repository is unavailable")
	ErrIdempotencyConflict                  = errors.New("Agent control idempotency key conflicts with the request")
	ErrVersionConflict                      = errors.New("Agent version base is stale")
	ErrDefinitionArchived                   = errors.New("Agent definition is archived")
	ErrVersionRevoked                       = errors.New("Agent version is revoked")
	ErrActivationConflict                   = errors.New("Agent installation activation conflicts with existing state")
	ErrInstallationArchived                 = errors.New("Agent installation is archived")
	ErrWorkspaceForbidden                   = errors.New("Workspace Agent operation is forbidden")
	ErrWorkspaceArchived                    = errors.New("Workspace is archived")
	ErrWorkspaceOwnerUnavailable            = errors.New("Workspace Owner is unavailable")
	ErrOrganizationAgentNotFound            = errors.New("organization agent not found")
	ErrOrganizationAgentForbidden           = errors.New("organization agent forbidden")
	ErrOrganizationArchived                 = errors.New("organization archived")
	ErrOrganizationPublicationPolicyBlocked = errors.New("organization publication policy blocked")
	ErrOrganizationPublicationDLPBlocked    = errors.New("organization publication dlp blocked")
)

const (
	operationPublishInitial            = "publish_initial"
	operationPublishNext               = "publish_next"
	operationCreateInstallation        = "create_installation"
	operationRevokeVersion             = "revoke_version"
	operationSubmitExperienceCandidate = "submit_experience_candidate"
	operationReviewExperienceCandidate = "review_experience_candidate"
	definitionStatusActive             = "active"
	definitionStatusArchived           = "archived"
	InstallationStatusPending          = "pending"
	InstallationStatusActive           = "active"
	InstallationStatusArchived         = "archived"
	installationUpdatePolicy           = "manual"
)

type workspaceAgentAccessMode uint8

const (
	workspaceAgentRead workspaceAgentAccessMode = iota
	workspaceAgentPublish
	workspaceAgentInstall
	workspaceAgentContribute
	workspaceAgentReview
)

type Principal struct {
	UserID          uuid.UUID
	DeviceID        uuid.UUID
	PersonalSpaceID uuid.UUID
}

func (p Principal) Owner() Owner {
	return Owner{TenantID: p.PersonalSpaceID, Scope: OwnerScopeUser, OwnerID: p.UserID}
}

type Definition struct {
	ID              uuid.UUID
	DisplayName     string
	IconMediaType   string
	IconData        []byte
	Status          string
	LatestVersionID *uuid.UUID
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Version struct {
	ID                             uuid.UUID
	DefinitionID                   uuid.UUID
	VersionNumber                  int64
	CanonicalManifest              []byte
	Bundle                         []byte
	ContentDigest                  [sha256.Size]byte
	SigningKeyID                   string
	Signature                      []byte
	RuntimeMinimumVersion          string
	RuntimeMaximumVersionExclusive string
	PublishedAt                    time.Time
}

type VersionMaterial struct {
	ID                             uuid.UUID
	VersionNumber                  int64
	CanonicalManifest              []byte
	Bundle                         []byte
	ContentDigest                  [sha256.Size]byte
	SigningKeyID                   string
	Signature                      []byte
	RuntimeMinimumVersion          string
	RuntimeMaximumVersionExclusive string
}

type IdempotencyEvidence struct {
	ID          uuid.UUID
	KeyHash     [sha256.Size]byte
	RequestHash [sha256.Size]byte
	ExpiresAt   time.Time
}

type AuditEvidence struct {
	EventID   uuid.UUID
	RequestID string
}

type InitialPublicationCommand struct {
	DefinitionID  uuid.UUID
	DisplayName   string
	IconMediaType string
	IconData      []byte
	BuildVersion  func() (VersionMaterial, error)
	Idempotency   IdempotencyEvidence
	Audit         AuditEvidence
	PublishedAt   time.Time
}

type NextPublicationCommand struct {
	DefinitionID  uuid.UUID
	BaseVersionID uuid.UUID
	BuildVersion  func(versionNumber int64) (VersionMaterial, error)
	Idempotency   IdempotencyEvidence
	Audit         AuditEvidence
	PublishedAt   time.Time
}

type Publication struct {
	Definition Definition
	Version    Version
	Replayed   bool
}

type PolicyMaterial struct {
	ID             uuid.UUID
	InstallationID uuid.UUID
	AgentVersionID uuid.UUID
	PolicyVersion  int64
	Document       []byte
	ContentDigest  [sha256.Size]byte
	Issuer         string
	SigningKeyID   string
	Signature      []byte
	CreatedAt      time.Time
}

type PolicySnapshot struct {
	ID             uuid.UUID
	InstallationID uuid.UUID
	AgentVersionID uuid.UUID
	PolicyVersion  int64
	Document       []byte
	ContentDigest  [sha256.Size]byte
	Issuer         string
	SigningKeyID   string
	Signature      []byte
	CreatedAt      time.Time
}

type Installation struct {
	ID                   uuid.UUID
	DeviceID             uuid.UUID
	DeviceInstallationID uuid.UUID
	DefinitionID         uuid.UUID
	SelectedVersionID    uuid.UUID
	RuntimeProfileID     *uuid.UUID
	PolicySnapshotID     *uuid.UUID
	UpdatePolicy         string
	Status               string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	ActivatedAt          *time.Time
	ArchivedAt           *time.Time
}

type CreateInstallationCommand struct {
	InstallationID          uuid.UUID
	DefinitionID            uuid.UUID
	VersionID               uuid.UUID
	SourceWorkspaceID       *uuid.UUID
	SourceOrganizationID    *uuid.UUID
	BuildPolicy             func(Version) (PolicyMaterial, error)
	BuildOrganizationPolicy func(Version, EffectiveOrganizationAgentPolicy) (PolicyMaterial, error)
	Idempotency             IdempotencyEvidence
	Audit                   AuditEvidence
	CreatedAt               time.Time
}

type InstallationCreation struct {
	Installation Installation
	Policy       PolicySnapshot
	Replayed     bool
}

type ActivationCommand struct {
	InstallationID   uuid.UUID
	RuntimeProfileID uuid.UUID
	AgentVersionID   uuid.UUID
	PolicySnapshotID uuid.UUID
	VersionDigest    [sha256.Size]byte
	Audit            AuditEvidence
	ActivatedAt      time.Time
}

type VersionSelectionCommand struct {
	InstallationID          uuid.UUID
	VersionID               uuid.UUID
	BuildPolicy             func(policyVersion int64, version Version) (PolicyMaterial, error)
	BuildOrganizationPolicy func(policyVersion int64, version Version, effective EffectiveOrganizationAgentPolicy) (PolicyMaterial, error)
	Audit                   AuditEvidence
	SelectedAt              time.Time
}

type ArchiveInstallationCommand struct {
	InstallationID uuid.UUID
	Audit          AuditEvidence
	ArchivedAt     time.Time
}

type RuntimeBindingRecordCommand struct {
	BindingID            uuid.UUID
	AgentInstallationID  uuid.UUID
	AgentVersionID       uuid.UUID
	RuntimeProfileID     uuid.UUID
	RuntimeVersion       string
	PolicySnapshotID     uuid.UUID
	ToolPermissionDigest [sha256.Size]byte
}

type PersistRuntimeBindingCommand struct {
	RuntimeBindingRecordCommand
	Audit     AuditEvidence
	CreatedAt time.Time
}

type InstallationActivationContext struct {
	Installation    Installation
	Version         Version
	DevicePublicKey ed25519.PublicKey
}

type RuntimeBindingRecord struct {
	ID                   uuid.UUID
	DeviceID             uuid.UUID
	AgentInstallationID  uuid.UUID
	AgentVersionID       uuid.UUID
	RuntimeProfileID     uuid.UUID
	RuntimeVersion       string
	PolicySnapshotID     uuid.UUID
	ToolPermissionDigest [sha256.Size]byte
	CreatedAt            time.Time
}

type VersionRevocationCommand struct {
	RevocationID         uuid.UUID
	VersionID            uuid.UUID
	ReasonCode           string
	PolicySnapshotID     uuid.UUID
	SupersedingVersionID *uuid.UUID
	Idempotency          IdempotencyEvidence
	Audit                AuditEvidence
	RevokedAt            time.Time
}

type VersionRevocation struct {
	ID                   uuid.UUID
	VersionID            uuid.UUID
	ReasonCode           string
	PolicySnapshotID     uuid.UUID
	SupersedingVersionID *uuid.UUID
	CreatedAt            time.Time
	Replayed             bool
}

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
}

func (r *PostgresRepository) PublishInitial(
	ctx context.Context,
	principal Principal,
	command InitialPublicationCommand,
) (Publication, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || !validInitialPublication(command) {
		return Publication{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadIdempotency(ctx, tx, principal, operationPublishInitial, command.Idempotency)
	if err != nil {
		return Publication{}, err
	}
	if found {
		publication, err := loadPublication(ctx, tx, principal, response.DefinitionID, response.VersionID)
		if err != nil {
			return Publication{}, err
		}
		publication.Replayed = true
		return publication, commitTransaction(ctx, tx)
	}
	var authorized bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM users u
			JOIN personal_spaces ps ON ps.id = $2 AND ps.owner_user_id = u.id AND ps.status = 'active'
			JOIN devices d ON d.id = $3 AND d.user_id = u.id AND d.status = 'active'
			WHERE u.id = $1 AND u.status = 'active'
		)
	`, principal.UserID, principal.PersonalSpaceID, principal.DeviceID).Scan(&authorized)
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	if !authorized {
		return Publication{}, ErrNotFound
	}
	material, err := command.BuildVersion()
	if err != nil {
		return Publication{}, err
	}
	if !validVersionMaterial(material, 1) {
		return Publication{}, ErrInvalidRepositoryCommand
	}

	owner := principal.Owner()
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_definitions (
			id, tenant_id, owner_scope, owner_id, display_name, icon_media_type, icon_data,
			status, latest_version_id, created_by, created_at, updated_at
		) VALUES ($1, $2, 'USER', $3, $4, NULLIF($5, ''), $6, 'active', NULL, $3, $7, $7)
	`, command.DefinitionID, owner.TenantID, owner.OwnerID, command.DisplayName,
		command.IconMediaType, nilIfEmptyBytes(command.IconData), command.PublishedAt.UTC()); err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	if err := insertVersion(ctx, tx, principal, command.DefinitionID, material, command.PublishedAt); err != nil {
		return Publication{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE agent_definitions SET latest_version_id = $4, updated_at = $5
		WHERE id = $3 AND tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
	`, owner.TenantID, owner.OwnerID, command.DefinitionID, material.ID, command.PublishedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return Publication{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: command.DefinitionID, VersionID: material.ID}
	if err := insertIdempotency(ctx, tx, principal, operationPublishInitial, command.Idempotency,
		"agent_definition", command.DefinitionID, response, command.PublishedAt); err != nil {
		return Publication{}, err
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "agent_definition_published", "agent_definition",
		command.DefinitionID, command.PublishedAt, map[string]string{
			"agent_definition_id": command.DefinitionID.String(), "agent_version_id": material.ID.String(),
			"content_digest": hex.EncodeToString(material.ContentDigest[:]),
		}); err != nil {
		return Publication{}, err
	}
	publication, err := loadPublication(ctx, tx, principal, command.DefinitionID, material.ID)
	if err != nil {
		return Publication{}, err
	}
	return publication, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) PublishNext(
	ctx context.Context,
	principal Principal,
	command NextPublicationCommand,
) (Publication, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || !validNextPublication(command) {
		return Publication{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadIdempotency(ctx, tx, principal, operationPublishNext, command.Idempotency)
	if err != nil {
		return Publication{}, err
	}
	if found {
		publication, err := loadPublication(ctx, tx, principal, response.DefinitionID, response.VersionID)
		if err != nil {
			return Publication{}, err
		}
		publication.Replayed = true
		return publication, commitTransaction(ctx, tx)
	}

	owner := principal.Owner()
	var status string
	var latestVersionID uuid.UUID
	var latestNumber int64
	err = tx.QueryRow(ctx, `
		SELECT d.status, d.latest_version_id, v.version_number
		FROM agent_definitions d
		JOIN agent_versions v ON v.id = d.latest_version_id
		WHERE d.id = $3 AND d.tenant_id = $1 AND d.owner_scope = 'USER' AND d.owner_id = $2
		  AND v.tenant_id = $1 AND v.owner_scope = 'USER' AND v.owner_id = $2
		FOR UPDATE OF d
	`, owner.TenantID, owner.OwnerID, command.DefinitionID).Scan(&status, &latestVersionID, &latestNumber)
	if errors.Is(err, pgx.ErrNoRows) {
		return Publication{}, ErrNotFound
	}
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	if status == definitionStatusArchived {
		return Publication{}, ErrDefinitionArchived
	}
	if latestVersionID != command.BaseVersionID {
		return Publication{}, ErrVersionConflict
	}
	material, err := command.BuildVersion(latestNumber + 1)
	if err != nil {
		return Publication{}, err
	}
	if !validVersionMaterial(material, latestNumber+1) {
		return Publication{}, ErrInvalidRepositoryCommand
	}
	if err := insertVersion(ctx, tx, principal, command.DefinitionID, material, command.PublishedAt); err != nil {
		return Publication{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE agent_definitions SET latest_version_id = $4, updated_at = $5
		WHERE id = $3 AND tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
	`, owner.TenantID, owner.OwnerID, command.DefinitionID, material.ID, command.PublishedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return Publication{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: command.DefinitionID, VersionID: material.ID}
	if err := insertIdempotency(ctx, tx, principal, operationPublishNext, command.Idempotency,
		"agent_version", material.ID, response, command.PublishedAt); err != nil {
		return Publication{}, err
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "agent_version_published", "agent_version",
		material.ID, command.PublishedAt, map[string]string{
			"agent_definition_id": command.DefinitionID.String(), "agent_version_id": material.ID.String(),
			"content_digest": hex.EncodeToString(material.ContentDigest[:]),
		}); err != nil {
		return Publication{}, err
	}
	publication, err := loadPublication(ctx, tx, principal, command.DefinitionID, material.ID)
	if err != nil {
		return Publication{}, err
	}
	return publication, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) PublishWorkspaceInitial(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	command InitialPublicationCommand,
) (Publication, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil ||
		!validInitialPublication(command) {
		return Publication{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireWorkspaceAgentAccess(
		ctx, tx, principal, workspaceID, workspaceAgentPublish, true,
	); err != nil {
		return Publication{}, err
	}
	response, found, err := lockAndReadWorkspaceIdempotency(
		ctx, tx, workspaceID, operationPublishInitial, command.Idempotency,
	)
	if err != nil {
		return Publication{}, err
	}
	if found {
		publication, err := loadWorkspacePublication(
			ctx, tx, workspaceID, response.DefinitionID, response.VersionID,
		)
		if err != nil {
			return Publication{}, err
		}
		publication.Replayed = true
		return publication, commitTransaction(ctx, tx)
	}
	material, err := command.BuildVersion()
	if err != nil {
		return Publication{}, err
	}
	if !validVersionMaterial(material, 1) {
		return Publication{}, ErrInvalidRepositoryCommand
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_definitions (
			id, tenant_id, owner_scope, owner_id, workspace_id, display_name, icon_media_type, icon_data,
			status, latest_version_id, created_by, created_at, updated_at
		) VALUES ($1, NULL, 'WORKSPACE', NULL, $2, $3, NULLIF($4, ''), $5, 'active', NULL, $6, $7, $7)
	`, command.DefinitionID, workspaceID, command.DisplayName, command.IconMediaType,
		nilIfEmptyBytes(command.IconData), principal.UserID, command.PublishedAt.UTC()); err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	if err := insertWorkspaceVersion(
		ctx, tx, principal, workspaceID, command.DefinitionID, material, command.PublishedAt,
	); err != nil {
		return Publication{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE agent_definitions SET latest_version_id = $3, updated_at = $4
		WHERE id = $2 AND owner_scope = 'WORKSPACE' AND workspace_id = $1
	`, workspaceID, command.DefinitionID, material.ID, command.PublishedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return Publication{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: command.DefinitionID, VersionID: material.ID}
	if err := insertWorkspaceIdempotency(
		ctx, tx, workspaceID, operationPublishInitial, command.Idempotency,
		"agent_definition", command.DefinitionID, response, command.PublishedAt,
	); err != nil {
		return Publication{}, err
	}
	if err := recordWorkspaceAgentAudit(
		ctx, tx, principal, workspaceID, command.Audit, "agent_definition_published", "agent_definition",
		command.DefinitionID, command.PublishedAt, map[string]string{
			"agent_definition_id": command.DefinitionID.String(),
			"agent_version_id":    material.ID.String(),
			"content_digest":      hex.EncodeToString(material.ContentDigest[:]),
		},
	); err != nil {
		return Publication{}, err
	}
	publication, err := loadWorkspacePublication(
		ctx, tx, workspaceID, command.DefinitionID, material.ID,
	)
	if err != nil {
		return Publication{}, err
	}
	return publication, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) PublishWorkspaceNext(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	command NextPublicationCommand,
) (Publication, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil ||
		!validNextPublication(command) {
		return Publication{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireWorkspaceAgentAccess(
		ctx, tx, principal, workspaceID, workspaceAgentPublish, true,
	); err != nil {
		return Publication{}, err
	}
	response, found, err := lockAndReadWorkspaceIdempotency(
		ctx, tx, workspaceID, operationPublishNext, command.Idempotency,
	)
	if err != nil {
		return Publication{}, err
	}
	if found {
		publication, err := loadWorkspacePublication(
			ctx, tx, workspaceID, response.DefinitionID, response.VersionID,
		)
		if err != nil {
			return Publication{}, err
		}
		publication.Replayed = true
		return publication, commitTransaction(ctx, tx)
	}

	var status string
	var latestVersionID uuid.UUID
	var latestNumber int64
	err = tx.QueryRow(ctx, `
		SELECT d.status, d.latest_version_id, v.version_number
		FROM agent_definitions d
		JOIN agent_versions v ON v.id = d.latest_version_id
		WHERE d.id = $2 AND d.owner_scope = 'WORKSPACE' AND d.workspace_id = $1
		  AND v.owner_scope = 'WORKSPACE' AND v.workspace_id = $1
		FOR UPDATE OF d
	`, workspaceID, command.DefinitionID).Scan(&status, &latestVersionID, &latestNumber)
	if errors.Is(err, pgx.ErrNoRows) {
		return Publication{}, ErrNotFound
	}
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	if status == definitionStatusArchived {
		return Publication{}, ErrDefinitionArchived
	}
	if latestVersionID != command.BaseVersionID {
		return Publication{}, ErrVersionConflict
	}
	material, err := command.BuildVersion(latestNumber + 1)
	if err != nil {
		return Publication{}, err
	}
	if !validVersionMaterial(material, latestNumber+1) {
		return Publication{}, ErrInvalidRepositoryCommand
	}
	if err := insertWorkspaceVersion(
		ctx, tx, principal, workspaceID, command.DefinitionID, material, command.PublishedAt,
	); err != nil {
		return Publication{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE agent_definitions SET latest_version_id = $3, updated_at = $4
		WHERE id = $2 AND owner_scope = 'WORKSPACE' AND workspace_id = $1
	`, workspaceID, command.DefinitionID, material.ID, command.PublishedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return Publication{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: command.DefinitionID, VersionID: material.ID}
	if err := insertWorkspaceIdempotency(
		ctx, tx, workspaceID, operationPublishNext, command.Idempotency,
		"agent_version", material.ID, response, command.PublishedAt,
	); err != nil {
		return Publication{}, err
	}
	if err := recordWorkspaceAgentAudit(
		ctx, tx, principal, workspaceID, command.Audit, "agent_version_published", "agent_version",
		material.ID, command.PublishedAt, map[string]string{
			"agent_definition_id": command.DefinitionID.String(),
			"agent_version_id":    material.ID.String(),
			"content_digest":      hex.EncodeToString(material.ContentDigest[:]),
		},
	); err != nil {
		return Publication{}, err
	}
	publication, err := loadWorkspacePublication(
		ctx, tx, workspaceID, command.DefinitionID, material.ID,
	)
	if err != nil {
		return Publication{}, err
	}
	return publication, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) FindDefinition(
	ctx context.Context,
	principal Principal,
	definitionID uuid.UUID,
) (Definition, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || definitionID == uuid.Nil {
		return Definition{}, false, ErrInvalidRepositoryCommand
	}
	definition, err := scanDefinition(r.postgres.QueryRow(ctx, definitionQuery, principal.PersonalSpaceID, principal.UserID, definitionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Definition{}, false, nil
	}
	if err != nil {
		return Definition{}, false, ErrServiceUnavailable
	}
	return definition, true, nil
}

func (r *PostgresRepository) FindWorkspaceDefinition(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
) (Definition, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil ||
		definitionID == uuid.Nil {
		return Definition{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Definition{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireWorkspaceAgentAccess(
		ctx, tx, principal, workspaceID, workspaceAgentRead, true,
	); err != nil {
		return Definition{}, false, err
	}
	definition, err := loadWorkspaceDefinition(ctx, tx, workspaceID, definitionID)
	if errors.Is(err, ErrNotFound) {
		if commitErr := commitTransaction(ctx, tx); commitErr != nil {
			return Definition{}, false, commitErr
		}
		return Definition{}, false, nil
	}
	if err != nil {
		return Definition{}, false, err
	}
	return definition, true, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) FindVersion(
	ctx context.Context,
	principal Principal,
	versionID uuid.UUID,
) (Version, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || versionID == uuid.Nil {
		return Version{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Version{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	var ownerScope string
	var organizationValue pgtype.UUID
	err = tx.QueryRow(ctx, `
		SELECT owner_scope, organization_id FROM agent_versions WHERE id = $1
	`, versionID).Scan(&ownerScope, &organizationValue)
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, false, nil
	}
	if err != nil {
		return Version{}, false, ErrServiceUnavailable
	}
	var version Version
	if OwnerScope(ownerScope) == OwnerScopeOrganization {
		if !organizationValue.Valid {
			return Version{}, false, ErrServiceUnavailable
		}
		organizationID := uuid.UUID(organizationValue.Bytes)
		if _, err := requireOrganizationAgentAccess(
			ctx, tx, principal, organizationID, organizationAgentRead, true,
		); err != nil {
			if errors.Is(err, ErrOrganizationAgentNotFound) {
				return Version{}, false, nil
			}
			return Version{}, false, err
		}
		version, err = loadOrganizationVersion(ctx, tx, organizationID, versionID)
	} else {
		version, err = scanVersion(tx.QueryRow(
			ctx, versionQuery, principal.PersonalSpaceID, principal.UserID, versionID,
		))
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrNotFound) {
		return Version{}, false, nil
	}
	if err != nil {
		return Version{}, false, ErrServiceUnavailable
	}
	return version, true, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) FindPolicySnapshot(
	ctx context.Context,
	principal Principal,
	policySnapshotID uuid.UUID,
) (PolicySnapshot, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || policySnapshotID == uuid.Nil {
		return PolicySnapshot{}, false, ErrInvalidRepositoryCommand
	}
	policy, err := loadPolicy(ctx, r.postgres, principal, policySnapshotID)
	if errors.Is(err, ErrNotFound) {
		return PolicySnapshot{}, false, nil
	}
	if err != nil {
		return PolicySnapshot{}, false, err
	}
	return policy, true, nil
}

func (r *PostgresRepository) ListDefinitions(ctx context.Context, principal Principal) ([]Definition, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) {
		return nil, ErrInvalidRepositoryCommand
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT id, display_name, COALESCE(icon_media_type, ''), icon_data, status, latest_version_id, created_at, updated_at
		FROM agent_definitions
		WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
		ORDER BY updated_at DESC, id
	`, principal.PersonalSpaceID, principal.UserID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rows.Close()
	definitions := make([]Definition, 0)
	for rows.Next() {
		definition, scanErr := scanDefinition(rows)
		if scanErr != nil {
			return nil, ErrServiceUnavailable
		}
		definitions = append(definitions, definition)
	}
	if rows.Err() != nil {
		return nil, ErrServiceUnavailable
	}
	return definitions, nil
}

func (r *PostgresRepository) ListWorkspaceDefinitions(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]Definition, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireWorkspaceAgentAccess(
		ctx, tx, principal, workspaceID, workspaceAgentRead, true,
	); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, display_name, COALESCE(icon_media_type, ''), icon_data, status,
			latest_version_id, created_at, updated_at
		FROM agent_definitions
		WHERE owner_scope = 'WORKSPACE' AND workspace_id = $1
		ORDER BY updated_at DESC, id
	`, workspaceID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	definitions := make([]Definition, 0)
	for rows.Next() {
		definition, scanErr := scanDefinition(rows)
		if scanErr != nil {
			rows.Close()
			return nil, ErrServiceUnavailable
		}
		definitions = append(definitions, definition)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, ErrServiceUnavailable
	}
	if err := commitTransaction(ctx, tx); err != nil {
		return nil, err
	}
	return definitions, nil
}

func (r *PostgresRepository) ListVersions(
	ctx context.Context,
	principal Principal,
	definitionID uuid.UUID,
) ([]Version, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || definitionID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	var exists bool
	err := r.postgres.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM agent_definitions
			WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND id = $3
		)
	`, principal.PersonalSpaceID, principal.UserID, definitionID).Scan(&exists)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT id, definition_id, version_number, canonical_manifest::text, bundle::text, content_digest,
			signing_key_id, signature, runtime_minimum_version, COALESCE(runtime_maximum_version_exclusive, ''), published_at
		FROM agent_versions
		WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND definition_id = $3
		ORDER BY version_number DESC
	`, principal.PersonalSpaceID, principal.UserID, definitionID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rows.Close()
	versions := make([]Version, 0)
	for rows.Next() {
		version, scanErr := scanVersion(rows)
		if scanErr != nil {
			return nil, ErrServiceUnavailable
		}
		versions = append(versions, version)
	}
	if rows.Err() != nil {
		return nil, ErrServiceUnavailable
	}
	return versions, nil
}

func (r *PostgresRepository) ListWorkspaceVersions(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
) ([]Version, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil ||
		definitionID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireWorkspaceAgentAccess(
		ctx, tx, principal, workspaceID, workspaceAgentRead, true,
	); err != nil {
		return nil, err
	}
	var exists bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM agent_definitions
			WHERE owner_scope = 'WORKSPACE' AND workspace_id = $1 AND id = $2
		)
	`, workspaceID, definitionID).Scan(&exists)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := tx.Query(ctx, `
		SELECT id, definition_id, version_number, canonical_manifest::text, bundle::text, content_digest,
			signing_key_id, signature, runtime_minimum_version,
			COALESCE(runtime_maximum_version_exclusive, ''), published_at
		FROM agent_versions
		WHERE owner_scope = 'WORKSPACE' AND workspace_id = $1 AND definition_id = $2
		ORDER BY version_number DESC
	`, workspaceID, definitionID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	versions := make([]Version, 0)
	for rows.Next() {
		version, scanErr := scanVersion(rows)
		if scanErr != nil {
			rows.Close()
			return nil, ErrServiceUnavailable
		}
		versions = append(versions, version)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, ErrServiceUnavailable
	}
	if err := commitTransaction(ctx, tx); err != nil {
		return nil, err
	}
	return versions, nil
}

func (r *PostgresRepository) RecordDenied(
	ctx context.Context,
	principal Principal,
	command DeniedAuditCommand,
) error {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || command.EventID == uuid.Nil ||
		command.ObjectID == uuid.Nil || command.ReasonCode != "not_found" || !validRequestID(command.RequestID) ||
		command.OccurredAt.IsZero() {
		return ErrInvalidRepositoryCommand
	}
	eventType := ""
	metadata := map[string]string{
		"tenant_id": principal.PersonalSpaceID.String(), "owner_scope": string(OwnerScopeUser),
		"owner_id": principal.UserID.String(),
	}
	switch command.ObjectType {
	case "agent_definition":
		eventType = "agent_definition_access_denied"
		metadata["agent_definition_id"] = command.ObjectID.String()
	case "agent_version":
		eventType = "agent_version_access_denied"
		metadata["agent_version_id"] = command.ObjectID.String()
	case "agent_installation":
		eventType = "agent_installation_access_denied"
		metadata["agent_installation_id"] = command.ObjectID.String()
	default:
		return ErrInvalidRepositoryCommand
	}
	recorder, err := audit.NewPostgresRecorder(r.postgres)
	if err != nil {
		return ErrServiceUnavailable
	}
	actor := principal.UserID
	device := principal.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID: command.EventID, EventType: eventType, ActorUserID: &actor, DeviceID: &device,
		ObjectType: command.ObjectType, ObjectID: &command.ObjectID, Outcome: audit.OutcomeDenied,
		ReasonCode: command.ReasonCode, RequestID: command.RequestID, Metadata: metadata,
		OccurredAt: command.OccurredAt.UTC(),
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (r *PostgresRepository) CreatePendingInstallation(
	ctx context.Context,
	principal Principal,
	command CreateInstallationCommand,
) (InstallationCreation, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || !validCreateInstallation(command) {
		return InstallationCreation{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return InstallationCreation{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	var organizationAccess OrganizationAgentAccess
	if command.SourceWorkspaceID != nil {
		if _, err := requireWorkspaceAgentAccess(
			ctx, tx, principal, *command.SourceWorkspaceID, workspaceAgentInstall, true,
		); err != nil {
			return InstallationCreation{}, err
		}
	} else if command.SourceOrganizationID != nil {
		organizationAccess, err = requireOrganizationAgentAccess(
			ctx, tx, principal, *command.SourceOrganizationID, organizationAgentInstall, false,
		)
		if err != nil {
			return InstallationCreation{}, err
		}
	}
	response, found, err := lockAndReadIdempotency(ctx, tx, principal, operationCreateInstallation, command.Idempotency)
	if err != nil {
		return InstallationCreation{}, err
	}
	if found {
		installation, err := loadInstallation(ctx, tx, principal, response.InstallationID, false)
		if err != nil {
			return InstallationCreation{}, err
		}
		policy, err := loadPolicy(ctx, tx, principal, response.PolicySnapshotID)
		if err != nil {
			return InstallationCreation{}, err
		}
		result := InstallationCreation{Installation: installation, Policy: policy, Replayed: true}
		return result, commitTransaction(ctx, tx)
	}

	owner := principal.Owner()
	var deviceInstallationID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT installation_id FROM devices
		WHERE id = $1 AND user_id = $2 AND status = 'active'
	`, principal.DeviceID, principal.UserID).Scan(&deviceInstallationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return InstallationCreation{}, ErrNotFound
	}
	if err != nil {
		return InstallationCreation{}, ErrServiceUnavailable
	}
	var definitionStatus string
	var version Version
	if command.SourceWorkspaceID == nil && command.SourceOrganizationID == nil {
		err = tx.QueryRow(ctx, `
			SELECT d.status
			FROM agent_definitions d
			JOIN agent_versions v ON v.definition_id = d.id AND v.id = $4
			WHERE d.id = $3 AND d.tenant_id = $1 AND d.owner_scope = 'USER' AND d.owner_id = $2
			  AND v.tenant_id = $1 AND v.owner_scope = 'USER' AND v.owner_id = $2
		`, owner.TenantID, owner.OwnerID, command.DefinitionID, command.VersionID).Scan(&definitionStatus)
	} else if command.SourceWorkspaceID != nil {
		err = tx.QueryRow(ctx, `
			SELECT d.status
			FROM agent_definitions d
			JOIN agent_versions v ON v.definition_id = d.id AND v.id = $3
			WHERE d.id = $2 AND d.owner_scope = 'WORKSPACE' AND d.workspace_id = $1
			  AND v.owner_scope = 'WORKSPACE' AND v.workspace_id = $1
		`, *command.SourceWorkspaceID, command.DefinitionID, command.VersionID).Scan(&definitionStatus)
	} else {
		err = tx.QueryRow(ctx, `
			SELECT d.status
			FROM agent_definitions d
			JOIN agent_versions v ON v.definition_id = d.id AND v.id = $3
			WHERE d.id = $2 AND d.owner_scope = 'ORGANIZATION' AND d.organization_id = $1
			  AND v.owner_scope = 'ORGANIZATION' AND v.organization_id = $1
		`, *command.SourceOrganizationID, command.DefinitionID, command.VersionID).Scan(&definitionStatus)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		if command.SourceOrganizationID != nil {
			return InstallationCreation{}, ErrOrganizationAgentNotFound
		}
		return InstallationCreation{}, ErrNotFound
	}
	if err != nil {
		return InstallationCreation{}, ErrServiceUnavailable
	}
	if definitionStatus == definitionStatusArchived {
		return InstallationCreation{}, ErrDefinitionArchived
	}
	if command.SourceWorkspaceID == nil && command.SourceOrganizationID == nil {
		if revoked, err := versionIsRevoked(ctx, tx, principal, command.VersionID); err != nil {
			return InstallationCreation{}, err
		} else if revoked {
			return InstallationCreation{}, ErrVersionRevoked
		}
		version, err = loadVersion(ctx, tx, principal, command.VersionID)
	} else if command.SourceWorkspaceID != nil {
		version, err = loadWorkspaceVersion(ctx, tx, *command.SourceWorkspaceID, command.VersionID)
	} else {
		version, err = loadOrganizationVersion(ctx, tx, *command.SourceOrganizationID, command.VersionID)
	}
	if err != nil || version.DefinitionID != command.DefinitionID {
		if err != nil {
			return InstallationCreation{}, err
		}
		return InstallationCreation{}, ErrNotFound
	}
	var policy PolicyMaterial
	if command.SourceOrganizationID == nil {
		policy, err = command.BuildPolicy(version)
	} else {
		effective, effectiveErr := effectiveOrganizationAgentPolicyForVersion(
			version, organizationAccess.PolicyDocument,
		)
		if effectiveErr != nil {
			return InstallationCreation{}, effectiveErr
		}
		policy, err = command.BuildOrganizationPolicy(version, effective)
	}
	if err != nil {
		return InstallationCreation{}, err
	}
	if !validPolicyMaterial(policy, command.InstallationID, command.VersionID) || policy.PolicyVersion != 1 {
		return InstallationCreation{}, ErrInvalidRepositoryCommand
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO installations (
			id, tenant_id, owner_scope, owner_id, device_id, device_installation_id,
			definition_id, selected_version_id, runtime_profile_id, policy_snapshot_id,
			update_policy, status, created_by, created_at, updated_at
		) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, NULL, NULL, 'manual', 'pending', $3, $8, $8)
	`, command.InstallationID, owner.TenantID, owner.OwnerID, principal.DeviceID, deviceInstallationID,
		command.DefinitionID, command.VersionID, command.CreatedAt.UTC()); err != nil {
		return InstallationCreation{}, ErrServiceUnavailable
	}
	if err := insertPolicy(ctx, tx, principal, policy); err != nil {
		return InstallationCreation{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE installations SET policy_snapshot_id = $4, updated_at = $5
		WHERE id = $3 AND tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
	`, owner.TenantID, owner.OwnerID, command.InstallationID, policy.ID, command.CreatedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return InstallationCreation{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{InstallationID: command.InstallationID, PolicySnapshotID: policy.ID}
	if err := insertIdempotency(ctx, tx, principal, operationCreateInstallation, command.Idempotency,
		"agent_installation", command.InstallationID, response, command.CreatedAt); err != nil {
		return InstallationCreation{}, err
	}
	auditMetadata := map[string]string{
		"agent_definition_id":   command.DefinitionID.String(),
		"agent_version_id":      command.VersionID.String(),
		"agent_installation_id": command.InstallationID.String(),
		"policy_snapshot_id":    policy.ID.String(),
		"source_owner_scope":    string(OwnerScopeUser),
	}
	if command.SourceWorkspaceID != nil {
		auditMetadata["source_owner_scope"] = string(OwnerScopeWorkspace)
		auditMetadata["source_workspace_id"] = command.SourceWorkspaceID.String()
	} else if command.SourceOrganizationID != nil {
		auditMetadata["source_owner_scope"] = string(OwnerScopeOrganization)
		auditMetadata["source_organization_id"] = command.SourceOrganizationID.String()
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "agent_installation_created", "agent_installation",
		command.InstallationID, command.CreatedAt, auditMetadata); err != nil {
		return InstallationCreation{}, err
	}
	installation, err := loadInstallation(ctx, tx, principal, command.InstallationID, false)
	if err != nil {
		return InstallationCreation{}, err
	}
	storedPolicy, err := loadPolicy(ctx, tx, principal, policy.ID)
	if err != nil {
		return InstallationCreation{}, err
	}
	created := InstallationCreation{Installation: installation, Policy: storedPolicy}
	return created, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) FindInstallation(
	ctx context.Context,
	principal Principal,
	installationID uuid.UUID,
) (Installation, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || installationID == uuid.Nil {
		return Installation{}, false, ErrInvalidRepositoryCommand
	}
	installation, err := loadInstallation(ctx, r.postgres, principal, installationID, false)
	if errors.Is(err, ErrNotFound) {
		return Installation{}, false, nil
	}
	if err != nil {
		return Installation{}, false, err
	}
	return installation, true, nil
}

func (r *PostgresRepository) LoadActivationContext(
	ctx context.Context,
	principal Principal,
	installationID uuid.UUID,
) (InstallationActivationContext, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || installationID == uuid.Nil {
		return InstallationActivationContext{}, false, ErrInvalidRepositoryCommand
	}
	installation, err := loadInstallation(ctx, r.postgres, principal, installationID, false)
	if errors.Is(err, ErrNotFound) {
		return InstallationActivationContext{}, false, nil
	}
	if err != nil {
		return InstallationActivationContext{}, false, err
	}
	if installation.DeviceID != principal.DeviceID {
		return InstallationActivationContext{}, false, nil
	}
	version, err := loadVersion(ctx, r.postgres, principal, installation.SelectedVersionID)
	if err != nil {
		return InstallationActivationContext{}, false, err
	}
	var publicKey []byte
	err = r.postgres.QueryRow(ctx, `
		SELECT public_key FROM devices
		WHERE id = $1 AND user_id = $2 AND status = 'active'
	`, principal.DeviceID, principal.UserID).Scan(&publicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return InstallationActivationContext{}, false, nil
	}
	if err != nil || len(publicKey) != 32 {
		return InstallationActivationContext{}, false, ErrServiceUnavailable
	}
	return InstallationActivationContext{
		Installation: installation, Version: version, DevicePublicKey: append(ed25519.PublicKey(nil), publicKey...),
	}, true, nil
}

func (r *PostgresRepository) ActivateInstallation(
	ctx context.Context,
	principal Principal,
	command ActivationCommand,
) (Installation, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || command.InstallationID == uuid.Nil ||
		command.RuntimeProfileID == uuid.Nil || command.AgentVersionID == uuid.Nil || command.PolicySnapshotID == uuid.Nil ||
		zeroDigest(command.VersionDigest) || command.ActivatedAt.IsZero() || !validAuditEvidence(command.Audit) {
		return Installation{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Installation{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	installation, err := loadInstallation(ctx, tx, principal, command.InstallationID, true)
	if err != nil {
		return Installation{}, err
	}
	if installation.DeviceID != principal.DeviceID {
		return Installation{}, ErrNotFound
	}
	switch installation.Status {
	case InstallationStatusArchived:
		return Installation{}, ErrInstallationArchived
	case InstallationStatusActive:
		if installation.RuntimeProfileID == nil || *installation.RuntimeProfileID != command.RuntimeProfileID {
			return Installation{}, ErrActivationConflict
		}
		matches, err := activationAuditMatches(ctx, tx, principal, command)
		if err != nil {
			return Installation{}, err
		}
		if !matches {
			return Installation{}, ErrActivationConflict
		}
		return installation, commitTransaction(ctx, tx)
	case InstallationStatusPending:
		if installation.PolicySnapshotID == nil || installation.SelectedVersionID != command.AgentVersionID ||
			*installation.PolicySnapshotID != command.PolicySnapshotID {
			return Installation{}, ErrServiceUnavailable
		}
	default:
		return Installation{}, ErrServiceUnavailable
	}
	version, err := loadVersion(ctx, tx, principal, command.AgentVersionID)
	if err != nil {
		return Installation{}, err
	}
	if version.ContentDigest != command.VersionDigest {
		return Installation{}, ErrActivationConflict
	}
	owner := principal.Owner()
	result, err := tx.Exec(ctx, `
		UPDATE installations
		SET runtime_profile_id = $4, status = 'active', activated_at = $5, updated_at = $5
		WHERE id = $3 AND tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND status = 'pending'
	`, owner.TenantID, owner.OwnerID, command.InstallationID, command.RuntimeProfileID, command.ActivatedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return Installation{}, ErrServiceUnavailable
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "agent_installation_activated", "agent_installation",
		command.InstallationID, command.ActivatedAt, map[string]string{
			"agent_installation_id": command.InstallationID.String(), "agent_version_id": installation.SelectedVersionID.String(),
			"policy_snapshot_id": installation.PolicySnapshotID.String(),
			"content_digest":     hex.EncodeToString(command.VersionDigest[:]),
		}); err != nil {
		return Installation{}, err
	}
	activated, err := loadInstallation(ctx, tx, principal, command.InstallationID, false)
	if err != nil {
		return Installation{}, err
	}
	return activated, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) SelectInstallationVersion(
	ctx context.Context,
	principal Principal,
	command VersionSelectionCommand,
) (Installation, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || command.InstallationID == uuid.Nil ||
		command.VersionID == uuid.Nil || command.BuildPolicy == nil || command.SelectedAt.IsZero() ||
		!validAuditEvidence(command.Audit) {
		return Installation{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Installation{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	installation, err := loadInstallation(ctx, tx, principal, command.InstallationID, true)
	if err != nil {
		return Installation{}, err
	}
	if installation.DeviceID != principal.DeviceID {
		return Installation{}, ErrNotFound
	}
	if installation.Status == InstallationStatusArchived {
		return Installation{}, ErrInstallationArchived
	}
	if installation.Status != InstallationStatusActive {
		return Installation{}, ErrActivationConflict
	}
	owner := principal.Owner()
	var definitionStatus string
	var definitionOwnerScope string
	var workspaceValue pgtype.UUID
	var organizationValue pgtype.UUID
	err = tx.QueryRow(ctx, `
		SELECT d.status, d.owner_scope, d.workspace_id, d.organization_id
		FROM agent_definitions d
		WHERE d.id = $3 AND (
			(d.tenant_id = $1 AND d.owner_scope = 'USER' AND d.owner_id = $2)
			OR (d.owner_scope = 'WORKSPACE' AND d.workspace_id IS NOT NULL)
			OR (d.owner_scope = 'ORGANIZATION' AND d.organization_id IS NOT NULL)
		)
	`, owner.TenantID, owner.OwnerID, installation.DefinitionID).Scan(
		&definitionStatus, &definitionOwnerScope, &workspaceValue, &organizationValue,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, ErrNotFound
	}
	if err != nil {
		return Installation{}, ErrServiceUnavailable
	}
	if definitionStatus == definitionStatusArchived {
		return Installation{}, ErrDefinitionArchived
	}
	var version Version
	var organizationEffective *EffectiveOrganizationAgentPolicy
	switch OwnerScope(definitionOwnerScope) {
	case OwnerScopeUser:
		if workspaceValue.Valid || organizationValue.Valid {
			return Installation{}, ErrServiceUnavailable
		}
		if revoked, err := versionIsRevoked(ctx, tx, principal, command.VersionID); err != nil {
			return Installation{}, err
		} else if revoked {
			return Installation{}, ErrVersionRevoked
		}
		version, err = loadVersion(ctx, tx, principal, command.VersionID)
	case OwnerScopeWorkspace:
		if !workspaceValue.Valid || organizationValue.Valid {
			return Installation{}, ErrServiceUnavailable
		}
		workspaceID := uuid.UUID(workspaceValue.Bytes)
		if _, err := requireWorkspaceAgentAccess(
			ctx, tx, principal, workspaceID, workspaceAgentInstall, true,
		); err != nil {
			return Installation{}, err
		}
		version, err = loadWorkspaceVersion(ctx, tx, workspaceID, command.VersionID)
	case OwnerScopeOrganization:
		if workspaceValue.Valid || !organizationValue.Valid || command.BuildOrganizationPolicy == nil {
			return Installation{}, ErrServiceUnavailable
		}
		organizationID := uuid.UUID(organizationValue.Bytes)
		access, accessErr := requireOrganizationAgentAccess(
			ctx, tx, principal, organizationID, organizationAgentInstall, false,
		)
		if accessErr != nil {
			return Installation{}, accessErr
		}
		version, err = loadOrganizationVersion(ctx, tx, organizationID, command.VersionID)
		if err == nil {
			effective, effectiveErr := effectiveOrganizationAgentPolicyForVersion(
				version, access.PolicyDocument,
			)
			if effectiveErr != nil {
				return Installation{}, effectiveErr
			}
			organizationEffective = &effective
		}
	default:
		return Installation{}, ErrServiceUnavailable
	}
	if err != nil || version.DefinitionID != installation.DefinitionID {
		if err != nil {
			return Installation{}, err
		}
		return Installation{}, ErrNotFound
	}
	var currentPolicyVersion int64
	if installation.PolicySnapshotID == nil {
		return Installation{}, ErrServiceUnavailable
	}
	err = tx.QueryRow(ctx, `
		SELECT policy_version FROM policy_snapshots
		WHERE id = $3 AND tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
	`, owner.TenantID, owner.OwnerID, *installation.PolicySnapshotID).Scan(&currentPolicyVersion)
	if err != nil {
		return Installation{}, ErrServiceUnavailable
	}
	var policy PolicyMaterial
	if organizationEffective == nil {
		policy, err = command.BuildPolicy(currentPolicyVersion+1, version)
	} else {
		policy, err = command.BuildOrganizationPolicy(
			currentPolicyVersion+1, version, *organizationEffective,
		)
	}
	if err != nil {
		return Installation{}, err
	}
	if !validPolicyMaterial(policy, command.InstallationID, command.VersionID) ||
		policy.PolicyVersion != currentPolicyVersion+1 {
		return Installation{}, ErrInvalidRepositoryCommand
	}
	if err := insertPolicy(ctx, tx, principal, policy); err != nil {
		return Installation{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE installations
		SET selected_version_id = $4, policy_snapshot_id = $5, updated_at = $6
		WHERE id = $3 AND tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND status = 'active'
	`, owner.TenantID, owner.OwnerID, command.InstallationID, command.VersionID, policy.ID, command.SelectedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return Installation{}, ErrServiceUnavailable
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "agent_installation_version_selected", "agent_installation",
		command.InstallationID, command.SelectedAt, map[string]string{
			"agent_installation_id": command.InstallationID.String(), "agent_version_id": command.VersionID.String(),
			"policy_snapshot_id": policy.ID.String(),
		}); err != nil {
		return Installation{}, err
	}
	selected, err := loadInstallation(ctx, tx, principal, command.InstallationID, false)
	if err != nil {
		return Installation{}, err
	}
	return selected, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) ArchiveInstallation(
	ctx context.Context,
	principal Principal,
	command ArchiveInstallationCommand,
) (Installation, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || command.InstallationID == uuid.Nil ||
		command.ArchivedAt.IsZero() || !validAuditEvidence(command.Audit) {
		return Installation{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Installation{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	installation, err := loadInstallation(ctx, tx, principal, command.InstallationID, true)
	if err != nil {
		return Installation{}, err
	}
	if installation.DeviceID != principal.DeviceID {
		return Installation{}, ErrNotFound
	}
	if installation.Status == InstallationStatusArchived {
		return installation, commitTransaction(ctx, tx)
	}
	owner := principal.Owner()
	result, err := tx.Exec(ctx, `
		UPDATE installations SET status = 'archived', archived_at = $4, updated_at = $4
		WHERE id = $3 AND tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
	`, owner.TenantID, owner.OwnerID, command.InstallationID, command.ArchivedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return Installation{}, ErrServiceUnavailable
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "agent_installation_archived", "agent_installation",
		command.InstallationID, command.ArchivedAt, map[string]string{
			"agent_installation_id": command.InstallationID.String(), "agent_version_id": installation.SelectedVersionID.String(),
		}); err != nil {
		return Installation{}, err
	}
	archived, err := loadInstallation(ctx, tx, principal, command.InstallationID, false)
	if err != nil {
		return Installation{}, err
	}
	return archived, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) InsertRuntimeBinding(
	ctx context.Context,
	principal Principal,
	command PersistRuntimeBindingCommand,
) (RuntimeBindingRecord, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) ||
		!validRuntimeBinding(command.RuntimeBindingRecordCommand) || !validAuditEvidence(command.Audit) || command.CreatedAt.IsZero() {
		return RuntimeBindingRecord{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return RuntimeBindingRecord{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	installation, err := loadInstallation(ctx, tx, principal, command.AgentInstallationID, true)
	if err != nil {
		return RuntimeBindingRecord{}, err
	}
	if installation.DeviceID != principal.DeviceID || installation.Status != InstallationStatusActive ||
		installation.RuntimeProfileID == nil || *installation.RuntimeProfileID != command.RuntimeProfileID ||
		installation.SelectedVersionID != command.AgentVersionID || installation.PolicySnapshotID == nil ||
		*installation.PolicySnapshotID != command.PolicySnapshotID {
		return RuntimeBindingRecord{}, ErrNotFound
	}
	owner := principal.Owner()
	if _, err := tx.Exec(ctx, `
		INSERT INTO runtime_binding_records (
			id, tenant_id, owner_scope, owner_id, device_id, agent_installation_id,
			agent_version_id, runtime_profile_id, runtime_version, policy_snapshot_id,
			tool_permission_digest, created_at
		) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, command.BindingID, owner.TenantID, owner.OwnerID, principal.DeviceID, command.AgentInstallationID,
		command.AgentVersionID, command.RuntimeProfileID, command.RuntimeVersion, command.PolicySnapshotID,
		command.ToolPermissionDigest[:], command.CreatedAt.UTC()); err != nil {
		return RuntimeBindingRecord{}, ErrServiceUnavailable
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "runtime_binding_recorded", "runtime_binding_record",
		command.BindingID, command.CreatedAt, map[string]string{
			"agent_installation_id": command.AgentInstallationID.String(), "agent_version_id": command.AgentVersionID.String(),
			"policy_snapshot_id": command.PolicySnapshotID.String(),
		}); err != nil {
		return RuntimeBindingRecord{}, err
	}
	record := RuntimeBindingRecord{
		ID: command.BindingID, DeviceID: principal.DeviceID, AgentInstallationID: command.AgentInstallationID,
		AgentVersionID: command.AgentVersionID, RuntimeProfileID: command.RuntimeProfileID,
		RuntimeVersion: command.RuntimeVersion, PolicySnapshotID: command.PolicySnapshotID,
		ToolPermissionDigest: command.ToolPermissionDigest, CreatedAt: command.CreatedAt.UTC(),
	}
	if err := tx.Commit(ctx); err != nil {
		return RuntimeBindingRecord{}, ErrServiceUnavailable
	}
	return record, nil
}

func (r *PostgresRepository) AppendVersionRevocation(
	ctx context.Context,
	principal Principal,
	command VersionRevocationCommand,
) (VersionRevocation, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || !validVersionRevocation(command) {
		return VersionRevocation{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return VersionRevocation{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, replayed, err := lockAndReadIdempotency(ctx, tx, principal, operationRevokeVersion, command.Idempotency)
	if err != nil {
		return VersionRevocation{}, err
	}
	if replayed {
		existing, found, err := findVersionRevocation(ctx, tx, principal, response.VersionID)
		if err != nil {
			return VersionRevocation{}, err
		}
		if !found {
			return VersionRevocation{}, ErrServiceUnavailable
		}
		existing.Replayed = true
		return existing, commitTransaction(ctx, tx)
	}
	owner := principal.Owner()
	if _, err := loadVersion(ctx, tx, principal, command.VersionID); err != nil {
		return VersionRevocation{}, err
	}
	if _, err := loadPolicy(ctx, tx, principal, command.PolicySnapshotID); err != nil {
		return VersionRevocation{}, err
	}
	_, found, err := findVersionRevocation(ctx, tx, principal, command.VersionID)
	if err != nil {
		return VersionRevocation{}, err
	}
	if found {
		return VersionRevocation{}, ErrVersionRevoked
	}
	if command.SupersedingVersionID != nil {
		if _, err := loadVersion(ctx, tx, principal, *command.SupersedingVersionID); err != nil {
			return VersionRevocation{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_version_revocations (
			id, version_id, tenant_id, owner_scope, owner_id, reason_code, actor_user_id,
			policy_snapshot_id, superseding_version_id, created_at
		) VALUES ($1, $2, $3, 'USER', $4, $5, $4, $6, $7, $8)
	`, command.RevocationID, command.VersionID, owner.TenantID, owner.OwnerID, command.ReasonCode,
		command.PolicySnapshotID, command.SupersedingVersionID, command.RevokedAt.UTC()); err != nil {
		return VersionRevocation{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{VersionID: command.VersionID}
	if err := insertIdempotency(ctx, tx, principal, operationRevokeVersion, command.Idempotency,
		"agent_version_revocation", command.RevocationID, response, command.RevokedAt); err != nil {
		return VersionRevocation{}, err
	}
	if err := recordAudit(ctx, tx, principal, command.Audit, "agent_version_revoked", "agent_version",
		command.VersionID, command.RevokedAt, map[string]string{
			"agent_version_id": command.VersionID.String(), "policy_snapshot_id": command.PolicySnapshotID.String(),
		}); err != nil {
		return VersionRevocation{}, err
	}
	revocation := VersionRevocation{
		ID: command.RevocationID, VersionID: command.VersionID, ReasonCode: command.ReasonCode,
		PolicySnapshotID: command.PolicySnapshotID, SupersedingVersionID: cloneUUIDPointer(command.SupersedingVersionID),
		CreatedAt: command.RevokedAt.UTC(),
	}
	return revocation, commitTransaction(ctx, tx)
}

const definitionQuery = `
	SELECT id, display_name, COALESCE(icon_media_type, ''), icon_data, status, latest_version_id, created_at, updated_at
	FROM agent_definitions
	WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND id = $3
`

const versionQuery = `
	SELECT v.id, v.definition_id, v.version_number, v.canonical_manifest::text, v.bundle::text, v.content_digest,
		v.signing_key_id, v.signature, v.runtime_minimum_version,
		COALESCE(v.runtime_maximum_version_exclusive, ''), v.published_at
	FROM agent_versions v
	LEFT JOIN workspaces workspace ON workspace.id = v.workspace_id
	LEFT JOIN users workspace_owner ON workspace_owner.id = workspace.owner_user_id
	LEFT JOIN workspace_memberships membership
		ON membership.workspace_id = v.workspace_id AND membership.user_id = $2
	LEFT JOIN organizations organization ON organization.id = v.organization_id
	LEFT JOIN organization_memberships organization_membership
		ON organization_membership.organization_id = v.organization_id
		AND organization_membership.user_id = $2
	LEFT JOIN users organization_member
		ON organization_member.id = organization_membership.user_id
	WHERE v.id = $3 AND (
		(v.tenant_id = $1 AND v.owner_scope = 'USER' AND v.owner_id = $2)
		OR (
			v.owner_scope = 'WORKSPACE' AND membership.user_id IS NOT NULL
			AND workspace.status = 'active' AND workspace_owner.status = 'active'
		)
		OR (
			v.owner_scope = 'ORGANIZATION' AND organization_membership.user_id IS NOT NULL
			AND organization.status IN ('active', 'archived')
			AND organization_member.status = 'active'
		)
	)
`

const workspaceDefinitionQuery = `
	SELECT id, display_name, COALESCE(icon_media_type, ''), icon_data, status,
		latest_version_id, created_at, updated_at
	FROM agent_definitions
	WHERE owner_scope = 'WORKSPACE' AND workspace_id = $1 AND id = $2
`

const workspaceVersionQuery = `
	SELECT id, definition_id, version_number, canonical_manifest::text, bundle::text, content_digest,
		signing_key_id, signature, runtime_minimum_version,
		COALESCE(runtime_maximum_version_exclusive, ''), published_at
	FROM agent_versions
	WHERE owner_scope = 'WORKSPACE' AND workspace_id = $1 AND id = $2
`

const installationQuery = `
	SELECT id, device_id, device_installation_id, definition_id, selected_version_id,
		runtime_profile_id, policy_snapshot_id, update_policy, status, created_at, updated_at, activated_at, archived_at
	FROM installations
	WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND id = $3
`

type rowScanner interface {
	Scan(...any) error
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func requireWorkspaceAgentAccess(
	ctx context.Context,
	queryer queryRower,
	principal Principal,
	workspaceID uuid.UUID,
	mode workspaceAgentAccessMode,
	forUpdate bool,
) (string, error) {
	query := `
		SELECT w.status, owner.status, membership.role, actor.status,
			EXISTS (
				SELECT 1 FROM devices device
				WHERE device.id = $3 AND device.user_id = $2 AND device.status = 'active'
			),
			EXISTS (
				SELECT 1 FROM workspace_memberships fixed_owner
				WHERE fixed_owner.workspace_id = w.id AND fixed_owner.user_id = w.owner_user_id
				  AND fixed_owner.role = 'owner'
			)
		FROM workspaces w
		JOIN workspace_memberships membership
			ON membership.workspace_id = w.id AND membership.user_id = $2
		JOIN users owner ON owner.id = w.owner_user_id
		JOIN users actor ON actor.id = membership.user_id
		WHERE w.id = $1
	`
	if forUpdate {
		query += ` FOR UPDATE OF w, membership`
	}
	var workspaceStatus string
	var ownerStatus string
	var role string
	var actorStatus string
	var deviceActive bool
	var fixedOwner bool
	err := queryer.QueryRow(ctx, query, workspaceID, principal.UserID, principal.DeviceID).Scan(
		&workspaceStatus, &ownerStatus, &role, &actorStatus, &deviceActive, &fixedOwner,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil || !fixedOwner {
		return "", ErrServiceUnavailable
	}
	if actorStatus != "active" || !deviceActive {
		if ownerStatus != "active" && role == "owner" {
			return "", ErrWorkspaceOwnerUnavailable
		}
		return "", ErrNotFound
	}
	if workspaceStatus == "archived" {
		return "", ErrWorkspaceArchived
	}
	if workspaceStatus != "active" {
		return "", ErrServiceUnavailable
	}
	if ownerStatus != "active" {
		return "", ErrWorkspaceOwnerUnavailable
	}
	if role != "owner" && role != "admin" && role != "member" {
		return "", ErrServiceUnavailable
	}
	switch mode {
	case workspaceAgentRead, workspaceAgentInstall, workspaceAgentContribute:
	case workspaceAgentPublish, workspaceAgentReview:
		if role != "owner" && role != "admin" {
			return "", ErrWorkspaceForbidden
		}
	default:
		return "", ErrServiceUnavailable
	}
	return role, nil
}

func scanDefinition(row rowScanner) (Definition, error) {
	var definition Definition
	var latest pgtype.UUID
	if err := row.Scan(&definition.ID, &definition.DisplayName, &definition.IconMediaType, &definition.IconData,
		&definition.Status, &latest, &definition.CreatedAt, &definition.UpdatedAt); err != nil {
		return Definition{}, err
	}
	if latest.Valid {
		value := uuid.UUID(latest.Bytes)
		definition.LatestVersionID = &value
	}
	definition.IconData = append([]byte(nil), definition.IconData...)
	return definition, nil
}

func scanVersion(row rowScanner) (Version, error) {
	var version Version
	var digest []byte
	var manifest string
	var bundle string
	if err := row.Scan(&version.ID, &version.DefinitionID, &version.VersionNumber, &manifest, &bundle, &digest,
		&version.SigningKeyID, &version.Signature, &version.RuntimeMinimumVersion,
		&version.RuntimeMaximumVersionExclusive, &version.PublishedAt); err != nil {
		return Version{}, err
	}
	if len(digest) != sha256.Size {
		return Version{}, ErrServiceUnavailable
	}
	copy(version.ContentDigest[:], digest)
	version.CanonicalManifest = []byte(manifest)
	version.Bundle = []byte(bundle)
	version.Signature = append([]byte(nil), version.Signature...)
	return version, nil
}

func loadPublication(
	ctx context.Context,
	queryer queryRower,
	principal Principal,
	definitionID uuid.UUID,
	versionID uuid.UUID,
) (Publication, error) {
	definition, err := scanDefinition(queryer.QueryRow(ctx, definitionQuery,
		principal.PersonalSpaceID, principal.UserID, definitionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Publication{}, ErrNotFound
	}
	if err != nil {
		return Publication{}, ErrServiceUnavailable
	}
	version, err := loadVersion(ctx, queryer, principal, versionID)
	if err != nil {
		return Publication{}, err
	}
	if version.DefinitionID != definition.ID {
		return Publication{}, ErrNotFound
	}
	return Publication{Definition: definition, Version: version}, nil
}

func loadWorkspacePublication(
	ctx context.Context,
	queryer queryRower,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
	versionID uuid.UUID,
) (Publication, error) {
	definition, err := loadWorkspaceDefinition(ctx, queryer, workspaceID, definitionID)
	if err != nil {
		return Publication{}, err
	}
	version, err := loadWorkspaceVersion(ctx, queryer, workspaceID, versionID)
	if err != nil {
		return Publication{}, err
	}
	if version.DefinitionID != definition.ID {
		return Publication{}, ErrNotFound
	}
	return Publication{Definition: definition, Version: version}, nil
}

func loadWorkspaceDefinition(
	ctx context.Context,
	queryer queryRower,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
) (Definition, error) {
	definition, err := scanDefinition(queryer.QueryRow(
		ctx, workspaceDefinitionQuery, workspaceID, definitionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Definition{}, ErrNotFound
	}
	if err != nil {
		return Definition{}, ErrServiceUnavailable
	}
	return definition, nil
}

func loadVersion(ctx context.Context, queryer queryRower, principal Principal, versionID uuid.UUID) (Version, error) {
	version, err := scanVersion(queryer.QueryRow(ctx, versionQuery,
		principal.PersonalSpaceID, principal.UserID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, ErrServiceUnavailable
	}
	return version, nil
}

func loadWorkspaceVersion(
	ctx context.Context,
	queryer queryRower,
	workspaceID uuid.UUID,
	versionID uuid.UUID,
) (Version, error) {
	version, err := scanVersion(queryer.QueryRow(ctx, workspaceVersionQuery, workspaceID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, ErrServiceUnavailable
	}
	return version, nil
}

func loadInstallation(
	ctx context.Context,
	queryer queryRower,
	principal Principal,
	installationID uuid.UUID,
	forUpdate bool,
) (Installation, error) {
	query := installationQuery
	if forUpdate {
		query += " FOR UPDATE"
	}
	var installation Installation
	var runtimeProfile, policySnapshot pgtype.UUID
	var activatedAt, archivedAt pgtype.Timestamptz
	err := queryer.QueryRow(ctx, query, principal.PersonalSpaceID, principal.UserID, installationID).Scan(
		&installation.ID, &installation.DeviceID, &installation.DeviceInstallationID, &installation.DefinitionID,
		&installation.SelectedVersionID, &runtimeProfile, &policySnapshot, &installation.UpdatePolicy,
		&installation.Status, &installation.CreatedAt, &installation.UpdatedAt, &activatedAt, &archivedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, ErrNotFound
	}
	if err != nil {
		return Installation{}, ErrServiceUnavailable
	}
	if runtimeProfile.Valid {
		value := uuid.UUID(runtimeProfile.Bytes)
		installation.RuntimeProfileID = &value
	}
	if policySnapshot.Valid {
		value := uuid.UUID(policySnapshot.Bytes)
		installation.PolicySnapshotID = &value
	}
	if activatedAt.Valid {
		value := activatedAt.Time
		installation.ActivatedAt = &value
	}
	if archivedAt.Valid {
		value := archivedAt.Time
		installation.ArchivedAt = &value
	}
	return installation, nil
}

func loadPolicy(ctx context.Context, queryer queryRower, principal Principal, policyID uuid.UUID) (PolicySnapshot, error) {
	var policy PolicySnapshot
	var document string
	var digest []byte
	err := queryer.QueryRow(ctx, `
		SELECT id, installation_id, agent_version_id, policy_version, policy_document::text,
			content_digest, issuer, signing_key_id, signature, created_at
		FROM policy_snapshots
		WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND id = $3
	`, principal.PersonalSpaceID, principal.UserID, policyID).Scan(
		&policy.ID, &policy.InstallationID, &policy.AgentVersionID, &policy.PolicyVersion, &document,
		&digest, &policy.Issuer, &policy.SigningKeyID, &policy.Signature, &policy.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicySnapshot{}, ErrNotFound
	}
	if err != nil || len(digest) != sha256.Size {
		return PolicySnapshot{}, ErrServiceUnavailable
	}
	policy.Document = []byte(document)
	copy(policy.ContentDigest[:], digest)
	policy.Signature = append([]byte(nil), policy.Signature...)
	return policy, nil
}

func insertVersion(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	definitionID uuid.UUID,
	material VersionMaterial,
	publishedAt time.Time,
) error {
	if !validVersionMaterial(material, material.VersionNumber) {
		return ErrInvalidRepositoryCommand
	}
	owner := principal.Owner()
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_versions (
			id, definition_id, tenant_id, owner_scope, owner_id, version_number,
			canonical_manifest, bundle, content_digest, signing_key_id, signature,
			runtime_minimum_version, runtime_maximum_version_exclusive, published_by, published_at
		) VALUES ($1, $2, $3, 'USER', $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11, NULLIF($12, ''), $4, $13)
	`, material.ID, definitionID, owner.TenantID, owner.OwnerID, material.VersionNumber,
		string(material.CanonicalManifest), string(material.Bundle), material.ContentDigest[:], material.SigningKeyID,
		material.Signature, material.RuntimeMinimumVersion, material.RuntimeMaximumVersionExclusive, publishedAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func insertWorkspaceVersion(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
	material VersionMaterial,
	publishedAt time.Time,
) error {
	if workspaceID == uuid.Nil || !validVersionMaterial(material, material.VersionNumber) {
		return ErrInvalidRepositoryCommand
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_versions (
			id, definition_id, tenant_id, owner_scope, owner_id, workspace_id, version_number,
			canonical_manifest, bundle, content_digest, signing_key_id, signature,
			runtime_minimum_version, runtime_maximum_version_exclusive, published_by, published_at
		) VALUES ($1, $2, NULL, 'WORKSPACE', NULL, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, $10, NULLIF($11, ''), $12, $13)
	`, material.ID, definitionID, workspaceID, material.VersionNumber,
		string(material.CanonicalManifest), string(material.Bundle), material.ContentDigest[:], material.SigningKeyID,
		material.Signature, material.RuntimeMinimumVersion, material.RuntimeMaximumVersionExclusive,
		principal.UserID, publishedAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func insertPolicy(ctx context.Context, tx pgx.Tx, principal Principal, policy PolicyMaterial) error {
	if !validPolicyMaterial(policy, policy.InstallationID, policy.AgentVersionID) {
		return ErrInvalidRepositoryCommand
	}
	owner := principal.Owner()
	if _, err := tx.Exec(ctx, `
		INSERT INTO policy_snapshots (
			id, installation_id, agent_version_id, tenant_id, owner_scope, owner_id,
			policy_version, policy_document, content_digest, issuer, signing_key_id,
			signature, created_by, created_at
		) VALUES ($1, $2, $3, $4, 'USER', $5, $6, $7::jsonb, $8, $9, $10, $11, $5, $12)
	`, policy.ID, policy.InstallationID, policy.AgentVersionID, owner.TenantID, owner.OwnerID,
		policy.PolicyVersion, string(policy.Document), policy.ContentDigest[:], policy.Issuer,
		policy.SigningKeyID, policy.Signature, policy.CreatedAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

type idempotencyResponse struct {
	DefinitionID     uuid.UUID `json:"definition_id,omitempty"`
	DraftID          uuid.UUID `json:"draft_id,omitempty"`
	VersionID        uuid.UUID `json:"version_id,omitempty"`
	InstallationID   uuid.UUID `json:"installation_id,omitempty"`
	PolicySnapshotID uuid.UUID `json:"policy_snapshot_id,omitempty"`
	CandidateID      uuid.UUID `json:"candidate_id,omitempty"`
	ReviewID         uuid.UUID `json:"review_id,omitempty"`
	SubmissionID     uuid.UUID `json:"submission_id,omitempty"`
}

func lockAndReadIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	operation string,
	evidence IdempotencyEvidence,
) (idempotencyResponse, bool, error) {
	lockID := idempotencyLockID(principal, operation, evidence.KeyHash)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	var requestHash []byte
	var encoded []byte
	err := tx.QueryRow(ctx, `
		SELECT request_hash, response_document
		FROM agent_control_idempotency_keys
		WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
		  AND operation = $3 AND key_hash = $4
	`, principal.PersonalSpaceID, principal.UserID, operation, evidence.KeyHash[:]).Scan(&requestHash, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return idempotencyResponse{}, false, nil
	}
	if err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	if len(requestHash) != sha256.Size || subtle.ConstantTimeCompare(requestHash, evidence.RequestHash[:]) != 1 {
		return idempotencyResponse{}, false, ErrIdempotencyConflict
	}
	var response idempotencyResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	return response, true, nil
}

func lockAndReadWorkspaceIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	workspaceID uuid.UUID,
	operation string,
	evidence IdempotencyEvidence,
) (idempotencyResponse, bool, error) {
	lockID := workspaceAgentIdempotencyLockID(workspaceID, operation, evidence.KeyHash)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	var requestHash []byte
	var encoded []byte
	err := tx.QueryRow(ctx, `
		SELECT request_hash, response_document
		FROM agent_control_idempotency_keys
		WHERE owner_scope = 'WORKSPACE' AND workspace_id = $1
		  AND operation = $2 AND key_hash = $3
	`, workspaceID, operation, evidence.KeyHash[:]).Scan(&requestHash, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return idempotencyResponse{}, false, nil
	}
	if err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	if len(requestHash) != sha256.Size || subtle.ConstantTimeCompare(requestHash, evidence.RequestHash[:]) != 1 {
		return idempotencyResponse{}, false, ErrIdempotencyConflict
	}
	var response idempotencyResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	return response, true, nil
}

func insertIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	operation string,
	evidence IdempotencyEvidence,
	resourceType string,
	resourceID uuid.UUID,
	response idempotencyResponse,
	createdAt time.Time,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return ErrServiceUnavailable
	}
	owner := principal.Owner()
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_control_idempotency_keys (
			id, tenant_id, owner_scope, owner_id, operation, key_hash, request_hash,
			resource_type, resource_id, response_document, created_at, expires_at
		) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
	`, evidence.ID, owner.TenantID, owner.OwnerID, operation, evidence.KeyHash[:], evidence.RequestHash[:],
		resourceType, resourceID, string(encoded), createdAt.UTC(), evidence.ExpiresAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func insertWorkspaceIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	workspaceID uuid.UUID,
	operation string,
	evidence IdempotencyEvidence,
	resourceType string,
	resourceID uuid.UUID,
	response idempotencyResponse,
	createdAt time.Time,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_control_idempotency_keys (
			id, tenant_id, owner_scope, owner_id, workspace_id, operation, key_hash, request_hash,
			resource_type, resource_id, response_document, created_at, expires_at
		) VALUES ($1, NULL, 'WORKSPACE', NULL, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
	`, evidence.ID, workspaceID, operation, evidence.KeyHash[:], evidence.RequestHash[:],
		resourceType, resourceID, string(encoded), createdAt.UTC(), evidence.ExpiresAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func idempotencyLockID(principal Principal, operation string, keyHash [sha256.Size]byte) int64 {
	payload := append([]byte(principal.PersonalSpaceID.String()+"\x00"+principal.UserID.String()+"\x00"+operation+"\x00"), keyHash[:]...)
	digest := sha256.Sum256(payload)
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func workspaceAgentIdempotencyLockID(
	workspaceID uuid.UUID,
	operation string,
	keyHash [sha256.Size]byte,
) int64 {
	payload := append([]byte("WORKSPACE\x00"+workspaceID.String()+"\x00"+operation+"\x00"), keyHash[:]...)
	digest := sha256.Sum256(payload)
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func recordAudit(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	evidence AuditEvidence,
	eventType string,
	objectType string,
	objectID uuid.UUID,
	occurredAt time.Time,
	metadata map[string]string,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	bounded := map[string]string{
		"tenant_id":   principal.PersonalSpaceID.String(),
		"owner_scope": string(OwnerScopeUser),
		"owner_id":    principal.UserID.String(),
	}
	for key, value := range metadata {
		bounded[key] = value
	}
	actor := principal.UserID
	device := principal.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID: evidence.EventID, EventType: eventType, ActorUserID: &actor, DeviceID: &device,
		ObjectType: objectType, ObjectID: &objectID, Outcome: audit.OutcomeSuccess,
		RequestID: evidence.RequestID, Metadata: bounded, OccurredAt: occurredAt.UTC(),
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func recordWorkspaceAgentAudit(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	workspaceID uuid.UUID,
	evidence AuditEvidence,
	eventType string,
	objectType string,
	objectID uuid.UUID,
	occurredAt time.Time,
	metadata map[string]string,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	bounded := map[string]string{
		"owner_scope":  string(OwnerScopeWorkspace),
		"workspace_id": workspaceID.String(),
	}
	for key, value := range metadata {
		bounded[key] = value
	}
	actor := principal.UserID
	device := principal.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID: evidence.EventID, EventType: eventType, ActorUserID: &actor, DeviceID: &device,
		ObjectType: objectType, ObjectID: &objectID, Outcome: audit.OutcomeSuccess,
		RequestID: evidence.RequestID, Metadata: bounded, OccurredAt: occurredAt.UTC(),
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func versionIsRevoked(ctx context.Context, queryer queryRower, principal Principal, versionID uuid.UUID) (bool, error) {
	var exists bool
	err := queryer.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM agent_version_revocations
			WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND version_id = $3
		)
	`, principal.PersonalSpaceID, principal.UserID, versionID).Scan(&exists)
	if err != nil {
		return false, ErrServiceUnavailable
	}
	return exists, nil
}

func activationAuditMatches(
	ctx context.Context,
	queryer queryRower,
	principal Principal,
	command ActivationCommand,
) (bool, error) {
	var versionText, policyText, digestText string
	err := queryer.QueryRow(ctx, `
		SELECT metadata->>'agent_version_id', metadata->>'policy_snapshot_id', metadata->>'content_digest'
		FROM audit_events
		WHERE event_type = 'agent_installation_activated' AND outcome = 'success'
		  AND actor_user_id = $1 AND device_id = $2 AND object_type = 'agent_installation' AND object_id = $3
		  AND metadata->>'tenant_id' = $4 AND metadata->>'owner_scope' = 'USER' AND metadata->>'owner_id' = $1::text
		ORDER BY created_at ASC, id ASC
		LIMIT 1
	`, principal.UserID, principal.DeviceID, command.InstallationID, principal.PersonalSpaceID.String()).Scan(
		&versionText, &policyText, &digestText,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrServiceUnavailable
	}
	if err != nil {
		return false, ErrServiceUnavailable
	}
	versionID, versionErr := uuid.Parse(versionText)
	policyID, policyErr := uuid.Parse(policyText)
	digest, digestErr := hex.DecodeString(digestText)
	if versionErr != nil || policyErr != nil || digestErr != nil || len(digest) != sha256.Size {
		return false, ErrServiceUnavailable
	}
	return versionID == command.AgentVersionID && policyID == command.PolicySnapshotID &&
		subtle.ConstantTimeCompare(digest, command.VersionDigest[:]) == 1, nil
}

func findVersionRevocation(
	ctx context.Context,
	queryer queryRower,
	principal Principal,
	versionID uuid.UUID,
) (VersionRevocation, bool, error) {
	var revocation VersionRevocation
	var superseding pgtype.UUID
	err := queryer.QueryRow(ctx, `
		SELECT id, version_id, reason_code, policy_snapshot_id, superseding_version_id, created_at
		FROM agent_version_revocations
		WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND version_id = $3
	`, principal.PersonalSpaceID, principal.UserID, versionID).Scan(
		&revocation.ID, &revocation.VersionID, &revocation.ReasonCode, &revocation.PolicySnapshotID,
		&superseding, &revocation.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return VersionRevocation{}, false, nil
	}
	if err != nil {
		return VersionRevocation{}, false, ErrServiceUnavailable
	}
	if superseding.Valid {
		value := uuid.UUID(superseding.Bytes)
		revocation.SupersedingVersionID = &value
	}
	return revocation, true, nil
}

func validPrincipal(principal Principal) bool {
	return principal.UserID != uuid.Nil && principal.DeviceID != uuid.Nil && principal.PersonalSpaceID != uuid.Nil
}

func validInitialPublication(command InitialPublicationCommand) bool {
	name := strings.TrimSpace(command.DisplayName)
	return command.DefinitionID != uuid.Nil && name == command.DisplayName && utf8.ValidString(name) &&
		len([]rune(name)) >= 1 && len([]rune(name)) <= 100 && validIcon(command.IconMediaType, command.IconData) &&
		command.BuildVersion != nil && validIdempotency(command.Idempotency, command.PublishedAt) &&
		validAuditEvidence(command.Audit) && !command.PublishedAt.IsZero()
}

func validNextPublication(command NextPublicationCommand) bool {
	return command.DefinitionID != uuid.Nil && command.BaseVersionID != uuid.Nil && command.BuildVersion != nil &&
		validIdempotency(command.Idempotency, command.PublishedAt) && validAuditEvidence(command.Audit) &&
		!command.PublishedAt.IsZero()
}

func validVersionMaterial(material VersionMaterial, expectedNumber int64) bool {
	return material.ID != uuid.Nil && material.VersionNumber == expectedNumber && expectedNumber > 0 &&
		len(material.CanonicalManifest) > 0 && len(material.CanonicalManifest) <= MaxManifestBytes && json.Valid(material.CanonicalManifest) &&
		len(material.Bundle) > 0 && len(material.Bundle) <= MaxBundleBytes && json.Valid(material.Bundle) &&
		!zeroDigest(material.ContentDigest) && validToken(material.SigningKeyID, 128) && len(material.Signature) == 64 &&
		validToken(material.RuntimeMinimumVersion, 128) &&
		(material.RuntimeMaximumVersionExclusive == "" || validToken(material.RuntimeMaximumVersionExclusive, 128))
}

func validCreateInstallation(command CreateInstallationCommand) bool {
	return command.InstallationID != uuid.Nil && command.DefinitionID != uuid.Nil && command.VersionID != uuid.Nil &&
		(command.SourceWorkspaceID == nil || *command.SourceWorkspaceID != uuid.Nil) &&
		(command.SourceOrganizationID == nil || *command.SourceOrganizationID != uuid.Nil) &&
		(command.SourceWorkspaceID == nil || command.SourceOrganizationID == nil) && command.BuildPolicy != nil &&
		(command.SourceOrganizationID == nil || command.BuildOrganizationPolicy != nil) &&
		validIdempotency(command.Idempotency, command.CreatedAt) && validAuditEvidence(command.Audit) && !command.CreatedAt.IsZero()
}

func validPolicyMaterial(policy PolicyMaterial, installationID uuid.UUID, versionID uuid.UUID) bool {
	return policy.ID != uuid.Nil && policy.InstallationID == installationID && policy.AgentVersionID == versionID &&
		policy.PolicyVersion > 0 && len(policy.Document) > 0 && len(policy.Document) <= MaxManifestBytes && json.Valid(policy.Document) &&
		!zeroDigest(policy.ContentDigest) && validToken(policy.Issuer, 128) && validToken(policy.SigningKeyID, 128) &&
		len(policy.Signature) == 64 && !policy.CreatedAt.IsZero()
}

func validRuntimeBinding(command RuntimeBindingRecordCommand) bool {
	return command.BindingID != uuid.Nil && command.AgentInstallationID != uuid.Nil && command.AgentVersionID != uuid.Nil &&
		command.RuntimeProfileID != uuid.Nil && command.PolicySnapshotID != uuid.Nil && !zeroDigest(command.ToolPermissionDigest) &&
		validToken(command.RuntimeVersion, 128)
}

func validVersionRevocation(command VersionRevocationCommand) bool {
	return command.RevocationID != uuid.Nil && command.VersionID != uuid.Nil && command.PolicySnapshotID != uuid.Nil &&
		validToken(command.ReasonCode, 64) && (command.SupersedingVersionID == nil ||
		(*command.SupersedingVersionID != uuid.Nil && *command.SupersedingVersionID != command.VersionID)) &&
		validIdempotency(command.Idempotency, command.RevokedAt) && validAuditEvidence(command.Audit) &&
		!command.RevokedAt.IsZero()
}

func validIdempotency(evidence IdempotencyEvidence, createdAt time.Time) bool {
	return evidence.ID != uuid.Nil && !zeroDigest(evidence.KeyHash) && !zeroDigest(evidence.RequestHash) &&
		!evidence.ExpiresAt.IsZero() && evidence.ExpiresAt.After(createdAt)
}

func validAuditEvidence(evidence AuditEvidence) bool {
	if evidence.EventID == uuid.Nil || len(evidence.RequestID) > 128 {
		return false
	}
	for _, value := range evidence.RequestID {
		if !(value >= 'a' && value <= 'z') && !(value >= 'A' && value <= 'Z') &&
			!(value >= '0' && value <= '9') && value != '.' && value != '_' && value != ':' && value != '-' {
			return false
		}
	}
	return evidence.RequestID != ""
}

func validIcon(mediaType string, data []byte) bool {
	if mediaType == "" {
		return len(data) == 0
	}
	return (mediaType == "image/png" || mediaType == "image/webp") && len(data) > 0 && len(data) <= MaxIconBytes
}

func validToken(value string, maximum int) bool {
	return value != "" && strings.TrimSpace(value) == value && utf8.ValidString(value) && len([]byte(value)) <= maximum &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func commitTransaction(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func rollback(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}

func nilIfEmptyBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func uuidPointersEqual(left *uuid.UUID, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
