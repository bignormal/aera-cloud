package organization

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationOrganizationCreate = "organization_create"

type IdempotencyEvidence struct {
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
	ExpiresAt     time.Time
}

type AuditEvidence struct {
	EventID   uuid.UUID
	RequestID string
}

type CreateTransaction struct {
	Actor            Actor
	OrganizationID   uuid.UUID
	DisplayName      string
	OwnedLimit       int
	PolicySnapshotID uuid.UUID
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	CreatedAt        time.Time
}

type PageCursor struct {
	SortKey string
	ID      uuid.UUID
}

type Page struct {
	Limit int
	After *PageCursor
}

type OrganizationPage struct {
	Items []OrganizationSummary
	Next  *PageCursor
}

type MemberPage struct {
	Items []MemberSummary
	Next  *PageCursor
}

type DepartmentPage struct {
	Items []DepartmentSummary
	Next  *PageCursor
}

type Repository interface {
	Create(context.Context, CreateTransaction) (OrganizationSummary, error)
	ListForActor(context.Context, uuid.UUID, Page) (OrganizationPage, error)
	GetForActor(context.Context, uuid.UUID, uuid.UUID) (OrganizationSummary, error)
	ListMembers(context.Context, uuid.UUID, uuid.UUID, Page) (MemberPage, error)
	ListDepartments(context.Context, uuid.UUID, uuid.UUID, Page) (DepartmentPage, error)
	CurrentPolicy(context.Context, uuid.UUID, uuid.UUID, bool) (PolicySnapshot, error)
}

type PolicySigner interface {
	SignPolicy(PolicySignatureInput) (PolicyAttestation, error)
}

type PostgresRepository struct {
	postgres *pgxpool.Pool
	signer   PolicySigner
}

func NewPostgresRepository(postgres *pgxpool.Pool, signer PolicySigner) *PostgresRepository {
	return &PostgresRepository{postgres: postgres, signer: signer}
}

func (r *PostgresRepository) Create(ctx context.Context, command CreateTransaction) (OrganizationSummary, error) {
	if r == nil || r.postgres == nil || r.signer == nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	displayName, err := NormalizeOrganizationName(command.DisplayName)
	if err != nil || !validCreateTransaction(command) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	expectedRequestDigest := canonicalCreateRequestDigest(displayName)
	if subtle.ConstantTimeCompare(command.Idempotency.RequestDigest[:], expectedRequestDigest[:]) != 1 {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	canonical, err := CanonicalizePolicy(DefaultPolicyDocument())
	if err != nil {
		return OrganizationSummary{}, err
	}

	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, command.Actor); err != nil {
		return OrganizationSummary{}, err
	}
	if err := lockOrganizationCreationQuota(ctx, tx, command.Actor.UserID); err != nil {
		return OrganizationSummary{}, err
	}
	if err := lockOrganizationIdempotency(ctx, tx, command.Actor.UserID, command.Idempotency.KeyDigest); err != nil {
		return OrganizationSummary{}, err
	}

	replayID, found, err := readOrganizationCreateIdempotency(ctx, tx, command.Actor.UserID, command.Idempotency)
	if err != nil {
		return OrganizationSummary{}, err
	}
	if found {
		summary, err := loadOrganizationSummary(ctx, tx, command.Actor.UserID, replayID)
		if err != nil {
			return OrganizationSummary{}, err
		}
		if err := commitOrganizationTransaction(ctx, tx); err != nil {
			return OrganizationSummary{}, err
		}
		return summary, nil
	}

	var owned int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM organization_memberships membership
		JOIN organizations organization ON organization.id = membership.organization_id
		WHERE membership.user_id = $1 AND membership.role = 'owner'
		  AND organization.status IN ('active', 'archived')
	`, command.Actor.UserID).Scan(&owned); err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	if owned >= command.OwnedLimit {
		return OrganizationSummary{}, ErrOrganizationLimitReached
	}

	createdAt := command.CreatedAt.UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (
			id, display_name, status, revision, current_policy_snapshot_id, created_at, updated_at
		) VALUES ($1, $2, 'active', 1, $3, $4, $4)
	`, command.OrganizationID, displayName, command.PolicySnapshotID, createdAt); err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_memberships (
			organization_id, user_id, role, revision, joined_at, updated_at
		) VALUES ($1, $2, 'owner', 1, $3, $3)
	`, command.OrganizationID, command.Actor.UserID, createdAt); err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}

	attestation, err := r.signer.SignPolicy(PolicySignatureInput{
		OrganizationID: command.OrganizationID,
		SnapshotID:     command.PolicySnapshotID,
		PolicyVersion:  1,
		ContentDigest:  canonical.ContentDigest,
	})
	if err != nil || !validStoredAttestation(command, canonical.ContentDigest, attestation) {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document, content_digest,
			issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES ($1, $2, 1, 1, $3::jsonb, $4, $5, $6, $7, $8, $9)
	`, command.PolicySnapshotID, command.OrganizationID, string(canonical.CanonicalJSON), canonical.ContentDigest[:],
		attestation.Issuer, attestation.KeyID, attestation.Signature, command.Actor.UserID, createdAt); err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_idempotency_records (
			actor_user_id, organization_id, operation, key_digest, request_digest,
			resource_type, resource_id, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'organization', $2, $6, $7)
	`, command.Actor.UserID, command.OrganizationID, operationOrganizationCreate,
		command.Idempotency.KeyDigest[:], command.Idempotency.RequestDigest[:], createdAt,
		command.Idempotency.ExpiresAt.UTC()); err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	if err := recordOrganizationCreateAudit(ctx, tx, command, canonical.ContentDigest); err != nil {
		return OrganizationSummary{}, err
	}

	summary, err := loadOrganizationSummary(ctx, tx, command.Actor.UserID, command.OrganizationID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	if err := commitOrganizationTransaction(ctx, tx); err != nil {
		return OrganizationSummary{}, err
	}
	return summary, nil
}

func (r *PostgresRepository) ListForActor(
	ctx context.Context,
	actorUserID uuid.UUID,
	page Page,
) (OrganizationPage, error) {
	if r == nil || r.postgres == nil {
		return OrganizationPage{}, ErrServiceUnavailable
	}
	if actorUserID == uuid.Nil || !validPage(page, false) {
		return OrganizationPage{}, ErrInvalidRequest
	}
	var after any
	if page.After != nil {
		after = page.After.ID
	}
	rows, err := r.postgres.Query(ctx, organizationListQuery, actorUserID, after, page.Limit+1)
	if err != nil {
		return OrganizationPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]OrganizationSummary, 0, page.Limit+1)
	for rows.Next() {
		item, scanErr := scanOrganizationSummary(rows)
		if scanErr != nil {
			return OrganizationPage{}, scanErr
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		return OrganizationPage{}, ErrServiceUnavailable
	}
	result := OrganizationPage{Items: items}
	if len(items) > page.Limit {
		result.Items = items[:page.Limit]
		result.Next = &PageCursor{ID: result.Items[len(result.Items)-1].ID}
	}
	return result, nil
}

func (r *PostgresRepository) GetForActor(
	ctx context.Context,
	actorUserID uuid.UUID,
	organizationID uuid.UUID,
) (OrganizationSummary, error) {
	if r == nil || r.postgres == nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	if actorUserID == uuid.Nil || organizationID == uuid.Nil {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	return loadOrganizationSummary(ctx, r.postgres, actorUserID, organizationID)
}

func (r *PostgresRepository) ListMembers(
	ctx context.Context,
	actorUserID uuid.UUID,
	organizationID uuid.UUID,
	page Page,
) (MemberPage, error) {
	if r == nil || r.postgres == nil {
		return MemberPage{}, ErrServiceUnavailable
	}
	if actorUserID == uuid.Nil || organizationID == uuid.Nil || !validPage(page, false) {
		return MemberPage{}, ErrInvalidRequest
	}
	if _, err := requireOrganizationMembership(ctx, r.postgres, actorUserID, organizationID); err != nil {
		return MemberPage{}, err
	}
	var after any
	if page.After != nil {
		after = page.After.ID
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT membership.user_id, users.nickname, membership.role, membership.department_id,
		       membership.revision, membership.joined_at, membership.updated_at
		FROM organization_memberships membership
		JOIN users ON users.id = membership.user_id
		WHERE membership.organization_id = $1
		  AND ($2::uuid IS NULL OR membership.user_id > $2)
		ORDER BY membership.user_id
		LIMIT $3
	`, organizationID, after, page.Limit+1)
	if err != nil {
		return MemberPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]MemberSummary, 0, page.Limit+1)
	for rows.Next() {
		var item MemberSummary
		var role string
		var department pgtype.UUID
		if err := rows.Scan(
			&item.UserID, &item.Nickname, &role, &department, &item.Revision, &item.JoinedAt, &item.UpdatedAt,
		); err != nil {
			return MemberPage{}, ErrServiceUnavailable
		}
		parsedRole, err := ParseRole(role)
		if err != nil || item.UserID == uuid.Nil || item.Revision <= 0 {
			return MemberPage{}, ErrServiceUnavailable
		}
		item.Role = parsedRole
		if department.Valid {
			value := uuid.UUID(department.Bytes)
			item.DepartmentID = &value
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		return MemberPage{}, ErrServiceUnavailable
	}
	result := MemberPage{Items: items}
	if len(items) > page.Limit {
		result.Items = items[:page.Limit]
		result.Next = &PageCursor{ID: result.Items[len(result.Items)-1].UserID}
	}
	return result, nil
}

func (r *PostgresRepository) ListDepartments(
	ctx context.Context,
	actorUserID uuid.UUID,
	organizationID uuid.UUID,
	page Page,
) (DepartmentPage, error) {
	if r == nil || r.postgres == nil {
		return DepartmentPage{}, ErrServiceUnavailable
	}
	if actorUserID == uuid.Nil || organizationID == uuid.Nil || !validPage(page, true) {
		return DepartmentPage{}, ErrInvalidRequest
	}
	if _, err := requireOrganizationMembership(ctx, r.postgres, actorUserID, organizationID); err != nil {
		return DepartmentPage{}, err
	}
	var afterName any
	var afterID any
	if page.After != nil {
		afterName = page.After.SortKey
		afterID = page.After.ID
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT department.id, department.display_name, department.status,
		       (SELECT count(*) FROM organization_memberships membership
		        WHERE membership.organization_id = department.organization_id
		          AND membership.department_id = department.id),
		       department.revision, department.created_at, department.updated_at, department.archived_at
		FROM organization_departments department
		WHERE department.organization_id = $1
		  AND ($2::text IS NULL OR (department.display_name, department.id) > ($2, $3::uuid))
		ORDER BY department.display_name, department.id
		LIMIT $4
	`, organizationID, afterName, afterID, page.Limit+1)
	if err != nil {
		return DepartmentPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]DepartmentSummary, 0, page.Limit+1)
	for rows.Next() {
		var item DepartmentSummary
		var status string
		var memberCount int64
		if err := rows.Scan(
			&item.ID, &item.DisplayName, &status, &memberCount, &item.Revision,
			&item.CreatedAt, &item.UpdatedAt, &item.ArchivedAt,
		); err != nil {
			return DepartmentPage{}, ErrServiceUnavailable
		}
		parsedStatus, err := ParseDepartmentStatus(status)
		if err != nil || item.ID == uuid.Nil || item.Revision <= 0 || memberCount < 0 {
			return DepartmentPage{}, ErrServiceUnavailable
		}
		item.Status = parsedStatus
		item.MemberCount = int(memberCount)
		items = append(items, item)
	}
	if rows.Err() != nil {
		return DepartmentPage{}, ErrServiceUnavailable
	}
	result := DepartmentPage{Items: items}
	if len(items) > page.Limit {
		result.Items = items[:page.Limit]
		last := result.Items[len(result.Items)-1]
		result.Next = &PageCursor{SortKey: last.DisplayName, ID: last.ID}
	}
	return result, nil
}

func (r *PostgresRepository) CurrentPolicy(
	ctx context.Context,
	actorUserID uuid.UUID,
	organizationID uuid.UUID,
	includeFull bool,
) (PolicySnapshot, error) {
	if r == nil || r.postgres == nil {
		return PolicySnapshot{}, ErrServiceUnavailable
	}
	if actorUserID == uuid.Nil || organizationID == uuid.Nil {
		return PolicySnapshot{}, ErrInvalidRequest
	}
	role, err := requireOrganizationMembership(ctx, r.postgres, actorUserID, organizationID)
	if err != nil {
		return PolicySnapshot{}, err
	}
	var snapshot PolicySnapshot
	var document []byte
	var digest []byte
	if err := r.postgres.QueryRow(ctx, `
		SELECT policy.id, policy.policy_version, policy.schema_version, policy.content_digest,
		       policy.issuer, policy.signing_key_id, policy.created_at,
		       policy.policy_document::text, policy.signature
		FROM organizations organization
		JOIN organization_policy_snapshots policy
		  ON policy.organization_id = organization.id AND policy.id = organization.current_policy_snapshot_id
		WHERE organization.id = $1 AND organization.status IN ('active', 'archived')
	`, organizationID).Scan(
		&snapshot.ID, &snapshot.PolicyVersion, &snapshot.SchemaVersion, &digest,
		&snapshot.Issuer, &snapshot.SigningKeyID, &snapshot.CreatedAt, &document, &snapshot.Signature,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PolicySnapshot{}, ErrOrganizationNotFound
		}
		return PolicySnapshot{}, ErrServiceUnavailable
	}
	if !copyDigest(&snapshot.ContentDigest, digest) || snapshot.ID == uuid.Nil || snapshot.PolicyVersion <= 0 ||
		snapshot.SchemaVersion != 1 || strings.TrimSpace(snapshot.Issuer) == "" || strings.TrimSpace(snapshot.SigningKeyID) == "" {
		return PolicySnapshot{}, ErrServiceUnavailable
	}
	canReadFull := role == RoleOwner || role == RoleAdmin || role == RoleAuditor
	if !includeFull || !canReadFull {
		snapshot.Signature = nil
		return snapshot, nil
	}
	decoded, err := DecodePolicyDocument(document)
	if err != nil {
		return PolicySnapshot{}, ErrServiceUnavailable
	}
	canonical, err := CanonicalizePolicy(decoded)
	if err != nil || canonical.ContentDigest != snapshot.ContentDigest || len(snapshot.Signature) != ed25519.SignatureSize {
		return PolicySnapshot{}, ErrServiceUnavailable
	}
	snapshot.Document = canonical.Document
	snapshot.Signature = append([]byte(nil), snapshot.Signature...)
	return snapshot, nil
}

const organizationListQuery = `
	SELECT organization.id, organization.display_name, organization.status, organization.revision,
	       membership.role,
	       (SELECT count(*) FROM organization_memberships count_membership
	        WHERE count_membership.organization_id = organization.id),
	       (SELECT count(*) FROM organization_departments department
	        WHERE department.organization_id = organization.id AND department.status = 'active'),
	       policy.policy_version, policy.content_digest,
	       organization.created_at, organization.updated_at, organization.archived_at
	FROM organization_memberships membership
	JOIN organizations organization ON organization.id = membership.organization_id
	JOIN organization_policy_snapshots policy
	  ON policy.organization_id = organization.id AND policy.id = organization.current_policy_snapshot_id
	WHERE membership.user_id = $1 AND organization.status IN ('active', 'archived')
	  AND ($2::uuid IS NULL OR organization.id > $2)
	ORDER BY organization.id
	LIMIT $3
`

const organizationGetQuery = `
	SELECT organization.id, organization.display_name, organization.status, organization.revision,
	       membership.role,
	       (SELECT count(*) FROM organization_memberships count_membership
	        WHERE count_membership.organization_id = organization.id),
	       (SELECT count(*) FROM organization_departments department
	        WHERE department.organization_id = organization.id AND department.status = 'active'),
	       policy.policy_version, policy.content_digest,
	       organization.created_at, organization.updated_at, organization.archived_at
	FROM organization_memberships membership
	JOIN organizations organization ON organization.id = membership.organization_id
	JOIN organization_policy_snapshots policy
	  ON policy.organization_id = organization.id AND policy.id = organization.current_policy_snapshot_id
	WHERE membership.user_id = $1 AND organization.id = $2
	  AND organization.status IN ('active', 'archived')
`

type rowScanner interface {
	Scan(...any) error
}

func loadOrganizationSummary(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	actorUserID uuid.UUID,
	organizationID uuid.UUID,
) (OrganizationSummary, error) {
	summary, err := scanOrganizationSummary(queryer.QueryRow(ctx, organizationGetQuery, actorUserID, organizationID))
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrOrganizationNotFound) {
		return OrganizationSummary{}, ErrOrganizationNotFound
	}
	return summary, err
}

func scanOrganizationSummary(row rowScanner) (OrganizationSummary, error) {
	var summary OrganizationSummary
	var status string
	var role string
	var memberCount int64
	var departmentCount int64
	var digest []byte
	if err := row.Scan(
		&summary.ID, &summary.DisplayName, &status, &summary.Revision, &role,
		&memberCount, &departmentCount, &summary.CurrentPolicyVersion, &digest,
		&summary.CreatedAt, &summary.UpdatedAt, &summary.ArchivedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrganizationSummary{}, ErrOrganizationNotFound
		}
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	parsedStatus, statusErr := ParseOrganizationStatus(status)
	parsedRole, roleErr := ParseRole(role)
	if statusErr != nil || roleErr != nil || summary.ID == uuid.Nil || summary.Revision <= 0 ||
		memberCount < 1 || departmentCount < 0 || summary.CurrentPolicyVersion <= 0 ||
		!copyDigest(&summary.CurrentPolicyDigest, digest) {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	summary.Status = parsedStatus
	summary.Role = parsedRole
	summary.MemberCount = int(memberCount)
	summary.DepartmentCount = int(departmentCount)
	switch parsedStatus {
	case OrganizationStatusActive:
		summary.MutationState = MutationStateWritable
	case OrganizationStatusArchived:
		summary.MutationState = MutationStateArchived
	default:
		summary.MutationState = MutationStateDissolved
	}
	return summary, nil
}

func requireOrganizationMembership(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	actorUserID uuid.UUID,
	organizationID uuid.UUID,
) (Role, error) {
	var role string
	if err := queryer.QueryRow(ctx, `
		SELECT membership.role
		FROM organization_memberships membership
		JOIN organizations organization ON organization.id = membership.organization_id
		WHERE membership.user_id = $1 AND membership.organization_id = $2
		  AND organization.status IN ('active', 'archived')
	`, actorUserID, organizationID).Scan(&role); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrOrganizationNotFound
		}
		return "", ErrServiceUnavailable
	}
	parsed, err := ParseRole(role)
	if err != nil {
		return "", ErrServiceUnavailable
	}
	return parsed, nil
}

func validCreateTransaction(command CreateTransaction) bool {
	return command.Actor.Validate() == nil && command.OrganizationID != uuid.Nil && command.PolicySnapshotID != uuid.Nil &&
		command.OrganizationID != command.PolicySnapshotID && command.OwnedLimit > 0 && command.Audit.EventID != uuid.Nil &&
		!command.CreatedAt.IsZero() && !command.Idempotency.ExpiresAt.IsZero() &&
		command.Idempotency.ExpiresAt.UTC().Equal(command.CreatedAt.UTC().Add(24*time.Hour)) &&
		!zeroDigest32(command.Idempotency.KeyDigest) && !zeroDigest32(command.Idempotency.RequestDigest)
}

func validStoredAttestation(
	command CreateTransaction,
	digest [sha256.Size]byte,
	attestation PolicyAttestation,
) bool {
	return attestation.OrganizationID == command.OrganizationID && attestation.SnapshotID == command.PolicySnapshotID &&
		attestation.PolicyVersion == 1 && attestation.ContentDigest == digest &&
		strings.TrimSpace(attestation.Issuer) != "" && attestation.Issuer == strings.TrimSpace(attestation.Issuer) &&
		len(attestation.Issuer) <= 512 && strings.TrimSpace(attestation.KeyID) != "" &&
		attestation.KeyID == strings.TrimSpace(attestation.KeyID) && len(attestation.KeyID) <= 128 &&
		len(attestation.Signature) == ed25519.SignatureSize
}

func validPage(page Page, requireSortKey bool) bool {
	if page.Limit < 1 || page.Limit > 100 {
		return false
	}
	if page.After == nil {
		return true
	}
	if page.After.ID == uuid.Nil {
		return false
	}
	if requireSortKey {
		return page.After.SortKey != "" && len(page.After.SortKey) <= 256
	}
	return page.After.SortKey == ""
}

func lockActiveOrganizationActor(ctx context.Context, tx pgx.Tx, actor Actor) error {
	var userStatus string
	var deviceStatus string
	if err := tx.QueryRow(ctx, `
		SELECT users.status, devices.status
		FROM users
		JOIN devices ON devices.id = $2 AND devices.user_id = users.id
		WHERE users.id = $1
		FOR UPDATE OF users, devices
	`, actor.UserID, actor.DeviceID).Scan(&userStatus, &deviceStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionRevoked
		}
		return ErrServiceUnavailable
	}
	if userStatus != "active" || deviceStatus != "active" {
		return ErrSessionRevoked
	}
	return nil
}

func lockOrganizationCreationQuota(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended('organization-owned:' || $1::text, 0))
	`, actorUserID); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func lockOrganizationIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actorUserID uuid.UUID,
	keyDigest [sha256.Size]byte,
) error {
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended(
			'organization-idempotency:' || $1::text || ':' || encode($2::bytea, 'hex'), 0
		))
	`, actorUserID, keyDigest[:]); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func readOrganizationCreateIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actorUserID uuid.UUID,
	evidence IdempotencyEvidence,
) (uuid.UUID, bool, error) {
	var organizationID uuid.UUID
	var requestDigest []byte
	err := tx.QueryRow(ctx, `
		SELECT organization_id, request_digest
		FROM organization_idempotency_records
		WHERE actor_user_id = $1 AND operation = $2 AND key_digest = $3
	`, actorUserID, operationOrganizationCreate, evidence.KeyDigest[:]).Scan(&organizationID, &requestDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, ErrServiceUnavailable
	}
	if len(requestDigest) != sha256.Size || subtle.ConstantTimeCompare(requestDigest, evidence.RequestDigest[:]) != 1 {
		return uuid.Nil, false, ErrIdempotencyConflict
	}
	return organizationID, true, nil
}

func recordOrganizationCreateAudit(
	ctx context.Context,
	tx pgx.Tx,
	command CreateTransaction,
	digest [sha256.Size]byte,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	organizationID := command.OrganizationID
	actorUserID := command.Actor.UserID
	deviceID := command.Actor.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID: command.Audit.EventID, EventType: "organization_created",
		ActorUserID: &actorUserID, DeviceID: &deviceID, OrganizationID: &organizationID,
		ObjectType: "organization", ObjectID: &organizationID, Outcome: audit.OutcomeSuccess,
		RequestID: command.Audit.RequestID, OccurredAt: command.CreatedAt.UTC(),
		Metadata: map[string]string{
			"organization_id":    organizationID.String(),
			"policy_snapshot_id": command.PolicySnapshotID.String(),
			"policy_version":     "1",
			"content_digest":     hex.EncodeToString(digest[:]),
		},
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func commitOrganizationTransaction(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func rollbackOrganizationTransaction(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}

func copyDigest(destination *[sha256.Size]byte, source []byte) bool {
	if len(source) != sha256.Size {
		return false
	}
	copy(destination[:], source)
	return true
}

func zeroDigest32(value [sha256.Size]byte) bool {
	return bytes.Equal(value[:], make([]byte, sha256.Size))
}

func CanonicalCreateRequestDigest(displayName string) ([sha256.Size]byte, error) {
	normalized, err := NormalizeOrganizationName(displayName)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return canonicalCreateRequestDigest(normalized), nil
}

func canonicalCreateRequestDigest(normalizedDisplayName string) [sha256.Size]byte {
	return sha256.Sum256([]byte("agentera.organization-create.v1\x00" + normalizedDisplayName))
}

type lockedOrganization struct {
	Status            OrganizationStatus
	Revision          int64
	UpdatedAt         time.Time
	ActorRole         Role
	ActorRevision     int64
	ActorMembershipAt time.Time
}

func (r *PostgresRepository) rename(
	ctx context.Context,
	actor Actor,
	command renameTransaction,
) (OrganizationSummary, error) {
	displayName, err := NormalizeOrganizationName(command.DisplayName)
	if r == nil || r.postgres == nil || actor.Validate() != nil || err != nil || command.OrganizationID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validMutationEvidence(command.mutationEvidence) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return OrganizationSummary{}, err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	if err := requireActiveOrganizationMutation(organization, true); err != nil {
		return OrganizationSummary{}, err
	}
	if organization.Revision != command.ExpectedRevision {
		return OrganizationSummary{}, ErrOrganizationConflict
	}
	changedAt := command.ChangedAt.UTC()
	if changedAt.Before(organization.UpdatedAt) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	tag, err := tx.Exec(ctx, `
		UPDATE organizations
		SET display_name = $2, revision = revision + 1, updated_at = $3
		WHERE id = $1 AND revision = $4 AND status = 'active'
	`, command.OrganizationID, displayName, changedAt, command.ExpectedRevision)
	if err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	if tag.RowsAffected() != 1 {
		return OrganizationSummary{}, ErrOrganizationConflict
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, "organization_renamed",
		command.OrganizationID, "organization", command.OrganizationID, changedAt, map[string]string{
			"previous_revision": strconv.FormatInt(command.ExpectedRevision, 10),
			"revision":          strconv.FormatInt(command.ExpectedRevision+1, 10),
		}); err != nil {
		return OrganizationSummary{}, err
	}
	result, err := loadOrganizationSummary(ctx, tx, actor.UserID, command.OrganizationID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	if err := commitOrganizationTransaction(ctx, tx); err != nil {
		return OrganizationSummary{}, err
	}
	return result, nil
}

func (r *PostgresRepository) patchMember(
	ctx context.Context,
	actor Actor,
	command patchMemberTransaction,
) (MemberSummary, error) {
	if r == nil || r.postgres == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil ||
		command.UserID == uuid.Nil || command.ExpectedRevision <= 0 ||
		!validMutationEvidence(command.mutationEvidence) || !validPatchMemberTransaction(command) {
		return MemberSummary{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return MemberSummary{}, ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return MemberSummary{}, err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return MemberSummary{}, err
	}
	if err := requireActiveOrganizationMutation(organization, true); err != nil {
		return MemberSummary{}, err
	}
	target, err := loadOrganizationMember(ctx, tx, command.OrganizationID, command.UserID, true)
	if err != nil {
		return MemberSummary{}, err
	}
	if target.Revision != command.ExpectedRevision {
		return MemberSummary{}, ErrMembershipConflict
	}
	if err := authorizeMemberPatch(organization.ActorRole, target.Role, command.Role); err != nil {
		return MemberSummary{}, err
	}
	newRole := target.Role
	if command.Role != nil {
		newRole = *command.Role
	}
	newDepartmentID := cloneUUIDPointer(target.DepartmentID)
	if command.ChangeDepartment {
		if command.ClearDepartment {
			newDepartmentID = nil
		} else {
			if err := requireActiveDepartment(ctx, tx, command.OrganizationID, *command.DepartmentID); err != nil {
				return MemberSummary{}, err
			}
			value := *command.DepartmentID
			newDepartmentID = &value
		}
	}
	if newRole == target.Role && equalUUIDPointers(newDepartmentID, target.DepartmentID) {
		return MemberSummary{}, ErrMembershipConflict
	}
	changedAt := command.ChangedAt.UTC()
	if changedAt.Before(target.UpdatedAt) {
		return MemberSummary{}, ErrInvalidRequest
	}
	tag, err := tx.Exec(ctx, `
		UPDATE organization_memberships
		SET role = $3, department_id = $4, revision = revision + 1, updated_at = $5
		WHERE organization_id = $1 AND user_id = $2 AND revision = $6
	`, command.OrganizationID, command.UserID, newRole, newDepartmentID, changedAt, command.ExpectedRevision)
	if err != nil {
		return MemberSummary{}, ErrServiceUnavailable
	}
	if tag.RowsAffected() != 1 {
		return MemberSummary{}, ErrMembershipConflict
	}
	metadata := map[string]string{
		"membership_user_id": command.UserID.String(),
		"previous_role":      string(target.Role),
		"role":               string(newRole),
		"previous_revision":  strconv.FormatInt(command.ExpectedRevision, 10),
		"revision":           strconv.FormatInt(command.ExpectedRevision+1, 10),
	}
	if newDepartmentID != nil {
		metadata["department_id"] = newDepartmentID.String()
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, "organization_member_patched",
		command.OrganizationID, "organization_membership", command.UserID, changedAt, metadata); err != nil {
		return MemberSummary{}, err
	}
	result, err := loadOrganizationMember(ctx, tx, command.OrganizationID, command.UserID, false)
	if err != nil {
		return MemberSummary{}, err
	}
	if err := commitOrganizationTransaction(ctx, tx); err != nil {
		return MemberSummary{}, err
	}
	return result, nil
}

func (r *PostgresRepository) removeMember(ctx context.Context, actor Actor, command removeMemberTransaction) error {
	if r == nil || r.postgres == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil ||
		command.UserID == uuid.Nil || command.ExpectedRevision <= 0 || !validMutationEvidence(command.mutationEvidence) {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return err
	}
	if err := requireActiveOrganizationMutation(organization, true); err != nil {
		return err
	}
	target, err := loadOrganizationMember(ctx, tx, command.OrganizationID, command.UserID, true)
	if err != nil {
		return err
	}
	if target.Revision != command.ExpectedRevision {
		return ErrMembershipConflict
	}
	if target.Role == RoleOwner || (organization.ActorRole == RoleAdmin && target.Role == RoleAdmin) {
		return ErrOrganizationForbidden
	}
	changedAt := command.ChangedAt.UTC()
	tag, err := tx.Exec(ctx, `
		DELETE FROM organization_memberships
		WHERE organization_id = $1 AND user_id = $2 AND revision = $3
	`, command.OrganizationID, command.UserID, command.ExpectedRevision)
	if err != nil {
		return ErrServiceUnavailable
	}
	if tag.RowsAffected() != 1 {
		return ErrMembershipConflict
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, "organization_member_removed",
		command.OrganizationID, "organization_membership", command.UserID, changedAt, map[string]string{
			"membership_user_id": command.UserID.String(), "role": string(target.Role),
			"previous_revision": strconv.FormatInt(command.ExpectedRevision, 10),
		}); err != nil {
		return err
	}
	return commitOrganizationTransaction(ctx, tx)
}

func (r *PostgresRepository) leave(ctx context.Context, actor Actor, command leaveTransaction) error {
	if r == nil || r.postgres == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil ||
		!validMutationEvidence(command.mutationEvidence) {
		return ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return err
	}
	if organization.Status == OrganizationStatusArchived {
		return ErrOrganizationArchived
	}
	if organization.Status != OrganizationStatusActive {
		return ErrOrganizationNotFound
	}
	if organization.ActorRole == RoleOwner {
		return ErrOrganizationForbidden
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM organization_memberships
		WHERE organization_id = $1 AND user_id = $2 AND revision = $3
	`, command.OrganizationID, actor.UserID, organization.ActorRevision)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrServiceUnavailable
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, "organization_member_left",
		command.OrganizationID, "organization_membership", actor.UserID, command.ChangedAt.UTC(), map[string]string{
			"membership_user_id": actor.UserID.String(), "role": string(organization.ActorRole),
			"previous_revision": strconv.FormatInt(organization.ActorRevision, 10),
		}); err != nil {
		return err
	}
	return commitOrganizationTransaction(ctx, tx)
}

func (r *PostgresRepository) createDepartment(
	ctx context.Context,
	actor Actor,
	command createDepartmentTransaction,
) (DepartmentSummary, error) {
	displayName, nameKey, err := NormalizeDepartmentName(command.DisplayName)
	if r == nil || r.postgres == nil || actor.Validate() != nil || err != nil || displayName != command.DisplayName ||
		nameKey != command.NameKey || command.OrganizationID == uuid.Nil || command.DepartmentID == uuid.Nil ||
		command.ActiveLimit <= 0 || !validMutationEvidence(command.mutationEvidence) {
		return DepartmentSummary{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DepartmentSummary{}, ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return DepartmentSummary{}, err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if err := requireActiveOrganizationMutation(organization, true); err != nil {
		return DepartmentSummary{}, err
	}
	if err := enforceDepartmentCapacity(ctx, tx, command.OrganizationID, command.ActiveLimit); err != nil {
		return DepartmentSummary{}, err
	}
	if duplicate, err := activeDepartmentNameExists(ctx, tx, command.OrganizationID, command.NameKey, uuid.Nil); err != nil {
		return DepartmentSummary{}, err
	} else if duplicate {
		return DepartmentSummary{}, ErrOrganizationConflict
	}
	changedAt := command.ChangedAt.UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_departments (
			organization_id, id, display_name, name_key, status, revision, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'active', 1, $5, $5)
	`, command.OrganizationID, command.DepartmentID, command.DisplayName, command.NameKey, changedAt); err != nil {
		if postgresUniqueViolation(err) {
			return DepartmentSummary{}, ErrOrganizationConflict
		}
		return DepartmentSummary{}, ErrServiceUnavailable
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, "organization_department_created",
		command.OrganizationID, "organization_department", command.DepartmentID, changedAt, map[string]string{
			"department_id": command.DepartmentID.String(), "revision": "1",
		}); err != nil {
		return DepartmentSummary{}, err
	}
	result, err := loadOrganizationDepartment(ctx, tx, command.OrganizationID, command.DepartmentID, false)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if err := commitOrganizationTransaction(ctx, tx); err != nil {
		return DepartmentSummary{}, err
	}
	return result, nil
}

func (r *PostgresRepository) renameDepartment(
	ctx context.Context,
	actor Actor,
	command renameDepartmentTransaction,
) (DepartmentSummary, error) {
	displayName, nameKey, err := NormalizeDepartmentName(command.DisplayName)
	if r == nil || r.postgres == nil || actor.Validate() != nil || err != nil || displayName != command.DisplayName ||
		nameKey != command.NameKey || command.OrganizationID == uuid.Nil || command.DepartmentID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validMutationEvidence(command.mutationEvidence) {
		return DepartmentSummary{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DepartmentSummary{}, ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return DepartmentSummary{}, err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if err := requireActiveOrganizationMutation(organization, true); err != nil {
		return DepartmentSummary{}, err
	}
	department, err := loadOrganizationDepartment(ctx, tx, command.OrganizationID, command.DepartmentID, true)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if department.Status != DepartmentStatusActive || department.Revision != command.ExpectedRevision {
		return DepartmentSummary{}, ErrOrganizationConflict
	}
	if department.DisplayName == command.DisplayName {
		return DepartmentSummary{}, ErrOrganizationConflict
	}
	if duplicate, err := activeDepartmentNameExists(ctx, tx, command.OrganizationID, command.NameKey, command.DepartmentID); err != nil {
		return DepartmentSummary{}, err
	} else if duplicate {
		return DepartmentSummary{}, ErrOrganizationConflict
	}
	changedAt := command.ChangedAt.UTC()
	tag, err := tx.Exec(ctx, `
		UPDATE organization_departments
		SET display_name = $3, name_key = $4, revision = revision + 1, updated_at = $5
		WHERE organization_id = $1 AND id = $2 AND revision = $6 AND status = 'active'
	`, command.OrganizationID, command.DepartmentID, command.DisplayName, command.NameKey, changedAt, command.ExpectedRevision)
	if err != nil {
		if postgresUniqueViolation(err) {
			return DepartmentSummary{}, ErrOrganizationConflict
		}
		return DepartmentSummary{}, ErrServiceUnavailable
	}
	if tag.RowsAffected() != 1 {
		return DepartmentSummary{}, ErrOrganizationConflict
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, "organization_department_renamed",
		command.OrganizationID, "organization_department", command.DepartmentID, changedAt, map[string]string{
			"department_id":     command.DepartmentID.String(),
			"previous_revision": strconv.FormatInt(command.ExpectedRevision, 10),
			"revision":          strconv.FormatInt(command.ExpectedRevision+1, 10),
		}); err != nil {
		return DepartmentSummary{}, err
	}
	result, err := loadOrganizationDepartment(ctx, tx, command.OrganizationID, command.DepartmentID, false)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if err := commitOrganizationTransaction(ctx, tx); err != nil {
		return DepartmentSummary{}, err
	}
	return result, nil
}

func (r *PostgresRepository) archiveDepartment(
	ctx context.Context,
	actor Actor,
	command departmentLifecycleTransaction,
) (DepartmentSummary, error) {
	return r.changeDepartmentLifecycle(ctx, actor, command, false)
}

func (r *PostgresRepository) restoreDepartment(
	ctx context.Context,
	actor Actor,
	command departmentLifecycleTransaction,
) (DepartmentSummary, error) {
	return r.changeDepartmentLifecycle(ctx, actor, command, true)
}

func (r *PostgresRepository) changeDepartmentLifecycle(
	ctx context.Context,
	actor Actor,
	command departmentLifecycleTransaction,
	restore bool,
) (DepartmentSummary, error) {
	if r == nil || r.postgres == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil ||
		command.DepartmentID == uuid.Nil || command.ExpectedRevision <= 0 || command.ActiveLimit <= 0 ||
		!validMutationEvidence(command.mutationEvidence) {
		return DepartmentSummary{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DepartmentSummary{}, ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return DepartmentSummary{}, err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if err := requireActiveOrganizationMutation(organization, true); err != nil {
		return DepartmentSummary{}, err
	}
	department, err := loadOrganizationDepartment(ctx, tx, command.OrganizationID, command.DepartmentID, true)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if department.Revision != command.ExpectedRevision {
		return DepartmentSummary{}, ErrOrganizationConflict
	}
	changedAt := command.ChangedAt.UTC()
	if restore {
		if department.Status != DepartmentStatusArchived {
			return DepartmentSummary{}, ErrOrganizationConflict
		}
		if err := enforceDepartmentCapacity(ctx, tx, command.OrganizationID, command.ActiveLimit); err != nil {
			return DepartmentSummary{}, err
		}
		_, nameKey, err := NormalizeDepartmentName(department.DisplayName)
		if err != nil {
			return DepartmentSummary{}, ErrServiceUnavailable
		}
		if duplicate, err := activeDepartmentNameExists(ctx, tx, command.OrganizationID, nameKey, command.DepartmentID); err != nil {
			return DepartmentSummary{}, err
		} else if duplicate {
			return DepartmentSummary{}, ErrOrganizationConflict
		}
		tag, err := tx.Exec(ctx, `
			UPDATE organization_departments
			SET status = 'active', revision = revision + 1, updated_at = $3, archived_at = NULL
			WHERE organization_id = $1 AND id = $2 AND revision = $4 AND status = 'archived'
		`, command.OrganizationID, command.DepartmentID, changedAt, command.ExpectedRevision)
		if err != nil {
			if postgresUniqueViolation(err) {
				return DepartmentSummary{}, ErrOrganizationConflict
			}
			return DepartmentSummary{}, ErrServiceUnavailable
		}
		if tag.RowsAffected() != 1 {
			return DepartmentSummary{}, ErrOrganizationConflict
		}
	} else {
		if department.Status != DepartmentStatusActive {
			return DepartmentSummary{}, ErrOrganizationConflict
		}
		var assigned int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM organization_memberships
			WHERE organization_id = $1 AND department_id = $2
		`, command.OrganizationID, command.DepartmentID).Scan(&assigned); err != nil {
			return DepartmentSummary{}, ErrServiceUnavailable
		}
		if assigned != 0 {
			return DepartmentSummary{}, ErrDepartmentNotEmpty
		}
		tag, err := tx.Exec(ctx, `
			UPDATE organization_departments
			SET status = 'archived', revision = revision + 1, updated_at = $3, archived_at = $3
			WHERE organization_id = $1 AND id = $2 AND revision = $4 AND status = 'active'
		`, command.OrganizationID, command.DepartmentID, changedAt, command.ExpectedRevision)
		if err != nil {
			return DepartmentSummary{}, ErrServiceUnavailable
		}
		if tag.RowsAffected() != 1 {
			return DepartmentSummary{}, ErrOrganizationConflict
		}
	}
	eventType := "organization_department_archived"
	status := DepartmentStatusArchived
	if restore {
		eventType = "organization_department_restored"
		status = DepartmentStatusActive
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, eventType,
		command.OrganizationID, "organization_department", command.DepartmentID, changedAt, map[string]string{
			"department_id":     command.DepartmentID.String(),
			"previous_revision": strconv.FormatInt(command.ExpectedRevision, 10),
			"revision":          strconv.FormatInt(command.ExpectedRevision+1, 10),
			"status":            string(status),
		}); err != nil {
		return DepartmentSummary{}, err
	}
	result, err := loadOrganizationDepartment(ctx, tx, command.OrganizationID, command.DepartmentID, false)
	if err != nil {
		return DepartmentSummary{}, err
	}
	if err := commitOrganizationTransaction(ctx, tx); err != nil {
		return DepartmentSummary{}, err
	}
	return result, nil
}

func (r *PostgresRepository) transferOwner(
	ctx context.Context,
	actor Actor,
	command ownerTransferTransaction,
) (OrganizationSummary, error) {
	if r == nil || r.postgres == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil ||
		command.TargetUserID == uuid.Nil || command.TargetUserID == actor.UserID ||
		command.ExpectedOrganizationRevision <= 0 || command.ExpectedOwnerRevision <= 0 ||
		command.ExpectedTargetRevision <= 0 || !validMutationEvidence(command.mutationEvidence) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationSummary{}, ErrServiceUnavailable
	}
	defer rollbackOrganizationTransaction(tx)
	if err := lockActiveOrganizationActor(ctx, tx, actor); err != nil {
		return OrganizationSummary{}, err
	}
	organization, err := loadLockedOrganization(ctx, tx, actor, command.OrganizationID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	if organization.ActorRole != RoleOwner {
		return OrganizationSummary{}, ErrOrganizationForbidden
	}
	if organization.Revision != command.ExpectedOrganizationRevision ||
		organization.ActorRevision != command.ExpectedOwnerRevision {
		return OrganizationSummary{}, ErrOrganizationConflict
	}
	target, err := loadOrganizationMember(ctx, tx, command.OrganizationID, command.TargetUserID, true)
	if err != nil {
		if errors.Is(err, ErrOrganizationNotFound) {
			return OrganizationSummary{}, ErrOwnerTransferTargetInvalid
		}
		return OrganizationSummary{}, err
	}
	if target.Role != RoleAdmin {
		return OrganizationSummary{}, ErrOwnerTransferTargetInvalid
	}
	if target.Revision != command.ExpectedTargetRevision {
		return OrganizationSummary{}, ErrOrganizationConflict
	}
	changedAt := command.ChangedAt.UTC()
	if changedAt.Before(organization.UpdatedAt) || changedAt.Before(organization.ActorMembershipAt) ||
		changedAt.Before(target.UpdatedAt) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	demoted, err := tx.Exec(ctx, `
		UPDATE organization_memberships
		SET role = 'admin', revision = revision + 1, updated_at = $3
		WHERE organization_id = $1 AND user_id = $2 AND role = 'owner' AND revision = $4
	`, command.OrganizationID, actor.UserID, changedAt, command.ExpectedOwnerRevision)
	if err != nil || demoted.RowsAffected() != 1 {
		return OrganizationSummary{}, ErrOrganizationConflict
	}
	promoted, err := tx.Exec(ctx, `
		UPDATE organization_memberships
		SET role = 'owner', revision = revision + 1, updated_at = $3
		WHERE organization_id = $1 AND user_id = $2 AND role = 'admin' AND revision = $4
	`, command.OrganizationID, command.TargetUserID, changedAt, command.ExpectedTargetRevision)
	if err != nil || promoted.RowsAffected() != 1 {
		return OrganizationSummary{}, ErrOrganizationConflict
	}
	updated, err := tx.Exec(ctx, `
		UPDATE organizations
		SET revision = revision + 1, updated_at = $2
		WHERE id = $1 AND revision = $3 AND status IN ('active', 'archived')
	`, command.OrganizationID, changedAt, command.ExpectedOrganizationRevision)
	if err != nil || updated.RowsAffected() != 1 {
		return OrganizationSummary{}, ErrOrganizationConflict
	}
	if err := recordOrganizationAudit(ctx, tx, actor, command.Audit, "organization_owner_transferred",
		command.OrganizationID, "organization_membership", command.TargetUserID, changedAt, map[string]string{
			"membership_user_id": command.TargetUserID.String(), "previous_role": string(RoleAdmin), "role": string(RoleOwner),
			"previous_revision": strconv.FormatInt(command.ExpectedOrganizationRevision, 10),
			"revision":          strconv.FormatInt(command.ExpectedOrganizationRevision+1, 10),
		}); err != nil {
		return OrganizationSummary{}, err
	}
	result, err := loadOrganizationSummary(ctx, tx, actor.UserID, command.OrganizationID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	if err := commitOrganizationTransaction(ctx, tx); err != nil {
		return OrganizationSummary{}, err
	}
	return result, nil
}

func loadLockedOrganization(ctx context.Context, tx pgx.Tx, actor Actor, organizationID uuid.UUID) (lockedOrganization, error) {
	var result lockedOrganization
	var status string
	var role string
	if err := tx.QueryRow(ctx, `
		SELECT organization.status, organization.revision, organization.updated_at,
		       membership.role, membership.revision, membership.updated_at
		FROM organizations organization
		JOIN organization_memberships membership
		  ON membership.organization_id = organization.id AND membership.user_id = $2
		WHERE organization.id = $1 AND organization.status IN ('active', 'archived')
		FOR UPDATE OF organization, membership
	`, organizationID, actor.UserID).Scan(
		&status, &result.Revision, &result.UpdatedAt, &role, &result.ActorRevision, &result.ActorMembershipAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return lockedOrganization{}, ErrOrganizationNotFound
		}
		return lockedOrganization{}, ErrServiceUnavailable
	}
	parsedStatus, statusErr := ParseOrganizationStatus(status)
	parsedRole, roleErr := ParseRole(role)
	if statusErr != nil || roleErr != nil || result.Revision <= 0 || result.ActorRevision <= 0 {
		return lockedOrganization{}, ErrServiceUnavailable
	}
	result.Status = parsedStatus
	result.ActorRole = parsedRole
	return result, nil
}

func loadOrganizationMember(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	organizationID uuid.UUID,
	userID uuid.UUID,
	forUpdate bool,
) (MemberSummary, error) {
	query := `
		SELECT membership.user_id, users.nickname, membership.role, membership.department_id,
		       membership.revision, membership.joined_at, membership.updated_at
		FROM organization_memberships membership
		JOIN users ON users.id = membership.user_id
		WHERE membership.organization_id = $1 AND membership.user_id = $2
	`
	if forUpdate {
		query += ` FOR UPDATE OF membership`
	}
	var result MemberSummary
	var role string
	var department pgtype.UUID
	if err := queryer.QueryRow(ctx, query, organizationID, userID).Scan(
		&result.UserID, &result.Nickname, &role, &department,
		&result.Revision, &result.JoinedAt, &result.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MemberSummary{}, ErrOrganizationNotFound
		}
		return MemberSummary{}, ErrServiceUnavailable
	}
	parsedRole, err := ParseRole(role)
	if err != nil || result.UserID == uuid.Nil || result.Revision <= 0 {
		return MemberSummary{}, ErrServiceUnavailable
	}
	result.Role = parsedRole
	if department.Valid {
		value := uuid.UUID(department.Bytes)
		result.DepartmentID = &value
	}
	return result, nil
}

func loadOrganizationDepartment(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	organizationID uuid.UUID,
	departmentID uuid.UUID,
	forUpdate bool,
) (DepartmentSummary, error) {
	query := `
		SELECT department.id, department.display_name, department.status,
		       (SELECT count(*) FROM organization_memberships membership
		        WHERE membership.organization_id = department.organization_id
		          AND membership.department_id = department.id),
		       department.revision, department.created_at, department.updated_at, department.archived_at
		FROM organization_departments department
		WHERE department.organization_id = $1 AND department.id = $2
	`
	if forUpdate {
		query += ` FOR UPDATE OF department`
	}
	var result DepartmentSummary
	var status string
	var memberCount int64
	if err := queryer.QueryRow(ctx, query, organizationID, departmentID).Scan(
		&result.ID, &result.DisplayName, &status, &memberCount, &result.Revision,
		&result.CreatedAt, &result.UpdatedAt, &result.ArchivedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DepartmentSummary{}, ErrOrganizationNotFound
		}
		return DepartmentSummary{}, ErrServiceUnavailable
	}
	parsedStatus, err := ParseDepartmentStatus(status)
	if err != nil || result.ID == uuid.Nil || result.Revision <= 0 || memberCount < 0 {
		return DepartmentSummary{}, ErrServiceUnavailable
	}
	result.Status = parsedStatus
	result.MemberCount = int(memberCount)
	return result, nil
}

func requireActiveOrganizationMutation(organization lockedOrganization, allowAdmin bool) error {
	if organization.Status == OrganizationStatusArchived {
		return ErrOrganizationArchived
	}
	if organization.Status != OrganizationStatusActive {
		return ErrOrganizationNotFound
	}
	if organization.ActorRole == RoleOwner || (allowAdmin && organization.ActorRole == RoleAdmin) {
		return nil
	}
	return ErrOrganizationForbidden
}

func authorizeMemberPatch(actorRole, targetRole Role, desiredRole *Role) error {
	if actorRole != RoleOwner && actorRole != RoleAdmin {
		return ErrOrganizationForbidden
	}
	if targetRole == RoleOwner || (actorRole == RoleAdmin && targetRole == RoleAdmin) {
		return ErrOrganizationForbidden
	}
	if desiredRole != nil {
		if *desiredRole == RoleOwner {
			return ErrMembershipConflict
		}
		if *desiredRole == RoleAdmin && actorRole != RoleOwner {
			return ErrOrganizationForbidden
		}
	}
	return nil
}

func requireActiveDepartment(ctx context.Context, tx pgx.Tx, organizationID, departmentID uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM organization_departments
			WHERE organization_id = $1 AND id = $2 AND status = 'active'
		)
	`, organizationID, departmentID).Scan(&exists); err != nil {
		return ErrServiceUnavailable
	}
	if !exists {
		return ErrMembershipConflict
	}
	return nil
}

func enforceDepartmentCapacity(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, limit int) error {
	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM organization_departments
		WHERE organization_id = $1 AND status = 'active'
	`, organizationID).Scan(&count); err != nil {
		return ErrServiceUnavailable
	}
	if count >= limit {
		return ErrDepartmentLimitReached
	}
	return nil
}

func activeDepartmentNameExists(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	nameKey string,
	excludeID uuid.UUID,
) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM organization_departments
			WHERE organization_id = $1 AND name_key = $2 AND status = 'active'
			  AND ($3::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR id <> $3)
		)
	`, organizationID, nameKey, excludeID).Scan(&exists); err != nil {
		return false, ErrServiceUnavailable
	}
	return exists, nil
}

func recordOrganizationAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	evidence AuditEvidence,
	eventType string,
	organizationID uuid.UUID,
	objectType string,
	objectID uuid.UUID,
	occurredAt time.Time,
	metadata map[string]string,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	bounded := make(map[string]string, len(metadata)+1)
	for key, value := range metadata {
		bounded[key] = value
	}
	bounded["organization_id"] = organizationID.String()
	actorUserID := actor.UserID
	deviceID := actor.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID: evidence.EventID, EventType: eventType, ActorUserID: &actorUserID, DeviceID: &deviceID,
		OrganizationID: &organizationID, ObjectType: objectType, ObjectID: &objectID,
		Outcome: audit.OutcomeSuccess, RequestID: evidence.RequestID, Metadata: bounded, OccurredAt: occurredAt,
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func validMutationEvidence(evidence mutationEvidence) bool {
	return evidence.Audit.EventID != uuid.Nil && validOrganizationRequestID(evidence.Audit.RequestID) &&
		!evidence.ChangedAt.IsZero()
}

func validPatchMemberTransaction(command patchMemberTransaction) bool {
	if command.Role == nil && !command.ChangeDepartment {
		return false
	}
	if command.Role != nil {
		switch *command.Role {
		case RoleAdmin, RoleAuditor, RoleMember:
		default:
			return false
		}
	}
	if !command.ChangeDepartment {
		return command.DepartmentID == nil && !command.ClearDepartment
	}
	return (command.DepartmentID != nil) != command.ClearDepartment &&
		(command.DepartmentID == nil || *command.DepartmentID != uuid.Nil)
}

func equalUUIDPointers(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func postgresUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}
