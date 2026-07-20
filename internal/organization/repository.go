package organization

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
