package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const userAggregateProjection = `
	SELECT
		u.id,
		u.status,
		u.administratively_disabled,
		u.deletion_finalized_at,
		u.administrative_revision,
		u.created_at,
		(SELECT count(*) FROM devices d WHERE d.user_id = u.id) AS device_count,
		(SELECT count(*) FROM devices d WHERE d.user_id = u.id AND d.status = 'active') AS active_device_count,
		(
			SELECT count(*) FROM sessions s
			WHERE s.user_id = u.id
			  AND s.revoked_at IS NULL
			  AND s.replaced_at IS NULL
			  AND s.expires_at > $1
		) AS active_session_count,
		GREATEST(
			(SELECT max(d.last_seen_at) FROM devices d WHERE d.user_id = u.id),
			(SELECT max(s.issued_at) FROM sessions s WHERE s.user_id = u.id)
		) AS last_cloud_activity_at
	FROM users u
`

type ControlRepository struct {
	postgres   *pgxpool.Pool
	identities *secure.IdentityCodec
	protector  *Protector
	passwords  *secure.PasswordHasher
	clock      func() time.Time
}

func NewControlRepository(
	postgres *pgxpool.Pool,
	identities *secure.IdentityCodec,
	protector *Protector,
	clock func() time.Time,
) (*ControlRepository, error) {
	if postgres == nil || identities == nil || protector == nil || clock == nil {
		return nil, errors.New("admin control repository dependencies are required")
	}
	passwords, err := secure.DefaultPasswordHasher()
	if err != nil {
		return nil, errors.New("admin control repository password hasher is unavailable")
	}
	return &ControlRepository{postgres: postgres, identities: identities, protector: protector, passwords: passwords, clock: clock}, nil
}

func (r *ControlRepository) ListUsers(ctx context.Context, query UserQuery) (DataPage[User], error) {
	if r == nil || !validUserStatusFilter(query.Status) || !validRepositoryPage(query.Limit, query.After) {
		return DataPage[User]{}, ErrInvalidCommand
	}
	afterTime, afterID := repositoryPageArguments(query.After)
	rows, err := r.postgres.Query(ctx, userAggregateProjection+`
		WHERE ($2 = '' OR u.status = $2)
		  AND ($3::timestamptz IS NULL OR (u.created_at, u.id) < ($3, $4::uuid))
		ORDER BY u.created_at DESC, u.id DESC
		LIMIT $5
	`, r.clock().UTC(), string(query.Status), afterTime, afterID, query.Limit+1)
	if err != nil {
		return DataPage[User]{}, ErrUnavailable
	}
	defer rows.Close()

	users := make([]User, 0, query.Limit+1)
	for rows.Next() {
		user, err := scanControlUser(rows)
		if err != nil {
			return DataPage[User]{}, err
		}
		users = append(users, user)
	}
	if rows.Err() != nil {
		return DataPage[User]{}, ErrUnavailable
	}

	page := retainUserPage(users, query.Limit)
	if err := r.attachMaskedIdentities(ctx, page.Items); err != nil {
		return DataPage[User]{}, err
	}
	return page, nil
}

func (r *ControlRepository) LookupUser(
	ctx context.Context,
	kind secure.IdentityKind,
	normalized string,
) (User, error) {
	if r == nil {
		return User{}, ErrInvalidCommand
	}
	canonical, err := secure.NormalizeIdentity(kind, normalized)
	if err != nil || canonical != normalized {
		return User{}, ErrInvalidCommand
	}
	for _, candidate := range r.identities.LookupCandidates(kind, normalized) {
		var userID uuid.UUID
		err := r.postgres.QueryRow(ctx, `
			SELECT user_id
			FROM identities
			WHERE kind = $1 AND lookup_key_id = $2 AND lookup_hmac = $3
		`, kind, candidate.KeyID, candidate.HMAC).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return User{}, ErrUnavailable
		}
		return r.GetUser(ctx, userID)
	}
	return User{}, ErrNotFound
}

func (r *ControlRepository) GetUser(ctx context.Context, userID uuid.UUID) (User, error) {
	if r == nil || userID == uuid.Nil {
		return User{}, ErrInvalidCommand
	}
	user, err := scanControlUser(r.postgres.QueryRow(ctx, userAggregateProjection+`
		WHERE u.id = $2
	`, r.clock().UTC(), userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, mapControlRepositoryError(err)
	}
	users := []User{user}
	if err := r.attachMaskedIdentities(ctx, users); err != nil {
		return User{}, err
	}
	return users[0], nil
}

// Stats computes point-in-time account and device counters in a single round
// trip for the admin overview dashboard.
func (r *ControlRepository) Stats(ctx context.Context) (PlatformStats, error) {
	if r == nil {
		return PlatformStats{}, ErrInvalidCommand
	}
	var stats PlatformStats
	err := r.postgres.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM users) AS user_total,
			(SELECT count(*) FROM users WHERE status = 'active') AS user_active,
			(SELECT count(*) FROM users WHERE status = 'disabled') AS user_disabled,
			(SELECT count(*) FROM users WHERE status = 'pending_deletion') AS user_pending_deletion,
			(SELECT count(*) FROM devices) AS device_total,
			(SELECT count(*) FROM devices WHERE status = 'active') AS device_active
	`).Scan(
		&stats.UserTotal, &stats.UserActive, &stats.UserDisabled,
		&stats.UserPendingDeletion, &stats.DeviceTotal, &stats.DeviceActive,
	)
	if err != nil {
		return PlatformStats{}, ErrUnavailable
	}
	return stats, nil
}

// DeviceStats groups the installed base by platform and app version for the
// admin device distribution view.
func (r *ControlRepository) DeviceStats(ctx context.Context) (DeviceStats, error) {
	if r == nil {
		return DeviceStats{}, ErrInvalidCommand
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT platform, app_version,
			count(*) AS total,
			count(*) FILTER (WHERE status = 'active') AS active
		FROM devices
		GROUP BY platform, app_version
		ORDER BY total DESC, platform ASC, app_version ASC
		LIMIT 500
	`)
	if err != nil {
		return DeviceStats{}, ErrUnavailable
	}
	defer rows.Close()
	buckets := make([]DeviceVersionStat, 0)
	for rows.Next() {
		var bucket DeviceVersionStat
		if err := rows.Scan(&bucket.Platform, &bucket.AppVersion, &bucket.Total, &bucket.Active); err != nil {
			return DeviceStats{}, ErrUnavailable
		}
		buckets = append(buckets, bucket)
	}
	if rows.Err() != nil {
		return DeviceStats{}, ErrUnavailable
	}
	return DeviceStats{Buckets: buckets}, nil
}

// UserMemberships lists the organizations and workspaces a user belongs to.
func (r *ControlRepository) UserMemberships(ctx context.Context, userID uuid.UUID) (UserMemberships, error) {
	if r == nil || userID == uuid.Nil {
		return UserMemberships{}, ErrInvalidCommand
	}
	exists, err := r.userExists(ctx, userID)
	if err != nil {
		return UserMemberships{}, err
	}
	if !exists {
		return UserMemberships{}, ErrNotFound
	}
	organizations, err := r.scanMemberships(ctx, `
		SELECT o.id, o.display_name, m.role, o.status
		FROM organization_memberships m
		JOIN organizations o ON o.id = m.organization_id
		WHERE m.user_id = $1
		ORDER BY o.created_at DESC, o.id DESC
		LIMIT 500
	`, userID)
	if err != nil {
		return UserMemberships{}, err
	}
	workspaces, err := r.scanMemberships(ctx, `
		SELECT w.id, w.display_name, m.role, w.status
		FROM workspace_memberships m
		JOIN workspaces w ON w.id = m.workspace_id
		WHERE m.user_id = $1
		ORDER BY w.created_at DESC, w.id DESC
		LIMIT 500
	`, userID)
	if err != nil {
		return UserMemberships{}, err
	}
	return UserMemberships{Organizations: organizations, Workspaces: workspaces}, nil
}

func (r *ControlRepository) scanMemberships(ctx context.Context, query string, userID uuid.UUID) ([]Membership, error) {
	rows, err := r.postgres.Query(ctx, query, userID)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	memberships := make([]Membership, 0)
	for rows.Next() {
		var membership Membership
		if err := rows.Scan(&membership.ID, &membership.DisplayName, &membership.Role, &membership.Status); err != nil {
			return nil, ErrUnavailable
		}
		memberships = append(memberships, membership)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return memberships, nil
}

func (r *ControlRepository) ListUserDevices(ctx context.Context, query DeviceQuery) (DataPage[Device], error) {
	if r == nil || query.UserID == uuid.Nil || !validRepositoryPage(query.Limit, query.After) {
		return DataPage[Device]{}, ErrInvalidCommand
	}
	exists, err := r.userExists(ctx, query.UserID)
	if err != nil {
		return DataPage[Device]{}, err
	}
	if !exists {
		return DataPage[Device]{}, ErrNotFound
	}
	afterTime, afterID := repositoryPageArguments(query.After)
	rows, err := r.postgres.Query(ctx, `
		SELECT id, user_id, display_name, platform, app_version, status, last_seen_at
		FROM devices
		WHERE user_id = $1
		  AND ($2::timestamptz IS NULL OR (last_seen_at, id) < ($2, $3::uuid))
		ORDER BY last_seen_at DESC, id DESC
		LIMIT $4
	`, query.UserID, afterTime, afterID, query.Limit+1)
	if err != nil {
		return DataPage[Device]{}, ErrUnavailable
	}
	defer rows.Close()

	devices := make([]Device, 0, query.Limit+1)
	for rows.Next() {
		var device Device
		var status string
		var lastSeen time.Time
		if err := rows.Scan(
			&device.ID, &device.UserID, &device.DisplayName, &device.Platform,
			&device.ClientVersion, &status, &lastSeen,
		); err != nil {
			return DataPage[Device]{}, ErrUnavailable
		}
		device.Status = DeviceStatus(status)
		if device.ID == uuid.Nil || device.UserID != query.UserID || !validDeviceStatus(device.Status) {
			return DataPage[Device]{}, ErrUnavailable
		}
		lastSeen = lastSeen.UTC()
		device.LastSeenAt = &lastSeen
		devices = append(devices, device)
	}
	if rows.Err() != nil {
		return DataPage[Device]{}, ErrUnavailable
	}
	return retainDevicePage(devices, query.Limit), nil
}

func (r *ControlRepository) ListUserSessions(ctx context.Context, query SessionQuery) (DataPage[Session], error) {
	if r == nil || query.UserID == uuid.Nil || query.Now.IsZero() || !validRepositoryPage(query.Limit, query.After) {
		return DataPage[Session]{}, ErrInvalidCommand
	}
	exists, err := r.userExists(ctx, query.UserID)
	if err != nil {
		return DataPage[Session]{}, err
	}
	if !exists {
		return DataPage[Session]{}, ErrNotFound
	}
	afterTime, afterID := repositoryPageArguments(query.After)
	rows, err := r.postgres.Query(ctx, `
		SELECT id, user_id, device_id, issued_at, expires_at, replaced_at, revoked_at, replay_detected_at
		FROM sessions
		WHERE user_id = $1
		  AND ($2::timestamptz IS NULL OR (issued_at, id) < ($2, $3::uuid))
		ORDER BY issued_at DESC, id DESC
		LIMIT $4
	`, query.UserID, afterTime, afterID, query.Limit+1)
	if err != nil {
		return DataPage[Session]{}, ErrUnavailable
	}
	defer rows.Close()

	sessions := make([]Session, 0, query.Limit+1)
	for rows.Next() {
		var session Session
		var replacedAt, revokedAt, replayAt pgtype.Timestamptz
		if err := rows.Scan(
			&session.ID, &session.UserID, &session.DeviceID, &session.IssuedAt, &session.ExpiresAt,
			&replacedAt, &revokedAt, &replayAt,
		); err != nil {
			return DataPage[Session]{}, ErrUnavailable
		}
		if session.ID == uuid.Nil || session.UserID != query.UserID || session.DeviceID == uuid.Nil {
			return DataPage[Session]{}, ErrUnavailable
		}
		session.IssuedAt = session.IssuedAt.UTC()
		session.ExpiresAt = session.ExpiresAt.UTC()
		session.RevokedAt = controlTimePointer(revokedAt)
		session.Status = deriveSessionStatus(replayAt.Valid, revokedAt.Valid, replacedAt.Valid, session.ExpiresAt, query.Now)
		sessions = append(sessions, session)
	}
	if rows.Err() != nil {
		return DataPage[Session]{}, ErrUnavailable
	}
	return retainSessionPage(sessions, query.Limit), nil
}

func (r *ControlRepository) ListOfficialAuditEvents(
	ctx context.Context,
	query OfficialAuditQuery,
) (DataPage[OfficialAuditEvent], error) {
	if r == nil || !validRepositoryPage(query.Limit, query.After) {
		return DataPage[OfficialAuditEvent]{}, ErrInvalidCommand
	}
	afterTime, afterID := repositoryPageArguments(query.After)
	rows, err := r.postgres.Query(ctx, `
		SELECT id, event_type, object_type, object_id, outcome,
		       COALESCE(reason_code, metadata->>'reason_code', ''), request_id,
		       (metadata->>'actor_admin_id')::uuid, metadata->>'actor_admin_role', created_at
		FROM audit_events
		WHERE event_type LIKE 'official\_%' ESCAPE '\'
		  AND metadata ? 'actor_admin_id'
		  AND metadata ? 'actor_admin_role'
		  AND ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2::uuid))
		ORDER BY created_at DESC, id DESC
		LIMIT $3
	`, afterTime, afterID, query.Limit+1)
	if err != nil {
		return DataPage[OfficialAuditEvent]{}, ErrUnavailable
	}
	defer rows.Close()
	items := make([]OfficialAuditEvent, 0, query.Limit+1)
	for rows.Next() {
		var item OfficialAuditEvent
		if err := rows.Scan(
			&item.ID, &item.EventType, &item.ObjectType, &item.ObjectID, &item.Outcome,
			&item.ReasonCode, &item.RequestID, &item.ActorAdminID, &item.ActorAdminRole, &item.CreatedAt,
		); err != nil || !validOfficialAuditEvent(item) {
			return DataPage[OfficialAuditEvent]{}, ErrUnavailable
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if rows.Err() != nil {
		return DataPage[OfficialAuditEvent]{}, ErrUnavailable
	}
	page := DataPage[OfficialAuditEvent]{Items: items}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &PagePosition{Time: last.CreatedAt, ID: last.ID}
	}
	return page, nil
}

func validOfficialAuditEvent(value OfficialAuditEvent) bool {
	if value.ID == uuid.Nil || value.ObjectID == uuid.Nil || value.ActorAdminID == uuid.Nil ||
		value.CreatedAt.IsZero() || !strings.HasPrefix(value.EventType, "official_") ||
		!validControlText(value.EventType, 3, 100, false) ||
		!validControlText(value.ObjectType, 3, 64, false) ||
		!validControlText(value.RequestID, 1, 128, false) ||
		(value.Outcome != "success" && value.Outcome != "denied") ||
		(value.ReasonCode != "" && !controlReasonPattern.MatchString(value.ReasonCode)) {
		return false
	}
	switch value.ActorAdminRole {
	case "super_admin", "developer", "operator", "support", "finance", "auditor":
		return true
	default:
		return false
	}
}

func (r *ControlRepository) attachMaskedIdentities(ctx context.Context, users []User) error {
	if len(users) == 0 {
		return nil
	}
	userIDs := make([]uuid.UUID, len(users))
	byID := make(map[uuid.UUID]int, len(users))
	for index := range users {
		userIDs[index] = users[index].ID
		byID[users[index].ID] = index
	}
	rows, err := r.postgres.Query(ctx, `
		SELECT user_id, kind, encryption_key_id, nonce, ciphertext
		FROM identities
		WHERE user_id = ANY($1::uuid[])
		ORDER BY user_id, kind
	`, userIDs)
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var userID uuid.UUID
		var kind secure.IdentityKind
		var sealed secure.SealedIdentity
		if err := rows.Scan(&userID, &kind, &sealed.EncryptionKeyID, &sealed.Nonce, &sealed.Ciphertext); err != nil {
			return ErrUnavailable
		}
		index, ok := byID[userID]
		if !ok {
			return ErrUnavailable
		}
		normalized, err := r.identities.Open(kind, sealed)
		if err != nil {
			return ErrUnavailable
		}
		masked, err := MaskIdentity(kind, normalized)
		if err != nil {
			return ErrUnavailable
		}
		switch kind {
		case secure.IdentityEmail:
			users[index].MaskedEmail = masked
		case secure.IdentityPhone:
			users[index].MaskedPhone = masked
		default:
			return ErrUnavailable
		}
	}
	if rows.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *ControlRepository) userExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	var exists bool
	if err := r.postgres.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
		return false, ErrUnavailable
	}
	return exists, nil
}

type controlRowScanner interface {
	Scan(...any) error
}

func scanControlUser(scanner controlRowScanner) (User, error) {
	var user User
	var status string
	var deletionFinalizedAt, lastCloudActivityAt pgtype.Timestamptz
	var deviceCount, activeDeviceCount, activeSessionCount int64
	if err := scanner.Scan(
		&user.ID,
		&status,
		&user.AdministrativelyDisabled,
		&deletionFinalizedAt,
		&user.AdministrativeRevision,
		&user.CreatedAt,
		&deviceCount,
		&activeDeviceCount,
		&activeSessionCount,
		&lastCloudActivityAt,
	); err != nil {
		return User{}, err
	}
	user.Status = UserStatus(status)
	if user.ID == uuid.Nil || !validUserStatusFilter(user.Status) || user.Status == "" ||
		user.AdministrativeRevision < 1 || deviceCount < 0 || activeDeviceCount < 0 ||
		activeSessionCount < 0 || activeDeviceCount > deviceCount {
		return User{}, ErrUnavailable
	}
	user.CreatedAt = user.CreatedAt.UTC()
	user.DeletionFinalizedAt = controlTimePointer(deletionFinalizedAt)
	user.LastCloudActivityAt = controlTimePointer(lastCloudActivityAt)
	user.DeviceCount = int(deviceCount)
	user.ActiveDeviceCount = int(activeDeviceCount)
	user.ActiveSessionCount = int(activeSessionCount)
	return user, nil
}

func retainUserPage(items []User, limit int) DataPage[User] {
	page := DataPage[User]{Items: items}
	if len(page.Items) <= limit {
		return page
	}
	page.Items = page.Items[:limit]
	last := page.Items[len(page.Items)-1]
	page.Next = &PagePosition{Time: last.CreatedAt, ID: last.ID}
	return page
}

func retainDevicePage(items []Device, limit int) DataPage[Device] {
	page := DataPage[Device]{Items: items}
	if len(page.Items) <= limit {
		return page
	}
	page.Items = page.Items[:limit]
	last := page.Items[len(page.Items)-1]
	page.Next = &PagePosition{Time: *last.LastSeenAt, ID: last.ID}
	return page
}

func retainSessionPage(items []Session, limit int) DataPage[Session] {
	page := DataPage[Session]{Items: items}
	if len(page.Items) <= limit {
		return page
	}
	page.Items = page.Items[:limit]
	last := page.Items[len(page.Items)-1]
	page.Next = &PagePosition{Time: last.IssuedAt, ID: last.ID}
	return page
}

func validRepositoryPage(limit int, after *PagePosition) bool {
	if limit < 1 || limit > maximumControlPageLimit {
		return false
	}
	return after == nil || (!after.Time.IsZero() && after.ID != uuid.Nil)
}

func repositoryPageArguments(after *PagePosition) (any, uuid.UUID) {
	if after == nil {
		return nil, uuid.Nil
	}
	return after.Time.UTC(), after.ID
}

func validDeviceStatus(status DeviceStatus) bool {
	return status == DeviceActive || status == DeviceInactive || status == DeviceRevoked
}

func deriveSessionStatus(
	replayDetected bool,
	revoked bool,
	rotated bool,
	expiresAt time.Time,
	now time.Time,
) SessionStatus {
	switch {
	case replayDetected:
		return SessionReplayDetected
	case revoked:
		return SessionRevoked
	case rotated:
		return SessionRotated
	case !expiresAt.After(now):
		return SessionExpired
	default:
		return SessionActive
	}
}

func controlTimePointer(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time.UTC()
	return &result
}

func mapControlRepositoryError(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return ErrUnavailable
	}
	return ErrUnavailable
}

type storedOperation struct {
	KeyID       string
	Fingerprint []byte
	Operation   Operation
}

type mutationResult struct {
	UserID         uuid.UUID
	BeforeRevision int64
	AfterRevision  int64
	ErrorCode      string
}

type controlDomainFailure struct {
	cause error
	code  string
}

func (e *controlDomainFailure) Error() string {
	return e.code
}

func (e *controlDomainFailure) Unwrap() error {
	return e.cause
}

func (r *ControlRepository) Execute(
	ctx context.Context,
	action Action,
	targetID uuid.UUID,
	command Command,
) (Operation, error) {
	if r == nil || validateControlCommand(action, targetID, command) != nil {
		return Operation{}, ErrInvalidCommand
	}
	if _, ok := serviceSubjectFromContext(ctx); !ok {
		return Operation{}, ErrInvalidCommand
	}
	digests := r.protector.IdempotencyCandidates(command.OperationID)
	if len(digests) == 0 {
		return Operation{}, ErrUnavailable
	}

	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Operation{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	existing, found, err := r.findOperation(ctx, tx, command.OperationID, digests)
	if err != nil {
		return Operation{}, err
	}
	if found {
		return r.replayOperation(existing, action, targetID, command)
	}

	active := digests[0]
	fingerprint := r.protector.RequestFingerprint(active.KeyID, action, targetID, command)
	if len(fingerprint) != 32 {
		return Operation{}, ErrUnavailable
	}
	inserted, err := r.insertExecuting(ctx, tx, action, targetID, command, active, fingerprint)
	if err != nil {
		return Operation{}, err
	}
	if !inserted {
		existing, found, err = r.findOperation(ctx, tx, command.OperationID, digests)
		if err != nil || !found {
			return Operation{}, ErrUnavailable
		}
		return r.replayOperation(existing, action, targetID, command)
	}

	mutation, domainErr := r.applyAction(ctx, tx, action, targetID, command)
	if domainErr != nil {
		if !durableDomainFailure(domainErr) {
			return Operation{}, ErrUnavailable
		}
		operation, finishErr := r.finishRejected(ctx, tx, action, targetID, command, mutation, domainErr)
		if finishErr != nil {
			return Operation{}, finishErr
		}
		if err := tx.Commit(ctx); err != nil {
			return Operation{}, ErrUnavailable
		}
		return operation, domainErr
	}

	operation, err := r.finishSucceeded(ctx, tx, action, targetID, command, mutation)
	if err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Operation{}, ErrUnavailable
	}
	return operation, nil
}

func (r *ControlRepository) GetOperation(ctx context.Context, operationID uuid.UUID) (Operation, error) {
	if r == nil || operationID == uuid.Nil {
		return Operation{}, ErrInvalidCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return Operation{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	stored, found, err := r.findOperation(ctx, tx, operationID, nil)
	if err != nil {
		return Operation{}, err
	}
	if !found {
		return Operation{}, ErrNotFound
	}
	return stored.Operation, nil
}

func (r *ControlRepository) findOperation(
	ctx context.Context,
	tx pgx.Tx,
	operationID uuid.UUID,
	digests []Digest,
) (storedOperation, bool, error) {
	stored, err := scanStoredOperation(tx.QueryRow(ctx, `
		SELECT idempotency_key_id, request_fingerprint, operation_id, status,
		       COALESCE(error_code, ''), COALESCE(result_revision, 0), updated_at
		FROM admin_operations
		WHERE operation_id = $1
	`, operationID))
	if err == nil {
		return stored, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return storedOperation{}, false, ErrUnavailable
	}
	for _, digest := range digests {
		stored, err = scanStoredOperation(tx.QueryRow(ctx, `
			SELECT idempotency_key_id, request_fingerprint, operation_id, status,
			       COALESCE(error_code, ''), COALESCE(result_revision, 0), updated_at
			FROM admin_operations
			WHERE idempotency_key_id = $1 AND idempotency_key_hmac = $2
		`, digest.KeyID, digest.Sum))
		if err == nil {
			return stored, true, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return storedOperation{}, false, ErrUnavailable
		}
	}
	return storedOperation{}, false, nil
}

func (r *ControlRepository) insertExecuting(
	ctx context.Context,
	tx pgx.Tx,
	action Action,
	targetID uuid.UUID,
	command Command,
	digest Digest,
	fingerprint []byte,
) (bool, error) {
	serviceSubject, ok := serviceSubjectFromContext(ctx)
	targetType, targetOK := controlTargetType(action)
	if !ok || !targetOK || len(digest.Sum) != 32 || len(fingerprint) != 32 {
		return false, ErrInvalidCommand
	}
	var approvalID any
	if command.ApprovalID != nil {
		approvalID = *command.ApprovalID
	}
	var ticketReference any
	if command.TicketReference != "" {
		ticketReference = command.TicketReference
	}
	now := r.clock().UTC()
	if now.IsZero() {
		return false, ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO admin_operations (
			operation_id, idempotency_key_id, idempotency_key_hmac, request_fingerprint,
			service_subject, actor_admin_id, approval_id, request_id, action, target_type,
			target_id, expected_revision, status, reason_code, ticket_reference,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, 'executing', $13, $14, $15, $15
		)
		ON CONFLICT DO NOTHING
	`, command.OperationID, digest.KeyID, digest.Sum, fingerprint, serviceSubject,
		command.ActorAdminID, approvalID, command.RequestID, action, targetType, targetID,
		command.ExpectedRevision, command.ReasonCode, ticketReference, now)
	if err != nil {
		return false, ErrUnavailable
	}
	return tag.RowsAffected() == 1, nil
}

func (r *ControlRepository) applyAction(
	ctx context.Context,
	tx pgx.Tx,
	action Action,
	targetID uuid.UUID,
	command Command,
) (mutationResult, error) {
	userID, err := resolveControlTargetUser(ctx, tx, action, targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		code := controlNotFoundCode(action)
		return mutationResult{ErrorCode: code}, controlFailure(ErrNotFound, code)
	}
	if err != nil {
		return mutationResult{}, ErrUnavailable
	}
	if err := lockTargetUser(ctx, tx, userID); err != nil {
		return mutationResult{}, ErrUnavailable
	}
	var status string
	var administrativelyDisabled bool
	var deletionFinalizedAt pgtype.Timestamptz
	var revision int64
	if err := tx.QueryRow(ctx, `
		SELECT status, administratively_disabled, deletion_finalized_at, administrative_revision
		FROM users WHERE id = $1 FOR UPDATE
	`, userID).Scan(&status, &administrativelyDisabled, &deletionFinalizedAt, &revision); errors.Is(err, pgx.ErrNoRows) {
		code := controlNotFoundCode(action)
		return mutationResult{ErrorCode: code}, controlFailure(ErrNotFound, code)
	} else if err != nil || revision < 1 {
		return mutationResult{}, ErrUnavailable
	}
	mutation := mutationResult{UserID: userID, BeforeRevision: revision}
	if revision != command.ExpectedRevision {
		mutation.ErrorCode = "USER_STATE_CONFLICT"
		return mutation, controlFailure(ErrStateConflict, mutation.ErrorCode)
	}

	now := r.clock().UTC()
	if now.IsZero() {
		return mutationResult{}, ErrUnavailable
	}
	var afterRevision int64
	switch action {
	case RevokeDevice:
		var lockedUserID uuid.UUID
		var deviceStatus string
		if err := tx.QueryRow(ctx, `
			SELECT user_id, status FROM devices WHERE id = $1 FOR UPDATE
		`, targetID).Scan(&lockedUserID, &deviceStatus); errors.Is(err, pgx.ErrNoRows) {
			mutation.ErrorCode = "DEVICE_NOT_FOUND"
			return mutation, controlFailure(ErrNotFound, mutation.ErrorCode)
		} else if err != nil || lockedUserID != userID {
			return mutationResult{}, ErrUnavailable
		}
		if deviceStatus == "revoked" {
			mutation.ErrorCode = "DEVICE_ALREADY_REVOKED"
			return mutation, controlFailure(ErrStateConflict, mutation.ErrorCode)
		}
		if deviceStatus != "active" && deviceStatus != "inactive" {
			return mutationResult{}, ErrUnavailable
		}
		afterRevision, err = revokeDeviceLifecycle(ctx, tx, userID, targetID, now)
	case RevokeSession:
		var lockedUserID, familyID uuid.UUID
		var revokedAt pgtype.Timestamptz
		if err := tx.QueryRow(ctx, `
			SELECT user_id, family_id, revoked_at FROM sessions WHERE id = $1 FOR UPDATE
		`, targetID).Scan(&lockedUserID, &familyID, &revokedAt); errors.Is(err, pgx.ErrNoRows) {
			mutation.ErrorCode = "SESSION_NOT_FOUND"
			return mutation, controlFailure(ErrNotFound, mutation.ErrorCode)
		} else if err != nil || lockedUserID != userID {
			return mutationResult{}, ErrUnavailable
		}
		if revokedAt.Valid {
			mutation.ErrorCode = "SESSION_ALREADY_REVOKED"
			return mutation, controlFailure(ErrStateConflict, mutation.ErrorCode)
		}
		afterRevision, err = revokeSessionFamilyLifecycle(ctx, tx, userID, familyID, now)
	case RevokeAllSessions:
		var activeCount int64
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL
		`, userID).Scan(&activeCount); err != nil {
			return mutationResult{}, ErrUnavailable
		}
		if activeCount == 0 {
			mutation.ErrorCode = "NO_ACTIVE_SESSIONS"
			return mutation, controlFailure(ErrStateConflict, mutation.ErrorCode)
		}
		afterRevision, err = revokeAllSessionsLifecycle(ctx, tx, userID, now)
	case ForcePasswordReset:
		if status != "active" || deletionFinalizedAt.Valid {
			mutation.ErrorCode = "USER_STATE_CONFLICT"
			return mutation, controlFailure(ErrStateConflict, mutation.ErrorCode)
		}
		afterRevision, err = r.forcePasswordResetLifecycle(ctx, tx, userID, now)
	case DisableUser:
		if status != "active" || administrativelyDisabled || deletionFinalizedAt.Valid {
			mutation.ErrorCode = "USER_STATE_CONFLICT"
			return mutation, controlFailure(ErrStateConflict, mutation.ErrorCode)
		}
		afterRevision, err = disableUserLifecycle(ctx, tx, userID, now)
	case EnableUser:
		if status != "disabled" || !administrativelyDisabled || deletionFinalizedAt.Valid {
			mutation.ErrorCode = "USER_STATE_CONFLICT"
			return mutation, controlFailure(ErrStateConflict, mutation.ErrorCode)
		}
		afterRevision, err = enableUserLifecycle(ctx, tx, userID, now)
	default:
		return mutationResult{}, ErrInvalidCommand
	}
	if err != nil || afterRevision != revision+1 {
		return mutationResult{}, ErrUnavailable
	}
	mutation.AfterRevision = afterRevision
	return mutation, nil
}

func (r *ControlRepository) finishRejected(
	ctx context.Context,
	tx pgx.Tx,
	action Action,
	targetID uuid.UUID,
	command Command,
	mutation mutationResult,
	domainErr error,
) (Operation, error) {
	code, ok := controlFailureCode(domainErr)
	if !ok {
		return Operation{}, ErrUnavailable
	}
	status := OperationConflict
	if errors.Is(domainErr, ErrNotFound) {
		status = OperationFailed
	}
	mutation.ErrorCode = code
	now := r.clock().UTC()
	if now.IsZero() {
		return Operation{}, ErrUnavailable
	}
	operation := Operation{ID: command.OperationID, Status: status, ErrorCode: code, UpdatedAt: now}
	if err := r.insertControlAudit(ctx, tx, action, targetID, command, mutation, "denied", now); err != nil {
		return Operation{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE admin_operations
		SET status = $2, error_code = $3, updated_at = $4, completed_at = $4
		WHERE operation_id = $1 AND status = 'executing'
	`, command.OperationID, status, code, now)
	if err != nil || tag.RowsAffected() != 1 {
		return Operation{}, ErrUnavailable
	}
	return operation, nil
}

func (r *ControlRepository) finishSucceeded(
	ctx context.Context,
	tx pgx.Tx,
	action Action,
	targetID uuid.UUID,
	command Command,
	mutation mutationResult,
) (Operation, error) {
	if mutation.UserID == uuid.Nil || mutation.AfterRevision < 1 {
		return Operation{}, ErrUnavailable
	}
	now := r.clock().UTC()
	if now.IsZero() {
		return Operation{}, ErrUnavailable
	}
	operation := Operation{
		ID: command.OperationID, Status: OperationSucceeded,
		AdministrativeRevision: mutation.AfterRevision, UpdatedAt: now,
	}
	if err := r.insertControlAudit(ctx, tx, action, targetID, command, mutation, "success", now); err != nil {
		return Operation{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE admin_operations
		SET status = 'succeeded', result_revision = $2, updated_at = $3, completed_at = $3
		WHERE operation_id = $1 AND status = 'executing'
	`, command.OperationID, mutation.AfterRevision, now)
	if err != nil || tag.RowsAffected() != 1 {
		return Operation{}, ErrUnavailable
	}
	return operation, nil
}

func (r *ControlRepository) insertControlAudit(
	ctx context.Context,
	tx pgx.Tx,
	action Action,
	targetID uuid.UUID,
	command Command,
	mutation mutationResult,
	outcome string,
	now time.Time,
) error {
	serviceSubject, ok := serviceSubjectFromContext(ctx)
	eventType, eventOK := controlEventType(action)
	targetType, targetOK := controlTargetType(action)
	if !ok || !eventOK || !targetOK || (outcome != "success" && outcome != "denied") {
		return ErrUnavailable
	}
	metadata, err := json.Marshal(struct {
		OperationID      uuid.UUID  `json:"operation_id"`
		ActorAdminID     uuid.UUID  `json:"actor_admin_id"`
		ApprovalID       *uuid.UUID `json:"approval_id,omitempty"`
		ExpectedRevision int64      `json:"expected_revision"`
		ResultRevision   int64      `json:"result_revision,omitempty"`
		TicketReference  string     `json:"ticket_reference,omitempty"`
	}{
		OperationID: command.OperationID, ActorAdminID: command.ActorAdminID,
		ApprovalID: command.ApprovalID, ExpectedRevision: command.ExpectedRevision,
		ResultRevision: mutation.AfterRevision, TicketReference: command.TicketReference,
	})
	if err != nil {
		return ErrUnavailable
	}
	var subjectUserID any
	if mutation.UserID != uuid.Nil {
		subjectUserID = mutation.UserID
	}
	auditID, err := uuid.NewRandom()
	if err != nil {
		return ErrUnavailable
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, operator_identity, subject_user_id, object_type, object_id,
			outcome, reason_code, request_id, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
	`, auditID, eventType, serviceSubject, subjectUserID, targetType, targetID,
		outcome, command.ReasonCode, command.RequestID, string(metadata), now)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *ControlRepository) replayOperation(
	existing storedOperation,
	action Action,
	targetID uuid.UUID,
	command Command,
) (Operation, error) {
	fingerprint := r.protector.RequestFingerprint(existing.KeyID, action, targetID, command)
	if len(fingerprint) != 32 {
		return Operation{}, ErrUnavailable
	}
	if subtle.ConstantTimeCompare(existing.Fingerprint, fingerprint) != 1 {
		return Operation{}, ErrIdempotencyKeyReused
	}
	return operationReplayResult(existing.Operation)
}

func operationReplayResult(operation Operation) (Operation, error) {
	if err := validateOperation(operation); err != nil {
		return Operation{}, ErrUnavailable
	}
	switch operation.Status {
	case OperationExecuting, OperationSucceeded:
		return operation, nil
	case OperationFailed:
		return operation, controlFailure(ErrNotFound, operation.ErrorCode)
	case OperationConflict:
		return operation, controlFailure(ErrStateConflict, operation.ErrorCode)
	default:
		return Operation{}, ErrUnavailable
	}
}

func durableDomainFailure(err error) bool {
	var failure *controlDomainFailure
	return errors.As(err, &failure) &&
		(errors.Is(err, ErrNotFound) || errors.Is(err, ErrStateConflict)) &&
		operationErrorPattern.MatchString(failure.code)
}

func controlFailure(cause error, code string) error {
	return &controlDomainFailure{cause: cause, code: code}
}

func controlFailureCode(err error) (string, bool) {
	var failure *controlDomainFailure
	if !errors.As(err, &failure) || !operationErrorPattern.MatchString(failure.code) {
		return "", false
	}
	return failure.code, true
}

func scanStoredOperation(scanner controlRowScanner) (storedOperation, error) {
	var stored storedOperation
	var status string
	if err := scanner.Scan(
		&stored.KeyID,
		&stored.Fingerprint,
		&stored.Operation.ID,
		&status,
		&stored.Operation.ErrorCode,
		&stored.Operation.AdministrativeRevision,
		&stored.Operation.UpdatedAt,
	); err != nil {
		return storedOperation{}, err
	}
	stored.Operation.Status = OperationStatus(status)
	stored.Operation.UpdatedAt = stored.Operation.UpdatedAt.UTC()
	if len(stored.Fingerprint) != 32 || !protectorKeyIDPattern.MatchString(stored.KeyID) ||
		validateOperation(stored.Operation) != nil {
		return storedOperation{}, ErrUnavailable
	}
	return stored, nil
}

func resolveControlTargetUser(ctx context.Context, tx pgx.Tx, action Action, targetID uuid.UUID) (uuid.UUID, error) {
	if action == DisableUser || action == EnableUser || action == RevokeAllSessions || action == ForcePasswordReset {
		var userID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1`, targetID).Scan(&userID); err != nil {
			return uuid.Nil, err
		}
		return userID, nil
	}
	table := "devices"
	if action == RevokeSession {
		table = "sessions"
	}
	if action != RevokeDevice && action != RevokeSession {
		return uuid.Nil, ErrInvalidCommand
	}
	var userID uuid.UUID
	query := `SELECT user_id FROM devices WHERE id = $1`
	if table == "sessions" {
		query = `SELECT user_id FROM sessions WHERE id = $1`
	}
	if err := tx.QueryRow(ctx, query, targetID).Scan(&userID); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

func controlNotFoundCode(action Action) string {
	switch action {
	case RevokeDevice:
		return "DEVICE_NOT_FOUND"
	case RevokeSession:
		return "SESSION_NOT_FOUND"
	case DisableUser, EnableUser, RevokeAllSessions, ForcePasswordReset:
		return "USER_NOT_FOUND"
	default:
		return "TARGET_NOT_FOUND"
	}
}

func controlTargetType(action Action) (string, bool) {
	switch action {
	case RevokeDevice:
		return "device", true
	case RevokeSession:
		return "session", true
	case DisableUser, EnableUser, RevokeAllSessions, ForcePasswordReset:
		return "user", true
	default:
		return "", false
	}
}

func controlEventType(action Action) (string, bool) {
	switch action {
	case RevokeDevice:
		return "device_admin_revoked", true
	case RevokeSession:
		return "session_admin_revoked", true
	case RevokeAllSessions:
		return "sessions_admin_revoked_all", true
	case ForcePasswordReset:
		return "account_password_reset", true
	case DisableUser:
		return "account_disabled", true
	case EnableUser:
		return "account_enabled", true
	default:
		return "", false
	}
}
