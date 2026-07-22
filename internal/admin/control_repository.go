package admin

import (
	"context"
	"errors"
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
	return &ControlRepository{postgres: postgres, identities: identities, protector: protector, clock: clock}, nil
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
