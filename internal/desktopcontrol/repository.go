package desktopcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	heartbeatExpiry = 150 * time.Second
	commandLifetime = 10 * time.Minute
	defaultPageSize = 50
	maxPageSize     = 100
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
	clock    func() time.Time
}

func NewPostgresRepository(postgres *pgxpool.Pool, clocks ...func() time.Time) *PostgresRepository {
	clock := time.Now
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &PostgresRepository{postgres: postgres, clock: clock}
}

func (r *PostgresRepository) AcceptHeartbeat(ctx context.Context, principal DevicePrincipal, heartbeat Heartbeat) (Instance, error) {
	if r == nil || r.postgres == nil {
		return Instance{}, ErrUnavailable
	}
	if err := validatePrincipal(principal); err != nil {
		return Instance{}, err
	}
	if err := validateHeartbeat(heartbeat); err != nil {
		return Instance{}, err
	}

	now := r.now()
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Instance{}, ErrUnavailable
	}
	defer rollback(tx)
	if err := requireActiveDevice(ctx, tx, principal); err != nil {
		return Instance{}, err
	}

	capabilities, err := json.Marshal(nonNilStrings(heartbeat.Capabilities))
	if err != nil {
		return Instance{}, ErrUnavailable
	}
	var healthSummary []byte
	healthStatus := string(HealthUnknown)
	if heartbeat.Health != nil {
		healthSummary, err = json.Marshal(heartbeat.Health)
		if err != nil {
			return Instance{}, ErrUnavailable
		}
		healthStatus = string(healthStatusFor(heartbeat.Health))
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO desktop_control_instances (
			device_id, user_id, organization_id, workspace_id, display_name, instance_type,
			client_version, platform, arch, capabilities, last_heartbeat_at,
			health_status, health_summary, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, 'desktop', $6, $7, $8, $9::jsonb, $10,
			$11, $12::jsonb, $10, $10)
		ON CONFLICT (device_id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			organization_id = EXCLUDED.organization_id,
			workspace_id = EXCLUDED.workspace_id,
			display_name = EXCLUDED.display_name,
			client_version = EXCLUDED.client_version,
			platform = EXCLUDED.platform,
			arch = EXCLUDED.arch,
			capabilities = EXCLUDED.capabilities,
			last_heartbeat_at = EXCLUDED.last_heartbeat_at,
			health_status = CASE WHEN EXCLUDED.health_summary IS NULL
				THEN desktop_control_instances.health_status ELSE EXCLUDED.health_status END,
			health_summary = CASE WHEN EXCLUDED.health_summary IS NULL
				THEN desktop_control_instances.health_summary ELSE EXCLUDED.health_summary END,
			updated_at = EXCLUDED.updated_at
	`, principal.DeviceID, principal.UserID, principal.OrganizationID, principal.WorkspaceID,
		heartbeat.DisplayName, heartbeat.ClientVersion, heartbeat.Platform, heartbeat.Arch,
		capabilities, now, healthStatus, healthSummary)
	if err != nil {
		return Instance{}, mapRepositoryError(err)
	}
	instance, err := readInstance(ctx, tx, principal.DeviceID)
	if err != nil {
		return Instance{}, err
	}
	if err := commit(tx, ctx); err != nil {
		return Instance{}, err
	}
	return instance, nil
}

func (r *PostgresRepository) QueueHealthCheck(ctx context.Context, input QueueHealthCheckCommand) (Command, error) {
	if r == nil || r.postgres == nil {
		return Command{}, ErrUnavailable
	}
	if err := validateQueue(input); err != nil {
		return Command{}, err
	}

	now := r.now()
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Command{}, ErrUnavailable
	}
	defer rollback(tx)
	if err := expireOverdueCommands(ctx, tx, now, nil); err != nil {
		return Command{}, err
	}

	if command, found, err := findCommandByIdempotency(ctx, tx, input.DeviceID, input.IdempotencyKeyHash); err != nil {
		return Command{}, err
	} else if found {
		command.Replayed = true
		if err := commit(tx, ctx); err != nil {
			return Command{}, err
		}
		return command, nil
	}

	instance, err := readInstance(ctx, tx, input.DeviceID)
	if err != nil {
		return Command{}, err
	}
	if instance.UserStatus != "active" || instance.DeviceStatus != "active" ||
		instance.EffectiveStatus(now) != EffectiveOnline || !hasCapability(instance.Capabilities, CapabilityHealthRead) {
		return Command{}, ErrConflict
	}

	command := Command{
		ID: uuid.New(), DeviceID: input.DeviceID, Type: CommandHealthCheck,
		RequiredCapability: CapabilityHealthRead,
		IdempotencyKeyHash: bytes.Clone(input.IdempotencyKeyHash), State: CommandQueued,
		ExpiresAt: now.Add(commandLifetime), CreatedByAdminID: input.Actor.AdminID,
		RequestID: input.Actor.RequestID, CreatedAt: now, UpdatedAt: now,
	}
	var insertedID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO desktop_control_commands (
			id, device_id, type, required_capability, idempotency_key_hash, state,
			expires_at, created_by_admin_id, request_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
		ON CONFLICT (device_id, idempotency_key_hash) DO NOTHING
		RETURNING id
	`, command.ID, command.DeviceID, command.Type, command.RequiredCapability,
		command.IdempotencyKeyHash, command.State, command.ExpiresAt, command.CreatedByAdminID,
		command.RequestID, command.CreatedAt).Scan(&insertedID)
	if errors.Is(err, pgx.ErrNoRows) {
		replayed, found, findErr := findCommandByIdempotency(ctx, tx, input.DeviceID, input.IdempotencyKeyHash)
		if findErr != nil || !found {
			return Command{}, ErrUnavailable
		}
		replayed.Replayed = true
		if err := commit(tx, ctx); err != nil {
			return Command{}, err
		}
		return replayed, nil
	}
	if err != nil {
		return Command{}, mapRepositoryError(err)
	}
	command.ID = insertedID
	if err := recordCommandAudit(ctx, tx, command, "desktop_health_check_requested", input.Actor.ServiceSubject, nil, now); err != nil {
		return Command{}, err
	}
	if err := commit(tx, ctx); err != nil {
		return Command{}, err
	}
	return command, nil
}

func (r *PostgresRepository) ClaimNextCommand(ctx context.Context, principal DevicePrincipal) (*Command, error) {
	if r == nil || r.postgres == nil {
		return nil, ErrUnavailable
	}
	if err := validatePrincipal(principal); err != nil {
		return nil, err
	}
	now := r.now()
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rollback(tx)
	if err := requireActiveDevice(ctx, tx, principal); err != nil {
		return nil, err
	}
	instance, err := readInstance(ctx, tx, principal.DeviceID)
	if err != nil {
		return nil, err
	}
	if !hasCapability(instance.Capabilities, CapabilityHealthRead) {
		if err := commit(tx, ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err := expireOverdueCommands(ctx, tx, now, &principal.DeviceID); err != nil {
		return nil, err
	}
	var commandID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM desktop_control_commands
		WHERE device_id = $1 AND state = 'queued' AND expires_at > $2
		ORDER BY created_at, id
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, principal.DeviceID, now).Scan(&commandID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := commit(tx, ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	_, err = tx.Exec(ctx, `
		UPDATE desktop_control_commands
		SET state = 'claimed', claimed_at = $2, updated_at = $2
		WHERE id = $1
	`, commandID, now)
	if err != nil {
		return nil, mapRepositoryError(err)
	}
	command, err := readCommand(ctx, tx, commandID)
	if err != nil {
		return nil, err
	}
	if err := commit(tx, ctx); err != nil {
		return nil, err
	}
	return &command, nil
}

func (r *PostgresRepository) AdvanceCommand(ctx context.Context, principal DevicePrincipal, commandID uuid.UUID, result CommandResult) (Command, error) {
	if r == nil || r.postgres == nil {
		return Command{}, ErrUnavailable
	}
	if err := validatePrincipal(principal); err != nil {
		return Command{}, err
	}
	if commandID == uuid.Nil {
		return Command{}, ErrInvalidInput
	}
	now := r.now()
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Command{}, ErrUnavailable
	}
	defer rollback(tx)
	if err := requireActiveDevice(ctx, tx, principal); err != nil {
		return Command{}, err
	}
	if err := expireOverdueCommands(ctx, tx, now, &principal.DeviceID); err != nil {
		return Command{}, err
	}
	command, err := readCommandForDevice(ctx, tx, commandID, principal.DeviceID, principal.UserID)
	if err != nil {
		return Command{}, err
	}
	if command.State == CommandSucceeded || command.State == CommandFailed {
		if sameCommandResult(command, result) {
			command.Replayed = true
			if err := commit(tx, ctx); err != nil {
				return Command{}, err
			}
			return command, nil
		}
		return Command{}, ErrConflict
	}
	if !CanTransition(command.State, result.State) {
		return Command{}, ErrInvalidTransition
	}
	if err := validateResult(result); err != nil {
		return Command{}, err
	}

	var summaryJSON []byte
	if result.Summary != nil {
		summaryJSON, err = json.Marshal(result.Summary)
		if err != nil {
			return Command{}, ErrUnavailable
		}
	}
	if result.State == CommandRunning {
		_, err = tx.Exec(ctx, `
			UPDATE desktop_control_commands
			SET state = 'running', started_at = $2, updated_at = $2
			WHERE id = $1
		`, commandID, now)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE desktop_control_commands
			SET state = $2, completed_at = $3, result_code = $4, result_summary = $5::jsonb, updated_at = $3
			WHERE id = $1
		`, commandID, result.State, now, result.Code, summaryJSON)
	}
	if err != nil {
		return Command{}, mapRepositoryError(err)
	}
	if result.State == CommandSucceeded || result.State == CommandFailed {
		if _, err := tx.Exec(ctx, `
			UPDATE desktop_control_instances
			SET health_status = $2, health_summary = $3::jsonb, updated_at = $4
			WHERE device_id = $1
		`, principal.DeviceID, healthStatusFor(result.Summary), summaryJSON, now); err != nil {
			return Command{}, ErrUnavailable
		}
		completedCommand := command
		completedCommand.State = result.State
		if err := recordCommandAudit(ctx, tx, completedCommand, "desktop_health_check_completed", "aera-cloud-desktop-control", &result.Code, now); err != nil {
			return Command{}, err
		}
	}
	command, err = readCommand(ctx, tx, commandID)
	if err != nil {
		return Command{}, err
	}
	if err := commit(tx, ctx); err != nil {
		return Command{}, err
	}
	return command, nil
}

func (r *PostgresRepository) ListInstances(ctx context.Context, filter InstanceFilter) (InstancePage, error) {
	if r == nil || r.postgres == nil {
		return InstancePage{}, ErrUnavailable
	}
	if err := validateInstanceFilter(filter); err != nil {
		return InstancePage{}, err
	}
	now := r.now()
	limit := filter.Limit
	if limit == 0 {
		limit = defaultPageSize
	}
	status := ""
	if filter.EffectiveStatus != nil {
		status = string(*filter.EffectiveStatus)
	}
	rows, err := r.postgres.Query(ctx, `
		WITH projected AS (
			SELECT i.device_id, i.user_id, i.organization_id, i.workspace_id,
				i.display_name, i.client_version, i.platform, i.arch, i.capabilities,
				i.last_heartbeat_at, i.health_status, i.health_summary, i.created_at, i.updated_at,
				u.status AS user_status, d.status AS device_status,
				CASE
					WHEN u.status = 'disabled' THEN 'disabled'
					WHEN u.status = 'pending_deletion' THEN 'pending'
					WHEN d.status = 'revoked' THEN 'revoked'
					WHEN d.status = 'inactive' THEN 'pending'
					WHEN i.last_heartbeat_at IS NULL OR i.last_heartbeat_at < $1::timestamptz - INTERVAL '150 seconds' THEN 'offline'
					ELSE 'online'
				END AS effective_status
			FROM desktop_control_instances i
			JOIN users u ON u.id = i.user_id
			JOIN devices d ON d.id = i.device_id AND d.user_id = i.user_id
		)
		SELECT device_id, user_id, organization_id, workspace_id, display_name, client_version,
			platform, arch, capabilities, last_heartbeat_at, health_status, health_summary,
			created_at, updated_at, user_status, device_status, count(*) OVER()
		FROM projected
		WHERE ($2::uuid IS NULL OR device_id = $2)
		  AND ($3::uuid IS NULL OR user_id = $3)
		  AND ($4::uuid IS NULL OR organization_id = $4)
		  AND ($5 = '' OR platform = $5)
		  AND ($6 = '' OR client_version = $6)
		  AND ($7 = '' OR effective_status = $7)
		ORDER BY updated_at DESC, device_id
		LIMIT $8 OFFSET $9
	`, now, nullableUUID(filter.DeviceID), nullableUUID(filter.UserID), nullableUUID(filter.OrganizationID),
		filter.Platform, filter.ClientVersion, status, limit, filter.Offset)
	if err != nil {
		return InstancePage{}, ErrUnavailable
	}
	defer rows.Close()
	page := InstancePage{Items: make([]Instance, 0, limit)}
	for rows.Next() {
		instance, total, err := scanInstanceWithTotal(rows)
		if err != nil {
			return InstancePage{}, err
		}
		page.Items = append(page.Items, instance)
		page.Total = total
	}
	if err := rows.Err(); err != nil {
		return InstancePage{}, ErrUnavailable
	}
	return page, nil
}

func (r *PostgresRepository) ListUserInstances(ctx context.Context, userID uuid.UUID, filter InstanceFilter) (InstancePage, error) {
	if userID == uuid.Nil {
		return InstancePage{}, ErrInvalidInput
	}
	if filter.UserID != nil && *filter.UserID != userID {
		return InstancePage{}, ErrInvalidInput
	}
	filter.UserID = &userID
	return r.ListInstances(ctx, filter)
}

func (r *PostgresRepository) GetInstance(ctx context.Context, deviceID uuid.UUID) (Instance, error) {
	if r == nil || r.postgres == nil {
		return Instance{}, ErrUnavailable
	}
	if deviceID == uuid.Nil {
		return Instance{}, ErrInvalidInput
	}
	return readInstance(ctx, r.postgres, deviceID)
}

func (r *PostgresRepository) GetCommand(ctx context.Context, commandID uuid.UUID) (Command, error) {
	if r == nil || r.postgres == nil {
		return Command{}, ErrUnavailable
	}
	if commandID == uuid.Nil {
		return Command{}, ErrInvalidInput
	}
	now := r.now()
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Command{}, ErrUnavailable
	}
	defer rollback(tx)
	if err := expireOverdueCommands(ctx, tx, now, nil); err != nil {
		return Command{}, err
	}
	command, err := readCommand(ctx, tx, commandID)
	if err != nil {
		return Command{}, err
	}
	if err := commit(tx, ctx); err != nil {
		return Command{}, err
	}
	return command, nil
}

func (r *PostgresRepository) now() time.Time {
	if r.clock == nil {
		return time.Now().UTC()
	}
	return r.clock().UTC()
}

func requireActiveDevice(ctx context.Context, tx pgx.Tx, principal DevicePrincipal) error {
	var userStatus, deviceStatus string
	err := tx.QueryRow(ctx, `
		SELECT u.status, d.status
		FROM users u
		JOIN devices d ON d.user_id = u.id
		WHERE u.id = $1 AND d.id = $2
		FOR UPDATE OF u, d
	`, principal.UserID, principal.DeviceID).Scan(&userStatus, &deviceStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return ErrUnavailable
	}
	if userStatus != "active" || deviceStatus != "active" {
		return ErrConflict
	}
	return nil
}

func readInstance(ctx context.Context, source interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, deviceID uuid.UUID) (Instance, error) {
	return scanInstance(source.QueryRow(ctx, instanceQuery+` WHERE i.device_id = $1`, deviceID))
}

const instanceQuery = `
	SELECT i.device_id, i.user_id, i.organization_id, i.workspace_id, i.display_name,
		i.client_version, i.platform, i.arch, i.capabilities, i.last_heartbeat_at,
		i.health_status, i.health_summary, i.created_at, i.updated_at,
		u.status, d.status
	FROM desktop_control_instances i
	JOIN users u ON u.id = i.user_id
	JOIN devices d ON d.id = i.device_id AND d.user_id = i.user_id
`

func scanInstance(row interface{ Scan(...any) error }) (Instance, error) {
	var instance Instance
	var organizationID, workspaceID pgtype.UUID
	var lastHeartbeat pgtype.Timestamptz
	var capabilitiesJSON, summaryJSON []byte
	var healthStatus string
	if err := row.Scan(
		&instance.DeviceID, &instance.UserID, &organizationID, &workspaceID, &instance.DisplayName,
		&instance.ClientVersion, &instance.Platform, &instance.Arch, &capabilitiesJSON, &lastHeartbeat,
		&healthStatus, &summaryJSON, &instance.CreatedAt, &instance.UpdatedAt,
		&instance.UserStatus, &instance.DeviceStatus,
	); errors.Is(err, pgx.ErrNoRows) {
		return Instance{}, ErrNotFound
	} else if err != nil {
		return Instance{}, ErrUnavailable
	}
	instance.OrganizationID = uuidPointer(organizationID)
	instance.WorkspaceID = uuidPointer(workspaceID)
	if lastHeartbeat.Valid {
		value := lastHeartbeat.Time.UTC()
		instance.LastHeartbeatAt = &value
	}
	instance.Capabilities = make([]string, 0)
	if err := json.Unmarshal(capabilitiesJSON, &instance.Capabilities); err != nil {
		return Instance{}, ErrUnavailable
	}
	instance.HealthStatus = HealthStatus(healthStatus)
	if len(summaryJSON) > 0 {
		var summary HealthSummary
		if err := json.Unmarshal(summaryJSON, &summary); err != nil {
			return Instance{}, ErrUnavailable
		}
		instance.HealthSummary = &summary
	}
	return instance, nil
}

func scanInstanceWithTotal(row interface{ Scan(...any) error }) (Instance, int, error) {
	var instance Instance
	var organizationID, workspaceID pgtype.UUID
	var lastHeartbeat pgtype.Timestamptz
	var capabilitiesJSON, summaryJSON []byte
	var healthStatus string
	var total int
	if err := row.Scan(
		&instance.DeviceID, &instance.UserID, &organizationID, &workspaceID, &instance.DisplayName,
		&instance.ClientVersion, &instance.Platform, &instance.Arch, &capabilitiesJSON, &lastHeartbeat,
		&healthStatus, &summaryJSON, &instance.CreatedAt, &instance.UpdatedAt,
		&instance.UserStatus, &instance.DeviceStatus, &total,
	); err != nil {
		return Instance{}, 0, mapRepositoryError(err)
	}
	instance.OrganizationID = uuidPointer(organizationID)
	instance.WorkspaceID = uuidPointer(workspaceID)
	if lastHeartbeat.Valid {
		value := lastHeartbeat.Time.UTC()
		instance.LastHeartbeatAt = &value
	}
	if err := json.Unmarshal(capabilitiesJSON, &instance.Capabilities); err != nil {
		return Instance{}, 0, ErrUnavailable
	}
	instance.HealthStatus = HealthStatus(healthStatus)
	if len(summaryJSON) > 0 {
		var summary HealthSummary
		if err := json.Unmarshal(summaryJSON, &summary); err != nil {
			return Instance{}, 0, ErrUnavailable
		}
		instance.HealthSummary = &summary
	}
	return instance, total, nil
}

func findCommandByIdempotency(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, keyHash []byte) (Command, bool, error) {
	command, err := scanCommand(tx.QueryRow(ctx, commandQuery+`
		WHERE c.device_id = $1 AND c.idempotency_key_hash = $2
		FOR UPDATE
	`, deviceID, keyHash))
	if errors.Is(err, ErrNotFound) {
		return Command{}, false, nil
	}
	if err != nil {
		return Command{}, false, err
	}
	return command, true, nil
}

func readCommand(ctx context.Context, source interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, commandID uuid.UUID) (Command, error) {
	return scanCommand(source.QueryRow(ctx, commandQuery+` WHERE c.id = $1`, commandID))
}

func readCommandForDevice(ctx context.Context, tx pgx.Tx, commandID, deviceID, userID uuid.UUID) (Command, error) {
	return scanCommand(tx.QueryRow(ctx, commandQuery+`
		JOIN devices owner_device ON owner_device.id = c.device_id AND owner_device.user_id = $2
		WHERE c.id = $1 AND c.device_id = $3
		FOR UPDATE
	`, commandID, userID, deviceID))
}

const commandQuery = `
	SELECT c.id, c.device_id, c.type, c.required_capability, c.idempotency_key_hash,
		c.state, c.expires_at, c.claimed_at, c.started_at, c.completed_at,
		c.result_code, c.result_summary, c.created_by_admin_id, c.request_id,
		c.created_at, c.updated_at
	FROM desktop_control_commands c
`

func scanCommand(row interface{ Scan(...any) error }) (Command, error) {
	var command Command
	var claimedAt, startedAt, completedAt pgtype.Timestamptz
	var resultCode pgtype.Text
	var summaryJSON []byte
	if err := row.Scan(
		&command.ID, &command.DeviceID, &command.Type, &command.RequiredCapability,
		&command.IdempotencyKeyHash, &command.State, &command.ExpiresAt, &claimedAt,
		&startedAt, &completedAt, &resultCode, &summaryJSON, &command.CreatedByAdminID,
		&command.RequestID, &command.CreatedAt, &command.UpdatedAt,
	); errors.Is(err, pgx.ErrNoRows) {
		return Command{}, ErrNotFound
	} else if err != nil {
		return Command{}, ErrUnavailable
	}
	command.IdempotencyKeyHash = bytes.Clone(command.IdempotencyKeyHash)
	if claimedAt.Valid {
		value := claimedAt.Time.UTC()
		command.ClaimedAt = &value
	}
	if startedAt.Valid {
		value := startedAt.Time.UTC()
		command.StartedAt = &value
	}
	if completedAt.Valid {
		value := completedAt.Time.UTC()
		command.CompletedAt = &value
	}
	if resultCode.Valid {
		value := HealthCode(resultCode.String)
		command.ResultCode = &value
	}
	if len(summaryJSON) > 0 {
		var summary HealthSummary
		if err := json.Unmarshal(summaryJSON, &summary); err != nil {
			return Command{}, ErrUnavailable
		}
		command.ResultSummary = &summary
	}
	return command, nil
}

func expireOverdueCommands(ctx context.Context, tx pgx.Tx, now time.Time, deviceID *uuid.UUID) error {
	query := `
		UPDATE desktop_control_commands
		SET state = 'expired', completed_at = $1, updated_at = $1
		WHERE state IN ('queued', 'claimed', 'running') AND expires_at <= $1
	`
	args := []any{now}
	if deviceID != nil {
		query += ` AND device_id = $2`
		args = append(args, *deviceID)
	}
	query += ` RETURNING id, device_id, created_by_admin_id, request_id`
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return ErrUnavailable
	}
	expired := make([]Command, 0)
	for rows.Next() {
		var command Command
		if err := rows.Scan(&command.ID, &command.DeviceID, &command.CreatedByAdminID, &command.RequestID); err != nil {
			rows.Close()
			return ErrUnavailable
		}
		command.State = CommandExpired
		expired = append(expired, command)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ErrUnavailable
	}
	for _, command := range expired {
		if err := recordCommandAudit(ctx, tx, command, "desktop_health_check_completed", "aera-cloud-desktop-control", nil, now); err != nil {
			return err
		}
	}
	return nil
}

func recordCommandAudit(ctx context.Context, tx pgx.Tx, command Command, eventType, operator string, resultCode *HealthCode, now time.Time) error {
	metadata := map[string]any{
		"admin_id":   command.CreatedByAdminID.String(),
		"device_id":  command.DeviceID.String(),
		"command_id": command.ID.String(),
		"request_id": command.RequestID,
		"state":      string(command.State),
		"at":         now.UTC().Format(time.RFC3339Nano),
	}
	if resultCode != nil {
		metadata["result_code"] = string(*resultCode)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, device_id, object_type, object_id, outcome,
			request_id, operator_identity, metadata, created_at
		) VALUES ($1, $2, $3, 'desktop_control_command', $4, 'success',
			$5, $6, $7::jsonb, $8)
	`, uuid.New(), eventType, command.DeviceID, command.ID, command.RequestID, operator, string(encoded), now); err != nil {
		return ErrUnavailable
	}
	return nil
}

func validateInstanceFilter(filter InstanceFilter) error {
	if filter.Limit < 0 || filter.Limit > maxPageSize || filter.Offset < 0 ||
		!boundedOptionalText(filter.Platform, 16) || !boundedOptionalText(filter.ClientVersion, 64) {
		return ErrInvalidInput
	}
	if filter.EffectiveStatus != nil {
		switch *filter.EffectiveStatus {
		case EffectivePending, EffectiveRevoked, EffectiveDisabled, EffectiveOnline, EffectiveOffline:
		default:
			return ErrInvalidInput
		}
	}
	return nil
}

func boundedOptionalText(value string, limit int) bool {
	return value == "" || boundedText(value, limit)
}

func hasCapability(capabilities []string, target string) bool {
	for _, capability := range capabilities {
		if capability == target {
			return true
		}
	}
	return false
}

func sameCommandResult(command Command, result CommandResult) bool {
	if command.State != result.State || command.ResultCode == nil || *command.ResultCode != result.Code {
		return false
	}
	if command.ResultSummary == nil || result.Summary == nil {
		return command.ResultSummary == nil && result.Summary == nil
	}
	left, leftErr := json.Marshal(command.ResultSummary)
	right, rightErr := json.Marshal(result.Summary)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func nonNilStrings(value []string) []string {
	if value == nil {
		return []string{}
	}
	return value
}

func nullableUUID(value *uuid.UUID) any {
	if value == nil {
		return nil
	}
	return *value
}

func uuidPointer(value pgtype.UUID) *uuid.UUID {
	if !value.Valid {
		return nil
	}
	result := uuid.UUID(value.Bytes)
	return &result
}

func rollback(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
}

func commit(tx pgx.Tx, ctx context.Context) error {
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func mapRepositoryError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return ErrUnavailable
}
