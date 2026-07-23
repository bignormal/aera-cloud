package officialquality

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
}

func (r *PostgresRepository) ActiveConsent(
	ctx context.Context,
	userID uuid.UUID,
	purpose string,
	consentVersion int64,
) (bool, error) {
	if r == nil || r.postgres == nil || userID == uuid.Nil || !validPurpose(purpose) || consentVersion <= 0 {
		return false, ErrInvalidRequest
	}
	return activeConsent(ctx, r.postgres, userID, purpose, consentVersion)
}

func (r *PostgresRepository) RecordConsent(
	ctx context.Context,
	command RecordConsentCommand,
) (ConsentReceipt, error) {
	if r == nil || r.postgres == nil || command.ReceiptID == uuid.Nil || !command.Principal.valid() ||
		!validPurpose(command.Purpose) || command.ConsentVersion <= 0 ||
		(command.State != ConsentGranted && command.State != ConsentRevoked) || command.RecordedAt.IsZero() {
		return ConsentReceipt{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var latest ConsentReceipt
	err = tx.QueryRow(ctx, `
		SELECT id, purpose, consent_version, state, revision, recorded_at
		FROM official_quality_consent_receipts
		WHERE user_id = $1 AND purpose = $2
		ORDER BY revision DESC
		LIMIT 1
		FOR UPDATE
	`, command.Principal.UserID, command.Purpose).Scan(
		&latest.ID, &latest.Purpose, &latest.ConsentVersion, &latest.State, &latest.Revision, &latest.RecordedAt,
	)
	if err == nil && latest.ConsentVersion == command.ConsentVersion && latest.State == command.State {
		latest.Replayed = true
		return latest, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	revision := latest.Revision + 1
	receipt := ConsentReceipt{
		ID: command.ReceiptID, Purpose: command.Purpose, ConsentVersion: command.ConsentVersion,
		State: command.State, Revision: revision, RecordedAt: command.RecordedAt.UTC(),
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO official_quality_consent_receipts (
			id, user_id, purpose, consent_version, state, revision, recorded_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, receipt.ID, command.Principal.UserID, receipt.Purpose, receipt.ConsentVersion,
		receipt.State, receipt.Revision, receipt.RecordedAt); err != nil {
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	if receipt.State == ConsentRevoked {
		if _, err := tx.Exec(ctx, `
			INSERT INTO official_quality_purge_requests (
				id, user_id, purpose, state, window_start_day, window_end_day,
				attempt_count, next_attempt_at, created_at, updated_at, completed_at
			) VALUES ($1, $2, $3, 'pending', $4, $5, 0, $6, $6, $6, NULL)
			ON CONFLICT (user_id, purpose) WHERE state IN ('pending', 'running')
			DO UPDATE SET
				state = 'pending',
				window_start_day = LEAST(official_quality_purge_requests.window_start_day, EXCLUDED.window_start_day),
				window_end_day = GREATEST(official_quality_purge_requests.window_end_day, EXCLUDED.window_end_day),
				attempt_count = 0,
				next_attempt_at = EXCLUDED.next_attempt_at,
				updated_at = EXCLUDED.updated_at,
				completed_at = NULL
		`, uuid.New(), command.Principal.UserID, command.Purpose,
			command.RecordedAt.UTC().AddDate(0, 0, -maximumEventAgeInDays), command.RecordedAt.UTC(),
			command.RecordedAt.UTC()); err != nil {
			return ConsentReceipt{}, ErrServiceUnavailable
		}
	}
	metadata, err := json.Marshal(map[string]any{
		"purpose": command.Purpose, "consent_version": command.ConsentVersion, "revision": revision,
	})
	if err != nil {
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	eventType := "official_quality_consent_granted"
	if command.State == ConsentRevoked {
		eventType = "official_quality_consent_revoked"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, device_id, object_type, object_id,
			outcome, reason_code, request_id, ip_hmac, metadata, created_at
		) VALUES ($1, $2, $3, $4, 'official_quality_consent', $5,
			'success', NULL, NULL, NULL, $6::jsonb, $7)
	`, uuid.New(), eventType, command.Principal.UserID, command.Principal.DeviceID,
		receipt.ID, string(metadata), command.RecordedAt.UTC()); err != nil {
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	return receipt, nil
}

func (r *PostgresRepository) ActiveDeviceKey(ctx context.Context, principal Principal) (ed25519.PublicKey, error) {
	if r == nil || r.postgres == nil || !principal.valid() {
		return nil, ErrInvalidRequest
	}
	var publicKey []byte
	err := r.postgres.QueryRow(ctx, `
		SELECT public_key
		FROM devices
		WHERE id = $1 AND user_id = $2 AND status = 'active'
	`, principal.DeviceID, principal.UserID).Scan(&publicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIneligible
	}
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrServiceUnavailable
	}
	return ed25519.PublicKey(bytes.Clone(publicKey)), nil
}

func (r *PostgresRepository) EligibleBinding(
	ctx context.Context,
	principal Principal,
	envelope PublicEnvelope,
) (bool, error) {
	if r == nil || r.postgres == nil || !principal.valid() || envelope.BindingProof == uuid.Nil {
		return false, ErrInvalidRequest
	}
	return eligibleBinding(ctx, r.postgres, principal, envelope)
}

func (r *PostgresRepository) AcceptEvent(ctx context.Context, command AcceptEventCommand) (bool, error) {
	if r == nil || r.postgres == nil || !validAcceptCommand(command) {
		return false, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	active, err := activeConsent(
		ctx, tx, command.Principal.UserID, command.Envelope.Purpose(), command.Envelope.ConsentVersion,
	)
	if err != nil {
		return false, ErrServiceUnavailable
	}
	if !active {
		return false, ErrConsentRequired
	}
	eligible, err := eligibleBinding(ctx, tx, command.Principal, command.Envelope)
	if err != nil {
		return false, ErrServiceUnavailable
	}
	if !eligible {
		return false, ErrIneligible
	}

	envelope := command.Envelope
	inserted, err := tx.Exec(ctx, `
		INSERT INTO official_quality_events (
			event_id, protocol_version, consent_version, platform_id,
			definition_id, version_id, release_id, release_revision_id,
			desktop_version, runtime_version, event_day, subject_pseudonym,
			binding_proof_digest, event_kind, result_code, latency_bucket,
			total_token_bucket, crash_code, feedback_rating,
			feedback_reason_codes, device_signature, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16,
			$17, NULLIF($18, ''), NULLIF($19, ''), $20, $21, $22
		)
		ON CONFLICT DO NOTHING
	`, envelope.EventID, envelope.ProtocolVersion, envelope.ConsentVersion, envelope.PlatformID,
		envelope.DefinitionID, envelope.VersionID, envelope.ReleaseID, envelope.ReleaseRevisionID,
		envelope.DesktopVersion, envelope.RuntimeVersion, envelope.Day(), command.SubjectPseudonym,
		command.BindingProofDigest, envelope.Kind, envelope.Result, envelope.LatencyBucket,
		envelope.TotalTokenBucket, envelope.CrashCode, envelope.FeedbackRating,
		envelope.FeedbackReasonCodes, envelope.DeviceSignature, command.AcceptedAt.UTC())
	if err != nil {
		return false, ErrServiceUnavailable
	}
	if inserted.RowsAffected() == 0 {
		replayed, replayErr := exactEventExists(ctx, tx, command)
		if replayErr != nil {
			return false, ErrServiceUnavailable
		}
		if replayed {
			return true, nil
		}
		return false, ErrConflict
	}

	metadata, err := json.Marshal(map[string]string{
		"platform_id": envelope.PlatformID.String(), "agent_definition_id": envelope.DefinitionID.String(),
		"agent_version_id": envelope.VersionID.String(), "official_release_id": envelope.ReleaseID.String(),
		"official_release_revision_id": envelope.ReleaseRevisionID.String(), "event_kind": envelope.Kind,
		"result_code": envelope.Result,
	})
	if err != nil {
		return false, ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, device_id, object_type, object_id,
			outcome, reason_code, request_id, ip_hmac, metadata, created_at
		) VALUES ($1, 'official_quality_event_accepted', NULL, NULL,
			'official_quality_event', $2, 'success', NULL, NULL, NULL, $3::jsonb, $4)
	`, uuid.New(), envelope.EventID, string(metadata), command.AcceptedAt.UTC()); err != nil {
		return false, ErrServiceUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return false, ErrServiceUnavailable
	}
	return false, nil
}

type qualityQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func activeConsent(
	ctx context.Context,
	queryer qualityQueryRower,
	userID uuid.UUID,
	purpose string,
	consentVersion int64,
) (bool, error) {
	var active bool
	err := queryer.QueryRow(ctx, `
		SELECT state = 'granted' AND consent_version = $3
		FROM official_quality_consent_receipts
		WHERE user_id = $1 AND purpose = $2
		ORDER BY revision DESC
		LIMIT 1
	`, userID, purpose, consentVersion).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return active, err
}

func eligibleBinding(
	ctx context.Context,
	queryer qualityQueryRower,
	principal Principal,
	envelope PublicEnvelope,
) (bool, error) {
	var eligible bool
	err := queryer.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM runtime_binding_records binding
			JOIN installations installation
			  ON installation.id = binding.agent_installation_id
			JOIN devices device
			  ON device.id = binding.device_id
			JOIN agent_versions version
			  ON version.id = binding.agent_version_id
			JOIN agent_definitions definition
			  ON definition.id = version.definition_id
			JOIN official_release_revisions revision
			  ON revision.id = binding.official_release_revision_id
			 AND revision.agent_version_id = binding.agent_version_id
			JOIN official_releases release
			  ON release.id = revision.release_id
			 AND release.id = installation.official_release_id
			 AND release.platform_id = definition.platform_id
			 AND release.definition_id = definition.id
			WHERE binding.id = $1
			  AND binding.tenant_id = $2
			  AND binding.owner_scope = 'USER'
			  AND binding.owner_id = $3
			  AND binding.device_id = $4
			  AND binding.runtime_version = $5
			  AND binding.official_release_revision_id = $6
			  AND binding.agent_version_id = $7
			  AND installation.tenant_id = $2
			  AND installation.owner_scope = 'USER'
			  AND installation.owner_id = $3
			  AND installation.device_id = $4
			  AND installation.update_policy = 'managed'
			  AND installation.status = 'active'
			  AND device.user_id = $3
			  AND device.status = 'active'
			  AND version.owner_scope = 'PLATFORM'
			  AND version.platform_id = $8
			  AND version.definition_id = $9
			  AND definition.owner_scope = 'PLATFORM'
			  AND definition.platform_id = $8
			  AND release.id = $10
		)
	`, envelope.BindingProof, principal.PersonalSpaceID, principal.UserID, principal.DeviceID,
		envelope.RuntimeVersion, envelope.ReleaseRevisionID, envelope.VersionID, envelope.PlatformID,
		envelope.DefinitionID, envelope.ReleaseID).Scan(&eligible)
	return eligible, err
}

func exactEventExists(ctx context.Context, queryer qualityQueryRower, command AcceptEventCommand) (bool, error) {
	var existing struct {
		ProtocolVersion, ConsentVersion int64
		PlatformID, DefinitionID        uuid.UUID
		VersionID, ReleaseID            uuid.UUID
		ReleaseRevisionID               uuid.UUID
		DesktopVersion, RuntimeVersion  string
		EventDay                        time.Time
		Subject, BindingDigest          []byte
		Kind, Result, Latency, Tokens   string
		Crash, Rating                   *string
		Reasons, Signature              []byte
	}
	var reasons []string
	err := queryer.QueryRow(ctx, `
		SELECT protocol_version, consent_version, platform_id, definition_id,
			version_id, release_id, release_revision_id, desktop_version, runtime_version,
			event_day, subject_pseudonym, binding_proof_digest, event_kind, result_code,
			latency_bucket, total_token_bucket, crash_code, feedback_rating,
			feedback_reason_codes, device_signature
		FROM official_quality_events
		WHERE event_id = $1
	`, command.Envelope.EventID).Scan(
		&existing.ProtocolVersion, &existing.ConsentVersion, &existing.PlatformID, &existing.DefinitionID,
		&existing.VersionID, &existing.ReleaseID, &existing.ReleaseRevisionID,
		&existing.DesktopVersion, &existing.RuntimeVersion, &existing.EventDay,
		&existing.Subject, &existing.BindingDigest, &existing.Kind, &existing.Result,
		&existing.Latency, &existing.Tokens, &existing.Crash, &existing.Rating,
		&reasons, &existing.Signature,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	e := command.Envelope
	return existing.ProtocolVersion == int64(e.ProtocolVersion) && existing.ConsentVersion == e.ConsentVersion &&
		existing.PlatformID == e.PlatformID && existing.DefinitionID == e.DefinitionID &&
		existing.VersionID == e.VersionID && existing.ReleaseID == e.ReleaseID &&
		existing.ReleaseRevisionID == e.ReleaseRevisionID && existing.DesktopVersion == e.DesktopVersion &&
		existing.RuntimeVersion == e.RuntimeVersion && existing.EventDay.Format("2006-01-02") == e.EventDay &&
		bytes.Equal(existing.Subject, command.SubjectPseudonym) &&
		bytes.Equal(existing.BindingDigest, command.BindingProofDigest) && existing.Kind == e.Kind &&
		existing.Result == e.Result && existing.Latency == e.LatencyBucket && existing.Tokens == e.TotalTokenBucket &&
		equalOptional(existing.Crash, e.CrashCode) && equalOptional(existing.Rating, e.FeedbackRating) &&
		equalStrings(reasons, e.FeedbackReasonCodes) && bytes.Equal(existing.Signature, e.DeviceSignature), nil
}

func validAcceptCommand(command AcceptEventCommand) bool {
	return command.Principal.valid() && command.Envelope.valid(command.AcceptedAt) &&
		len(command.SubjectPseudonym) == 32 && len(command.BindingProofDigest) == 32 && !command.AcceptedAt.IsZero()
}

func validPurpose(purpose string) bool {
	return purpose == PurposeMetrics || purpose == PurposeExplicitFeedback
}

func equalOptional(value *string, expected string) bool {
	return (value == nil && expected == "") || (value != nil && *value == expected)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
