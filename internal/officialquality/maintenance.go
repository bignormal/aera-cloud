package officialquality

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MaintenanceConfig struct {
	Postgres               *pgxpool.Pool
	Pseudonymizer          *Pseudonymizer
	RawRetentionDays       int
	AggregateRetentionDays int
	MinimumSubjects        int
}

type PostgresMaintenance struct {
	postgres               *pgxpool.Pool
	pseudonymizer          *Pseudonymizer
	rawRetentionDays       int
	aggregateRetentionDays int
	minimumSubjects        int
}

func NewPostgresMaintenance(config MaintenanceConfig) (*PostgresMaintenance, error) {
	if config.Postgres == nil || config.Pseudonymizer == nil || config.RawRetentionDays != 30 ||
		config.AggregateRetentionDays != 180 || config.MinimumSubjects < 10 {
		return nil, errors.New("official quality maintenance configuration is invalid")
	}
	return &PostgresMaintenance{
		postgres: config.Postgres, pseudonymizer: config.Pseudonymizer,
		rawRetentionDays:       config.RawRetentionDays,
		aggregateRetentionDays: config.AggregateRetentionDays,
		minimumSubjects:        config.MinimumSubjects,
	}, nil
}

type aggregateGroup struct {
	PlatformID, DefinitionID, VersionID uuid.UUID
	ReleaseID, ReleaseRevisionID        uuid.UUID
	Day                                 time.Time
	Kind, Result, Latency, Tokens       string
	Crash, Rating, Reason               string
	EventCount, DistinctSubjects        int64
}

func (m *PostgresMaintenance) Run(ctx context.Context, now time.Time) error {
	if m == nil || m.postgres == nil || now.IsZero() {
		return ErrServiceUnavailable
	}
	today := now.UTC().Truncate(24 * time.Hour)
	tx, err := m.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("official quality maintenance begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := m.processPurges(ctx, tx, now.UTC()); err != nil {
		return fmt.Errorf("official quality purge: %w", err)
	}
	groups, err := readAggregateGroups(ctx, tx, today)
	if err != nil {
		return fmt.Errorf("official quality aggregate read: %w", err)
	}
	for _, group := range groups {
		if err := upsertAggregateGroup(ctx, tx, group, m.minimumSubjects, now.UTC()); err != nil {
			return fmt.Errorf("official quality aggregate upsert: %w", err)
		}
	}
	var rawDeleted int64
	if err := tx.QueryRow(ctx, `SELECT delete_official_quality_events_before($1)`, today.AddDate(0, 0, -m.rawRetentionDays)).Scan(&rawDeleted); err != nil {
		return fmt.Errorf("official quality raw retention: %w", err)
	}
	aggregatesDeleted, err := tx.Exec(ctx, `
		DELETE FROM official_quality_daily_aggregates WHERE aggregate_day < $1
	`, today.AddDate(0, 0, -m.aggregateRetentionDays))
	if err != nil {
		return fmt.Errorf("official quality aggregate retention: %w", err)
	}
	if err := recordMaintenanceAudit(ctx, tx, now.UTC(), rawDeleted, aggregatesDeleted.RowsAffected()); err != nil {
		return fmt.Errorf("official quality retention audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("official quality maintenance commit: %w", err)
	}
	return nil
}

func readAggregateGroups(ctx context.Context, tx pgx.Tx, before time.Time) ([]aggregateGroup, error) {
	rows, err := tx.Query(ctx, `
		SELECT event.platform_id, event.definition_id, event.version_id,
			event.release_id, event.release_revision_id, event.event_day,
			event.event_kind, event.result_code, event.latency_bucket,
			event.total_token_bucket, COALESCE(event.crash_code, ''),
			COALESCE(event.feedback_rating, ''), COALESCE(reason.code, ''),
			count(*), count(DISTINCT event.subject_pseudonym)
		FROM official_quality_events event
		LEFT JOIN LATERAL unnest(event.feedback_reason_codes) AS reason(code) ON TRUE
		WHERE event.event_day < $1
		GROUP BY event.platform_id, event.definition_id, event.version_id,
			event.release_id, event.release_revision_id, event.event_day,
			event.event_kind, event.result_code, event.latency_bucket,
			event.total_token_bucket, event.crash_code, event.feedback_rating, reason.code
	`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := make([]aggregateGroup, 0)
	for rows.Next() {
		var group aggregateGroup
		if err := rows.Scan(
			&group.PlatformID, &group.DefinitionID, &group.VersionID,
			&group.ReleaseID, &group.ReleaseRevisionID, &group.Day,
			&group.Kind, &group.Result, &group.Latency, &group.Tokens,
			&group.Crash, &group.Rating, &group.Reason,
			&group.EventCount, &group.DistinctSubjects,
		); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func upsertAggregateGroup(
	ctx context.Context,
	tx pgx.Tx,
	group aggregateGroup,
	minimumSubjects int,
	now time.Time,
) error {
	id := aggregateGroupID(group)
	_, err := tx.Exec(ctx, `
		INSERT INTO official_quality_daily_aggregates (
			id, platform_id, definition_id, version_id, release_id, release_revision_id,
			aggregate_day, event_kind, result_code, latency_bucket, total_token_bucket,
			crash_code, feedback_rating, feedback_reason_code,
			event_count, distinct_subject_count, suppression_threshold, is_suppressed,
			computed_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''),
			$15::bigint, $16::bigint, $17::smallint, $16::bigint < $17::bigint, $18, $18
		)
		ON CONFLICT ON CONSTRAINT official_quality_daily_aggregates_bucket_key
		DO UPDATE SET
			event_count = GREATEST(official_quality_daily_aggregates.event_count, EXCLUDED.event_count),
			distinct_subject_count = GREATEST(official_quality_daily_aggregates.distinct_subject_count, EXCLUDED.distinct_subject_count),
			suppression_threshold = EXCLUDED.suppression_threshold,
			is_suppressed = official_quality_daily_aggregates.is_suppressed AND EXCLUDED.is_suppressed,
			updated_at = GREATEST(official_quality_daily_aggregates.updated_at, EXCLUDED.updated_at)
	`, id, group.PlatformID, group.DefinitionID, group.VersionID,
		group.ReleaseID, group.ReleaseRevisionID, group.Day.UTC(), group.Kind, group.Result,
		group.Latency, group.Tokens, group.Crash, group.Rating, group.Reason,
		group.EventCount, group.DistinctSubjects, minimumSubjects, now)
	return err
}

func aggregateGroupID(group aggregateGroup) uuid.UUID {
	buffer := make([]byte, 0, 16*5+64)
	for _, identifier := range []uuid.UUID{
		group.PlatformID, group.DefinitionID, group.VersionID, group.ReleaseID, group.ReleaseRevisionID,
	} {
		buffer = append(buffer, identifier[:]...)
	}
	day := make([]byte, 8)
	binary.BigEndian.PutUint64(day, uint64(group.Day.UTC().Unix()))
	buffer = append(buffer, day...)
	for _, value := range []string{group.Kind, group.Result, group.Latency, group.Tokens, group.Crash, group.Rating, group.Reason} {
		buffer = append(buffer, 0)
		buffer = append(buffer, value...)
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, buffer)
}

func (m *PostgresMaintenance) processPurges(ctx context.Context, tx pgx.Tx, now time.Time) error {
	rows, err := tx.Query(ctx, `
		SELECT id, user_id, purpose, window_start_day, window_end_day
		FROM official_quality_purge_requests
		WHERE state IN ('pending', 'running')
		  AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
		ORDER BY created_at, id
		FOR UPDATE SKIP LOCKED
	`, now)
	if err != nil {
		return err
	}
	type purgeRequest struct {
		ID, UserID uuid.UUID
		Purpose    string
		StartDay   time.Time
		EndDay     time.Time
	}
	requests := make([]purgeRequest, 0)
	for rows.Next() {
		var request purgeRequest
		if err := rows.Scan(&request.ID, &request.UserID, &request.Purpose, &request.StartDay, &request.EndDay); err != nil {
			rows.Close()
			return err
		}
		requests = append(requests, request)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(requests) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('agentera.official_quality_retention', 'on', true)`); err != nil {
		return err
	}
	for _, request := range requests {
		kind := EventKindMetric
		if request.Purpose == PurposeExplicitFeedback {
			kind = EventKindExplicitFeedback
		} else if request.Purpose != PurposeMetrics {
			return ErrInvalidRequest
		}
		deleted := int64(0)
		for day := request.StartDay.UTC().Truncate(24 * time.Hour); !day.After(request.EndDay.UTC().Truncate(24 * time.Hour)); day = day.AddDate(0, 0, 1) {
			for _, pseudonym := range m.pseudonymizer.Candidates(request.UserID, request.Purpose, day) {
				result, err := tx.Exec(ctx, `
					DELETE FROM official_quality_events
					WHERE event_day = $1 AND event_kind = $2 AND subject_pseudonym = $3
				`, day, kind, pseudonym)
				if err != nil {
					return err
				}
				deleted += result.RowsAffected()
			}
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM official_quality_daily_aggregates
			WHERE aggregate_day BETWEEN $1 AND $2
			  AND event_kind = $3
			  AND is_suppressed = TRUE
		`, request.StartDay, request.EndDay, kind); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE official_quality_purge_requests
			SET state = 'completed', attempt_count = attempt_count + 1,
				next_attempt_at = NULL, updated_at = $2, completed_at = $2
			WHERE id = $1
		`, request.ID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_events (
				id, event_type, object_type, object_id, outcome, metadata, created_at
			) VALUES ($1, 'official_quality_subject_purge_completed',
				'official_quality_purge', $2, 'success',
				jsonb_build_object('purpose', $3::text, 'events_deleted', $4::bigint), $5)
		`, uuid.New(), request.ID, request.Purpose, deleted, now); err != nil {
			return err
		}
	}
	return nil
}

func recordMaintenanceAudit(ctx context.Context, tx pgx.Tx, now time.Time, rawDeleted, aggregatesDeleted int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, object_type, outcome, metadata, created_at
		) VALUES ($1, 'official_quality_retention_completed', 'official_quality_retention',
			'success', jsonb_build_object('raw_deleted', $2::bigint, 'aggregates_deleted', $3::bigint), $4)
	`, uuid.New(), rawDeleted, aggregatesDeleted, now)
	return err
}
