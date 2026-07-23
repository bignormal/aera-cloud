package officialquality

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	maximumAggregatePageSize   = 100
	maximumAggregateWindowDays = 31
)

type Aggregate struct {
	ID                   uuid.UUID `json:"id"`
	PlatformID           uuid.UUID `json:"platform_id"`
	DefinitionID         uuid.UUID `json:"definition_id"`
	VersionID            uuid.UUID `json:"version_id"`
	ReleaseID            uuid.UUID `json:"release_id"`
	ReleaseRevisionID    uuid.UUID `json:"release_revision_id"`
	AggregateDay         time.Time `json:"aggregate_day"`
	EventKind            string    `json:"event_kind"`
	ResultCode           string    `json:"result_code"`
	LatencyBucket        string    `json:"latency_bucket"`
	TotalTokenBucket     string    `json:"total_token_bucket"`
	CrashCode            string    `json:"crash_code,omitempty"`
	FeedbackRating       string    `json:"feedback_rating,omitempty"`
	FeedbackReasonCode   string    `json:"feedback_reason_code,omitempty"`
	EventCount           int64     `json:"event_count"`
	DistinctSubjectCount int64     `json:"distinct_subject_count"`
	ComputedAt           time.Time `json:"computed_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type AggregateFilter struct {
	PlatformID   uuid.UUID
	DefinitionID uuid.UUID
	FromDay      time.Time
	ToDay        time.Time
}

func (f AggregateFilter) valid() bool {
	if f.PlatformID == uuid.Nil || f.FromDay.IsZero() || f.ToDay.IsZero() ||
		!isUTCMidnight(f.FromDay) || !isUTCMidnight(f.ToDay) || f.ToDay.Before(f.FromDay) {
		return false
	}
	return int(f.ToDay.Sub(f.FromDay)/(24*time.Hour))+1 <= maximumAggregateWindowDays
}

type AggregatePageRequest struct {
	Limit  int
	Cursor string
}

func (p AggregatePageRequest) valid() bool {
	return p.Limit >= 1 && p.Limit <= maximumAggregatePageSize && len(p.Cursor) <= 512
}

type AggregatePage struct {
	Items      []Aggregate `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type AggregateCursor struct {
	Day time.Time
	ID  uuid.UUID
}

type aggregateCursorJSON struct {
	Day string `json:"day"`
	ID  string `json:"id"`
}

func encodeAggregateCursor(cursor AggregateCursor) (string, error) {
	if cursor.ID == uuid.Nil || !isUTCMidnight(cursor.Day) {
		return "", ErrInvalidRequest
	}
	raw, err := json.Marshal(aggregateCursorJSON{Day: cursor.Day.Format("2006-01-02"), ID: cursor.ID.String()})
	if err != nil {
		return "", ErrInvalidRequest
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeAggregateCursor(raw string) (AggregateCursor, error) {
	if raw == "" || len(raw) > 512 {
		return AggregateCursor{}, ErrInvalidRequest
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return AggregateCursor{}, ErrInvalidRequest
	}
	var wire aggregateCursorJSON
	if rejectDuplicateJSONKeys(decoded) != nil || decodeStrictJSON(decoded, &wire) != nil {
		return AggregateCursor{}, ErrInvalidRequest
	}
	day, err := time.Parse("2006-01-02", wire.Day)
	if err != nil || day.Format("2006-01-02") != wire.Day {
		return AggregateCursor{}, ErrInvalidRequest
	}
	id, ok := canonicalUUID(wire.ID)
	if !ok {
		return AggregateCursor{}, ErrInvalidRequest
	}
	return AggregateCursor{Day: day, ID: id}, nil
}

func (r *PostgresRepository) ListAggregates(
	ctx context.Context,
	filter AggregateFilter,
	page AggregatePageRequest,
	minimumSubjects int,
) (AggregatePage, error) {
	if r == nil || r.postgres == nil || !filter.valid() || !page.valid() || minimumSubjects < 10 {
		return AggregatePage{}, ErrInvalidRequest
	}
	args := []any{filter.PlatformID, filter.FromDay, filter.ToDay, minimumSubjects}
	query := `
		SELECT id, platform_id, definition_id, version_id, release_id, release_revision_id,
			aggregate_day, event_kind, result_code, latency_bucket, total_token_bucket,
			COALESCE(crash_code, ''), COALESCE(feedback_rating, ''),
			COALESCE(feedback_reason_code, ''), event_count, distinct_subject_count,
			computed_at, updated_at
		FROM official_quality_daily_aggregates
		WHERE platform_id = $1 AND aggregate_day BETWEEN $2 AND $3
		  AND is_suppressed = FALSE AND distinct_subject_count >= $4
	`
	if filter.DefinitionID != uuid.Nil {
		args = append(args, filter.DefinitionID)
		query += fmt.Sprintf(" AND definition_id = $%d", len(args))
	}
	if page.Cursor != "" {
		cursor, err := decodeAggregateCursor(page.Cursor)
		if err != nil {
			return AggregatePage{}, err
		}
		args = append(args, cursor.Day, cursor.ID)
		query += fmt.Sprintf(" AND (aggregate_day, id) < ($%d, $%d)", len(args)-1, len(args))
	}
	args = append(args, page.Limit+1)
	query += fmt.Sprintf(" ORDER BY aggregate_day DESC, id DESC LIMIT $%d", len(args))
	rows, err := r.postgres.Query(ctx, query, args...)
	if err != nil {
		return AggregatePage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]Aggregate, 0, page.Limit+1)
	for rows.Next() {
		var item Aggregate
		if err := rows.Scan(
			&item.ID, &item.PlatformID, &item.DefinitionID, &item.VersionID,
			&item.ReleaseID, &item.ReleaseRevisionID, &item.AggregateDay,
			&item.EventKind, &item.ResultCode, &item.LatencyBucket, &item.TotalTokenBucket,
			&item.CrashCode, &item.FeedbackRating, &item.FeedbackReasonCode,
			&item.EventCount, &item.DistinctSubjectCount, &item.ComputedAt, &item.UpdatedAt,
		); err != nil {
			return AggregatePage{}, ErrServiceUnavailable
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return AggregatePage{}, ErrServiceUnavailable
	}
	nextCursor := ""
	if len(items) > page.Limit {
		items = items[:page.Limit]
		last := items[len(items)-1]
		nextCursor, err = encodeAggregateCursor(AggregateCursor{Day: last.AggregateDay.UTC(), ID: last.ID})
		if err != nil {
			return AggregatePage{}, ErrServiceUnavailable
		}
	}
	if items == nil {
		items = []Aggregate{}
	}
	return AggregatePage{Items: items, NextCursor: nextCursor}, nil
}

func isUTCMidnight(value time.Time) bool {
	return value.Location() == time.UTC && value.Equal(value.UTC().Truncate(24*time.Hour))
}
