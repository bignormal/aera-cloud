package officialquality

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresMaintenanceSuppressesNineAndReleasesTenAndElevenSubjects(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	maintenance := newQualityMaintenance(t, postgres)
	repository := NewPostgresRepository(postgres)
	day := fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)

	for index := 0; index < 9; index++ {
		insertRawMetric(t, ctx, postgres, fixture, day, byte(index+1))
	}
	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("Run(9) error = %v", err)
	}
	page, err := repository.ListAggregates(ctx, AggregateFilter{
		PlatformID: fixture.platformID, DefinitionID: fixture.definitionID,
		FromDay: day, ToDay: day,
	}, AggregatePageRequest{Limit: 100}, 10)
	if err != nil {
		t.Fatalf("ListAggregates(9) error = %v", err)
	}
	if page.Items == nil || len(page.Items) != 0 {
		t.Fatalf("ListAggregates(9) = %+v, want non-nil empty items", page)
	}

	insertRawMetric(t, ctx, postgres, fixture, day, 10)
	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("Run(10) error = %v", err)
	}
	page, err = repository.ListAggregates(ctx, AggregateFilter{
		PlatformID: fixture.platformID, DefinitionID: fixture.definitionID,
		FromDay: day, ToDay: day,
	}, AggregatePageRequest{Limit: 100}, 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].EventCount != 10 || page.Items[0].DistinctSubjectCount != 10 {
		t.Fatalf("ListAggregates(10) = %+v, %v", page, err)
	}

	insertRawMetric(t, ctx, postgres, fixture, day, 11)
	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("Run(11) error = %v", err)
	}
	page, err = repository.ListAggregates(ctx, AggregateFilter{
		PlatformID: fixture.platformID, DefinitionID: fixture.definitionID,
		FromDay: day, ToDay: day,
	}, AggregatePageRequest{Limit: 100}, 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].EventCount != 11 || page.Items[0].DistinctSubjectCount != 11 {
		t.Fatalf("ListAggregates(11) = %+v, %v", page, err)
	}
	if page.Items[0].ID == uuid.Nil || page.Items[0].AggregateDay.Format("2006-01-02") != day.Format("2006-01-02") {
		t.Fatalf("aggregate identity/day = %+v", page.Items[0])
	}
}

func TestPostgresMaintenanceIsReplaySafeAndPinsRetentionBoundaries(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	maintenance := newQualityMaintenance(t, postgres)
	today := fixture.now.UTC().Truncate(24 * time.Hour)
	boundaryRawDay := today.AddDate(0, 0, -30)
	expiredRawDay := today.AddDate(0, 0, -31)
	insertRawMetric(t, ctx, postgres, fixture, boundaryRawDay, 0x31)
	insertRawMetric(t, ctx, postgres, fixture, expiredRawDay, 0x32)

	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("replayed Run() error = %v", err)
	}
	var boundaryCount, expiredCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_events WHERE platform_id = $1 AND event_day = $2`, fixture.platformID, boundaryRawDay).Scan(&boundaryCount); err != nil {
		t.Fatalf("count boundary raw events: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_events WHERE platform_id = $1 AND event_day = $2`, fixture.platformID, expiredRawDay).Scan(&expiredCount); err != nil {
		t.Fatalf("count expired raw events: %v", err)
	}
	if boundaryCount != 1 || expiredCount != 0 {
		t.Fatalf("raw retention boundary/expired = %d/%d, want 1/0", boundaryCount, expiredCount)
	}

	var aggregateRows int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM official_quality_daily_aggregates
		WHERE platform_id = $1 AND aggregate_day = $2
	`, fixture.platformID, boundaryRawDay).Scan(&aggregateRows); err != nil {
		t.Fatalf("count replayed aggregate rows: %v", err)
	}
	if aggregateRows != 1 {
		t.Fatalf("replayed aggregate rows = %d, want 1", aggregateRows)
	}

	boundaryAggregateDay := fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -180)
	expiredAggregateDay := fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -181)
	insertAggregateFixture(t, ctx, postgres, fixture, boundaryAggregateDay, "1s_5s")
	insertAggregateFixture(t, ctx, postgres, fixture, expiredAggregateDay, "5s_15s")
	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("aggregate retention Run() error = %v", err)
	}
	var boundaryAggregates, expiredAggregates int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_daily_aggregates WHERE platform_id = $1 AND aggregate_day = $2`, fixture.platformID, boundaryAggregateDay).Scan(&boundaryAggregates); err != nil {
		t.Fatalf("count boundary aggregates: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_daily_aggregates WHERE platform_id = $1 AND aggregate_day = $2`, fixture.platformID, expiredAggregateDay).Scan(&expiredAggregates); err != nil {
		t.Fatalf("count expired aggregates: %v", err)
	}
	if boundaryAggregates != 1 || expiredAggregates != 0 {
		t.Fatalf("aggregate retention boundary/expired = %d/%d, want 1/0", boundaryAggregates, expiredAggregates)
	}
}

func TestPostgresMaintenancePurgesRevokedPurposeWithoutTouchingOtherPurpose(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	maintenance := newQualityMaintenance(t, postgres)
	day := fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	metricsSubject := maintenance.pseudonymizer.Active(fixture.principal.UserID, PurposeMetrics, day)
	explicitSubject := maintenance.pseudonymizer.Active(fixture.principal.UserID, PurposeExplicitFeedback, day)
	insertRawQualityVariant(t, ctx, postgres, fixture, day, metricsSubject, EventKindMetric, 0x61)
	insertRawQualityVariant(t, ctx, postgres, fixture, day, explicitSubject, EventKindExplicitFeedback, 0x62)
	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("initial Run() error = %v", err)
	}
	repository := NewPostgresRepository(postgres)
	if _, err := repository.RecordConsent(ctx, RecordConsentCommand{
		ReceiptID: uuid.New(), Principal: fixture.principal, Purpose: PurposeMetrics,
		ConsentVersion: 1, State: ConsentRevoked, RecordedAt: fixture.now,
	}); err != nil {
		t.Fatalf("RecordConsent(revoke) error = %v", err)
	}
	if err := maintenance.Run(ctx, fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("purge Run() error = %v", err)
	}

	var metricsRaw, explicitRaw, metricsAggregates, completedPurges int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_events WHERE platform_id = $1 AND event_kind = 'metric' AND subject_pseudonym = $2`, fixture.platformID, metricsSubject).Scan(&metricsRaw); err != nil {
		t.Fatalf("count metric raw events: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_events WHERE platform_id = $1 AND event_kind = 'explicit_feedback' AND subject_pseudonym = $2`, fixture.platformID, explicitSubject).Scan(&explicitRaw); err != nil {
		t.Fatalf("count explicit raw events: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_daily_aggregates WHERE platform_id = $1 AND aggregate_day = $2 AND event_kind = 'metric'`, fixture.platformID, day).Scan(&metricsAggregates); err != nil {
		t.Fatalf("count metric aggregates: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_purge_requests WHERE user_id = $1 AND purpose = $2 AND state = 'completed'`, fixture.principal.UserID, PurposeMetrics).Scan(&completedPurges); err != nil {
		t.Fatalf("count completed purge requests: %v", err)
	}
	if metricsRaw != 0 || explicitRaw != 1 || metricsAggregates != 0 || completedPurges != 1 {
		t.Fatalf("purge results metric=%d explicit=%d aggregate=%d completed=%d, want 0/1/0/1", metricsRaw, explicitRaw, metricsAggregates, completedPurges)
	}
}

func TestPostgresMaintenanceExpiresAggregateButPreservesImmutableProposalSourceID(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	maintenance := newQualityMaintenance(t, postgres)
	expiredDay := fixture.now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -181)
	aggregateID := insertAggregateFixture(t, ctx, postgres, fixture, expiredDay, "15s_60s")
	proposalID := uuid.New()
	adminID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO official_quality_proposals (
			id, platform_id, definition_id, version_id, release_id, release_revision_id,
			problem_categories, improvement_objective, created_by_admin_id, created_by_role,
			status, revision, reason_code, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, ARRAY['latency']::TEXT[],
			'Reduce bounded official Agent latency safely.', $7, 'developer',
			'open', 1, 'quality_review', $8, $8)
	`, proposalID, fixture.platformID, fixture.definitionID, fixture.versionID,
		fixture.releaseID, fixture.releaseRevisionID, adminID, fixture.now); err != nil {
		t.Fatalf("insert quality proposal: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO official_quality_proposal_aggregates (
			proposal_id, aggregate_id, position, created_at
		) VALUES ($1, $2, 1, $3)
	`, proposalID, aggregateID, fixture.now); err != nil {
		t.Fatalf("insert proposal aggregate source: %v", err)
	}
	if err := maintenance.Run(ctx, fixture.now); err != nil {
		t.Fatalf("Run() with expired proposal source error = %v", err)
	}
	var aggregateCount, sourceCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_daily_aggregates WHERE id = $1`, aggregateID).Scan(&aggregateCount); err != nil {
		t.Fatalf("count expired aggregate: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_proposal_aggregates WHERE proposal_id = $1 AND aggregate_id = $2`, proposalID, aggregateID).Scan(&sourceCount); err != nil {
		t.Fatalf("count preserved proposal source: %v", err)
	}
	if aggregateCount != 0 || sourceCount != 1 {
		t.Fatalf("expired aggregate/preserved source = %d/%d, want 0/1", aggregateCount, sourceCount)
	}
}

func TestAggregateCursorIsOpaqueBoundedAndRejectsWideFilters(t *testing.T) {
	request := AggregatePageRequest{Limit: 101}
	filter := AggregateFilter{
		PlatformID: uuid.New(), FromDay: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ToDay: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := encodeAggregateCursor(AggregateCursor{Day: filter.FromDay, ID: uuid.New()}); err != nil {
		t.Fatalf("encodeAggregateCursor() error = %v", err)
	}
	if filter.valid() || request.valid() {
		t.Fatalf("wide filter/page unexpectedly valid: %+v / %+v", filter, request)
	}
	if _, err := decodeAggregateCursor("not-a-cursor"); err == nil {
		t.Fatal("decodeAggregateCursor() accepted malformed cursor")
	}
}

func newQualityMaintenance(t *testing.T, postgres *pgxpool.Pool) *PostgresMaintenance {
	t.Helper()
	pseudonyms, err := NewPseudonymizer("active", map[string][]byte{
		"active": bytes.Repeat([]byte{0x71}, 32),
	})
	if err != nil {
		t.Fatalf("NewPseudonymizer() error = %v", err)
	}
	maintenance, err := NewPostgresMaintenance(MaintenanceConfig{
		Postgres: postgres, Pseudonymizer: pseudonyms,
		RawRetentionDays: 30, AggregateRetentionDays: 180, MinimumSubjects: 10,
	})
	if err != nil {
		t.Fatalf("NewPostgresMaintenance() error = %v", err)
	}
	return maintenance
}

func insertRawMetric(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	fixture qualityProvenanceFixture,
	day time.Time,
	discriminator byte,
) {
	t.Helper()
	eventID := mustUUIDV7(t)
	subject := sha256Digest("aggregate-subject", uuidFromDiscriminator(discriminator))
	binding := sha256Digest("aggregate-binding", eventID)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO official_quality_events (
			event_id, protocol_version, consent_version, platform_id,
			definition_id, version_id, release_id, release_revision_id,
			desktop_version, runtime_version, event_day, subject_pseudonym,
			binding_proof_digest, event_kind, result_code, latency_bucket,
			total_token_bucket, crash_code, feedback_rating,
			feedback_reason_codes, device_signature, created_at
		) VALUES ($1, 1, 1, $2, $3, $4, $5, $6, '1.2.3', '2.3.4', $7,
			$8, $9, 'metric', 'success', 'lt_1s', '1_1k', NULL, NULL,
			ARRAY[]::TEXT[], $10, $11)
	`, eventID, fixture.platformID, fixture.definitionID, fixture.versionID,
		fixture.releaseID, fixture.releaseRevisionID, day.UTC(), subject, binding,
		bytes.Repeat([]byte{discriminator}, 64), fixture.now); err != nil {
		t.Fatalf("insert raw metric: %v", err)
	}
}

func insertRawQualityVariant(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	fixture qualityProvenanceFixture,
	day time.Time,
	subject []byte,
	kind string,
	discriminator byte,
) {
	t.Helper()
	rating := any(nil)
	reasons := []string{}
	if kind == EventKindExplicitFeedback {
		rating = "helpful"
		reasons = []string{"incomplete"}
	}
	eventID := mustUUIDV7(t)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO official_quality_events (
			event_id, protocol_version, consent_version, platform_id,
			definition_id, version_id, release_id, release_revision_id,
			desktop_version, runtime_version, event_day, subject_pseudonym,
			binding_proof_digest, event_kind, result_code, latency_bucket,
			total_token_bucket, crash_code, feedback_rating,
			feedback_reason_codes, device_signature, created_at
		) VALUES ($1, 1, 1, $2, $3, $4, $5, $6, '1.2.3', '2.3.4', $7,
			$8, $9, $10, 'success', 'lt_1s', '1_1k', NULL, $11, $12, $13, $14)
	`, eventID, fixture.platformID, fixture.definitionID, fixture.versionID,
		fixture.releaseID, fixture.releaseRevisionID, day, subject,
		sha256Digest("purge-binding", eventID), kind, rating, reasons,
		bytes.Repeat([]byte{discriminator}, 64), fixture.now); err != nil {
		t.Fatalf("insert raw quality variant: %v", err)
	}
}

func insertAggregateFixture(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	fixture qualityProvenanceFixture,
	day time.Time,
	latency string,
) uuid.UUID {
	t.Helper()
	aggregateID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO official_quality_daily_aggregates (
			id, platform_id, definition_id, version_id, release_id, release_revision_id,
			aggregate_day, event_kind, result_code, latency_bucket, total_token_bucket,
			event_count, distinct_subject_count, suppression_threshold, is_suppressed,
			computed_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'metric', 'success', $8, '1_1k',
			10, 10, 10, FALSE, $9, $9)
	`, aggregateID, fixture.platformID, fixture.definitionID, fixture.versionID,
		fixture.releaseID, fixture.releaseRevisionID, day, latency, fixture.now); err != nil {
		t.Fatalf("insert aggregate fixture: %v", err)
	}
	return aggregateID
}

func uuidFromDiscriminator(discriminator byte) uuid.UUID {
	value := uuid.UUID{0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, discriminator}
	return value
}
