package officialquality

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresRepositoryAcceptsEligibleEventAndReplaysExactly(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	repository := NewPostgresRepository(postgres)

	active, err := repository.ActiveConsent(ctx, fixture.principal.UserID, PurposeMetrics, 1)
	if err != nil || !active {
		t.Fatalf("ActiveConsent() = %v, %v", active, err)
	}
	publicKey, err := repository.ActiveDeviceKey(ctx, fixture.principal)
	if err != nil || !bytes.Equal(publicKey, fixture.publicKey) {
		t.Fatalf("ActiveDeviceKey() = %x, %v", publicKey, err)
	}
	envelope := fixture.envelope(t)
	eligible, err := repository.EligibleBinding(ctx, fixture.principal, envelope)
	if err != nil || !eligible {
		t.Fatalf("EligibleBinding() = %v, %v", eligible, err)
	}
	command := AcceptEventCommand{
		Principal: fixture.principal, Envelope: envelope,
		SubjectPseudonym:   sha256Digest("subject", envelope.EventID),
		BindingProofDigest: sha256Digest("binding", envelope.EventID),
		AcceptedAt:         fixture.now,
	}
	replayed, err := repository.AcceptEvent(ctx, command)
	if err != nil || replayed {
		t.Fatalf("first AcceptEvent() = %v, %v", replayed, err)
	}
	replayed, err = repository.AcceptEvent(ctx, command)
	if err != nil || !replayed {
		t.Fatalf("replayed AcceptEvent() = %v, %v", replayed, err)
	}

	var eventCount, auditCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_events WHERE event_id = $1`, envelope.EventID).Scan(&eventCount); err != nil {
		t.Fatalf("count accepted event: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE object_id = $1 AND event_type = 'official_quality_event_accepted'`, envelope.EventID).Scan(&auditCount); err != nil {
		t.Fatalf("count accepted event audit: %v", err)
	}
	if eventCount != 1 || auditCount != 1 {
		t.Fatalf("accepted event/audit counts = %d/%d, want 1/1", eventCount, auditCount)
	}
}

func sha256Digest(domain string, identifier uuid.UUID) []byte {
	digest := sha256.Sum256(append([]byte(domain+"\x00"), identifier[:]...))
	return digest[:]
}

func TestPostgresRepositoryRejectsMismatchedOfficialBinding(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	repository := NewPostgresRepository(postgres)
	envelope := fixture.envelope(t)
	envelope.ReleaseRevisionID = uuid.New()
	eligible, err := repository.EligibleBinding(ctx, fixture.principal, envelope)
	if err != nil {
		t.Fatalf("EligibleBinding() error = %v", err)
	}
	if eligible {
		t.Fatal("EligibleBinding() accepted mismatched release revision")
	}
}

func TestPostgresRepositoryConsentIsAppendOnlyPurposeSpecificAndRevocationQueuesPurge(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	fixture := seedOfficialQualityProvenance(t, ctx, postgres)
	repository := NewPostgresRepository(postgres)

	replayed, err := repository.RecordConsent(ctx, RecordConsentCommand{
		ReceiptID: uuid.New(), Principal: fixture.principal, Purpose: PurposeMetrics,
		ConsentVersion: 1, State: ConsentGranted, RecordedAt: fixture.now.Add(time.Minute),
	})
	if err != nil || !replayed.Replayed || replayed.Revision != 1 {
		t.Fatalf("replayed RecordConsent() = %+v, %v", replayed, err)
	}
	revoked, err := repository.RecordConsent(ctx, RecordConsentCommand{
		ReceiptID: uuid.New(), Principal: fixture.principal, Purpose: PurposeMetrics,
		ConsentVersion: 1, State: ConsentRevoked, RecordedAt: fixture.now.Add(2 * time.Minute),
	})
	if err != nil || revoked.Replayed || revoked.Revision != 2 {
		t.Fatalf("revoked RecordConsent() = %+v, %v", revoked, err)
	}
	active, err := repository.ActiveConsent(ctx, fixture.principal.UserID, PurposeMetrics, 1)
	if err != nil || active {
		t.Fatalf("ActiveConsent(metrics) = %v, %v, want false", active, err)
	}
	explicit, err := repository.RecordConsent(ctx, RecordConsentCommand{
		ReceiptID: uuid.New(), Principal: fixture.principal, Purpose: PurposeExplicitFeedback,
		ConsentVersion: 1, State: ConsentGranted, RecordedAt: fixture.now.Add(3 * time.Minute),
	})
	if err != nil || explicit.Revision != 1 || explicit.Replayed {
		t.Fatalf("explicit RecordConsent() = %+v, %v", explicit, err)
	}

	var receiptCount, purgeCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_consent_receipts WHERE user_id = $1`, fixture.principal.UserID).Scan(&receiptCount); err != nil {
		t.Fatalf("count consent receipts: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM official_quality_purge_requests WHERE user_id = $1 AND purpose = $2 AND state = 'pending'`, fixture.principal.UserID, PurposeMetrics).Scan(&purgeCount); err != nil {
		t.Fatalf("count purge requests: %v", err)
	}
	if receiptCount != 3 || purgeCount != 1 {
		t.Fatalf("consent receipt/purge counts = %d/%d, want 3/1", receiptCount, purgeCount)
	}
}

type qualityProvenanceFixture struct {
	now               time.Time
	principal         Principal
	privateKey        ed25519.PrivateKey
	publicKey         ed25519.PublicKey
	platformID        uuid.UUID
	definitionID      uuid.UUID
	versionID         uuid.UUID
	releaseID         uuid.UUID
	releaseRevisionID uuid.UUID
	bindingID         uuid.UUID
}

func (f qualityProvenanceFixture) envelope(t *testing.T) PublicEnvelope {
	t.Helper()
	envelope := PublicEnvelope{
		ProtocolVersion: ProtocolVersion, ConsentVersion: 1, EventID: mustUUIDV7(t),
		PlatformID: f.platformID, DefinitionID: f.definitionID, VersionID: f.versionID,
		ReleaseID: f.releaseID, ReleaseRevisionID: f.releaseRevisionID,
		DesktopVersion: "1.2.3", RuntimeVersion: "2.3.4", EventDay: f.now.Format("2006-01-02"),
		Kind: EventKindMetric, Result: ResultSuccess, LatencyBucket: "lt_1s", TotalTokenBucket: "1_1k",
		FeedbackReasonCodes: []string{}, BindingProof: f.bindingID,
	}
	payload, err := envelope.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes() error = %v", err)
	}
	envelope.DeviceSignature = ed25519.Sign(f.privateKey, payload)
	return envelope
}

func seedOfficialQualityProvenance(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
) qualityProvenanceFixture {
	t.Helper()
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate provenance device key: %v", err)
	}
	fixture := qualityProvenanceFixture{
		now: now, privateKey: privateKey, publicKey: publicKey,
		principal:  Principal{UserID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New()},
		platformID: uuid.New(), definitionID: uuid.New(), versionID: uuid.New(),
		releaseID: uuid.New(), releaseRevisionID: uuid.New(), bindingID: uuid.New(),
	}
	tx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin provenance fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qualityExec(t, ctx, tx, `SET CONSTRAINTS ALL DEFERRED`)

	qualityExec(t, ctx, tx, `INSERT INTO users (id, nickname, status, created_at, updated_at) VALUES ($1, 'quality-user', 'active', $2, $2)`, fixture.principal.UserID, now)
	qualityExec(t, ctx, tx, `INSERT INTO personal_spaces (id, owner_user_id, display_name, status, created_at, updated_at) VALUES ($1, $2, 'Quality Space', 'active', $3, $3)`, fixture.principal.PersonalSpaceID, fixture.principal.UserID, now)
	qualityExec(t, ctx, tx, `INSERT INTO devices (id, user_id, installation_id, public_key, display_name, platform, app_version, status, created_at, updated_at, last_seen_at) VALUES ($1, $2, $3, $4, 'Quality Device', 'darwin', '1.2.3', 'active', $5, $5, $5)`, fixture.principal.DeviceID, fixture.principal.UserID, uuid.New(), fixture.publicKey, now)
	qualityExec(t, ctx, tx, `INSERT INTO platforms (id, platform_key, display_name, status, created_at, updated_at) VALUES ($1, $2, 'AgentEra Official', 'active', $3, $3)`, fixture.platformID, "quality_"+fixture.platformID.String()[:8], now)

	adminID := uuid.New()
	draftID := uuid.New()
	submissionID := uuid.New()
	platformPolicyID := uuid.New()
	digest := bytes.Repeat([]byte{0x21}, 32)
	signature := bytes.Repeat([]byte{0x22}, 64)
	qualityExec(t, ctx, tx, `INSERT INTO agent_definitions (id, owner_scope, display_name, status, created_at, updated_at, platform_id, created_by_admin_id) VALUES ($1, 'PLATFORM', 'Quality Official', 'active', $2, $2, $3, $4)`, fixture.definitionID, now, fixture.platformID, adminID)
	qualityExec(t, ctx, tx, `INSERT INTO platform_agent_policy_snapshots (id, platform_id, version, canonical_policy, policy_digest, signature_key_id, signature, created_at) VALUES ($1, $2, 1, '{}'::jsonb, $3, 'quality-key', $4, $5)`, platformPolicyID, fixture.platformID, digest, signature, now)
	qualityExec(t, ctx, tx, `INSERT INTO platform_agent_drafts (id, platform_id, definition_id, kind, display_name, canonical_manifest, bundle, manifest_digest, bundle_digest, content_digest, revision, status, last_editor_admin_id, last_editor_role, created_at, updated_at) VALUES ($1, $2, $3, 'initial', 'Quality Official', '{}'::jsonb, '{}'::jsonb, $4, $4, $4, 1, 'active', $5, 'developer', $6, $6)`, draftID, fixture.platformID, fixture.definitionID, digest, adminID, now)
	qualityExec(t, ctx, tx, `INSERT INTO platform_agent_submissions (id, platform_id, draft_id, draft_revision, definition_id, kind, display_name, canonical_manifest, bundle, manifest_digest, bundle_digest, content_digest, submitted_by_admin_id, submitted_by_role, status, revision, submitted_at, terminal_at, updated_at) VALUES ($1, $2, $3, 1, $4, 'initial', 'Quality Official', '{}'::jsonb, '{}'::jsonb, $5, $5, $5, $6, 'developer', 'approved', 2, $7, $7, $7)`, submissionID, fixture.platformID, draftID, fixture.definitionID, digest, adminID, now)
	qualityExec(t, ctx, tx, `INSERT INTO agent_versions (id, definition_id, owner_scope, version_number, canonical_manifest, bundle, content_digest, signing_key_id, signature, runtime_minimum_version, published_at, platform_id, platform_submission_id, platform_policy_snapshot_id, published_by_admin_id) VALUES ($1, $2, 'PLATFORM', 1, '{}'::jsonb, '{}'::jsonb, $3, 'quality-key', $4, '1.0.0', $5, $6, $7, $8, $9)`, fixture.versionID, fixture.definitionID, digest, signature, now, fixture.platformID, submissionID, platformPolicyID, adminID)
	qualityExec(t, ctx, tx, `UPDATE agent_definitions SET latest_version_id = $1 WHERE id = $2`, fixture.versionID, fixture.definitionID)

	qualityExec(t, ctx, tx, `INSERT INTO official_releases (id, platform_id, definition_id, channel, current_release_revision_id, head_revision, created_at, updated_at) VALUES ($1, $2, $3, 'stable', $4, 1, $5, $5)`, fixture.releaseID, fixture.platformID, fixture.definitionID, fixture.releaseRevisionID, now)
	qualityExec(t, ctx, tx, `INSERT INTO official_release_revisions (id, release_id, revision_number, agent_version_id, state, rollout_basis_points, minimum_desktop_version, bucket_algorithm_version, rollout_key_id, action, actor_admin_id, actor_admin_role, reason_code, created_at) VALUES ($1, $2, 1, $3, 'paused', 0, '1.0.0', '1', 'rollout-v1', 'initial', $4, 'developer', 'initial_release', $5)`, fixture.releaseRevisionID, fixture.releaseID, fixture.versionID, adminID, now)

	installationID := uuid.New()
	policyID := uuid.New()
	runtimeProfileID := uuid.New()
	qualityExec(t, ctx, tx, `INSERT INTO installations (id, tenant_id, owner_scope, owner_id, device_id, device_installation_id, definition_id, selected_version_id, runtime_profile_id, policy_snapshot_id, update_policy, status, created_by, created_at, updated_at, activated_at, official_release_id, selected_release_revision_id) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, $8, $9, 'managed', 'active', $3, $10, $10, $10, $11, $12)`, installationID, fixture.principal.PersonalSpaceID, fixture.principal.UserID, fixture.principal.DeviceID, uuid.New(), fixture.definitionID, fixture.versionID, runtimeProfileID, policyID, now, fixture.releaseID, fixture.releaseRevisionID)
	qualityExec(t, ctx, tx, `INSERT INTO policy_snapshots (id, installation_id, agent_version_id, tenant_id, owner_scope, owner_id, policy_version, policy_document, content_digest, issuer, signing_key_id, signature, created_by, created_at) VALUES ($1, $2, $3, $4, 'USER', $5, 1, '{}'::jsonb, $6, 'AgentEra', 'quality-key', $7, $5, $8)`, policyID, installationID, fixture.versionID, fixture.principal.PersonalSpaceID, fixture.principal.UserID, digest, signature, now)
	qualityExec(t, ctx, tx, `INSERT INTO runtime_binding_records (id, tenant_id, owner_scope, owner_id, device_id, agent_installation_id, agent_version_id, runtime_profile_id, runtime_version, policy_snapshot_id, tool_permission_digest, created_at, official_release_revision_id) VALUES ($1, $2, 'USER', $3, $4, $5, $6, $7, '2.3.4', $8, $9, $10, $11)`, fixture.bindingID, fixture.principal.PersonalSpaceID, fixture.principal.UserID, fixture.principal.DeviceID, installationID, fixture.versionID, runtimeProfileID, policyID, digest, now, fixture.releaseRevisionID)
	qualityExec(t, ctx, tx, `INSERT INTO official_quality_consent_receipts (id, user_id, purpose, consent_version, state, revision, recorded_at) VALUES ($1, $2, $3, 1, 'granted', 1, $4)`, uuid.New(), fixture.principal.UserID, PurposeMetrics, now)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit provenance fixture: %v", err)
	}
	return fixture
}

func qualityExec(t *testing.T, ctx context.Context, tx pgx.Tx, query string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, query, args...); err != nil {
		t.Fatalf("execute provenance fixture statement: %v", err)
	}
}
