//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/officialquality"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maximumFixtureBytes = 16 << 10

type fixture struct {
	UserID                 uuid.UUID `json:"user_id"`
	OfficialAudienceUserID uuid.UUID `json:"official_audience_user_id"`
	DeviceID               uuid.UUID `json:"device_id"`
	SessionID              uuid.UUID `json:"session_id"`
	MaskedEmail            string    `json:"masked_email"`
	RawIdentity            string    `json:"raw_lookup_identity"`
	InitialRevision        int64     `json:"initial_revision"`
}

type seedConfig struct {
	Environment            string
	DatabaseURL            string
	IdentityEncryptionKeys config.KeyRing
	IdentityLookupKeys     config.KeyRing
	PlatformID             uuid.UUID
	QualityActiveKeyID     string
	QualityKeys            map[string][]byte
	QualityRawRetention    int
	QualityAggregateTTL    int
	QualityMinimumSubjects int
}

type qualitySeedArguments struct {
	DefinitionID, VersionID, ReleaseID, ReleaseRevisionID uuid.UUID
	FromSubject, ToSubject                                int
}

func main() {
	if err := run(os.Args[1:], os.LookupEnv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "aera-cloud-e2e:", err)
		os.Exit(1)
	}
}

func run(arguments []string, lookup config.LookupEnv) error {
	if len(arguments) == 0 || lookup == nil {
		return errors.New("seed or verify mode is required")
	}
	cloudConfig, err := config.Load(lookup)
	if err != nil {
		return err
	}
	runtime := seedConfig{
		Environment: cloudConfig.Environment, DatabaseURL: cloudConfig.DatabaseURL,
		IdentityEncryptionKeys: cloudConfig.IdentityEncryptionKeyRing,
		IdentityLookupKeys:     cloudConfig.IdentityLookupKeyRing,
		PlatformID:             cloudConfig.OfficialAgent.PlatformID,
		QualityActiveKeyID:     cloudConfig.OfficialQuality.PseudonymHMACActiveKey,
		QualityKeys:            cloudConfig.OfficialQuality.PseudonymHMACKeys,
		QualityRawRetention:    cloudConfig.OfficialQuality.RawRetentionDays,
		QualityAggregateTTL:    cloudConfig.OfficialQuality.AggregateRetentionDays,
		QualityMinimumSubjects: cloudConfig.OfficialQuality.MinimumSubjects,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	switch arguments[0] {
	case "seed":
		flags := flag.NewFlagSet("seed", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		output := flags.String("output", "", "fixture output path")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *output == "" {
			return errors.New("seed arguments are invalid")
		}
		_, err := seed(ctx, runtime, *output)
		return err
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		fixturePath := flags.String("fixture", "", "fixture input path")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *fixturePath == "" {
			return errors.New("verify arguments are invalid")
		}
		return verify(ctx, runtime, *fixturePath)
	case "seed-quality":
		qualityArguments, err := parseQualitySeedArguments(arguments[1:])
		if err != nil {
			return err
		}
		return seedQuality(ctx, runtime, qualityArguments)
	default:
		return errors.New("seed, seed-quality, or verify mode is required")
	}
}

func parseQualitySeedArguments(arguments []string) (qualitySeedArguments, error) {
	if len(arguments) != 12 {
		return qualitySeedArguments{}, errors.New("quality seed arguments are invalid")
	}
	allowed := map[string]bool{
		"--definition-id": false, "--version-id": false, "--release-id": false,
		"--release-revision-id": false, "--from-subject": false, "--to-subject": false,
	}
	for index := 0; index < len(arguments); index += 2 {
		seen, ok := allowed[arguments[index]]
		if !ok || seen || arguments[index+1] == "" {
			return qualitySeedArguments{}, errors.New("quality seed arguments are invalid")
		}
		allowed[arguments[index]] = true
	}
	flags := flag.NewFlagSet("seed-quality", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	definitionID := flags.String("definition-id", "", "official definition ID")
	versionID := flags.String("version-id", "", "official version ID")
	releaseID := flags.String("release-id", "", "official release ID")
	releaseRevisionID := flags.String("release-revision-id", "", "official release revision ID")
	fromSubject := flags.String("from-subject", "", "first synthetic subject")
	toSubject := flags.String("to-subject", "", "last synthetic subject")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return qualitySeedArguments{}, errors.New("quality seed arguments are invalid")
	}
	parsed := qualitySeedArguments{}
	var ok bool
	if parsed.DefinitionID, ok = canonicalE2EUUID(*definitionID); !ok {
		return qualitySeedArguments{}, errors.New("quality seed definition is invalid")
	}
	if parsed.VersionID, ok = canonicalE2EUUID(*versionID); !ok {
		return qualitySeedArguments{}, errors.New("quality seed version is invalid")
	}
	if parsed.ReleaseID, ok = canonicalE2EUUID(*releaseID); !ok {
		return qualitySeedArguments{}, errors.New("quality seed release is invalid")
	}
	if parsed.ReleaseRevisionID, ok = canonicalE2EUUID(*releaseRevisionID); !ok {
		return qualitySeedArguments{}, errors.New("quality seed release revision is invalid")
	}
	parsed.FromSubject, _ = strconv.Atoi(*fromSubject)
	parsed.ToSubject, _ = strconv.Atoi(*toSubject)
	if strconv.Itoa(parsed.FromSubject) != *fromSubject || strconv.Itoa(parsed.ToSubject) != *toSubject ||
		parsed.FromSubject < 1 || parsed.ToSubject < parsed.FromSubject || parsed.ToSubject > 100 {
		return qualitySeedArguments{}, errors.New("quality seed subject range is invalid")
	}
	return parsed, nil
}

func canonicalE2EUUID(raw string) (uuid.UUID, bool) {
	value, err := uuid.Parse(raw)
	return value, err == nil && value != uuid.Nil && value.String() == raw
}

func seedQuality(ctx context.Context, cfg seedConfig, arguments qualitySeedArguments) error {
	if ctx == nil || cfg.validate() != nil || cfg.PlatformID == uuid.Nil || cfg.QualityActiveKeyID == "" ||
		cfg.QualityRawRetention != 30 || cfg.QualityAggregateTTL != 180 || cfg.QualityMinimumSubjects != 10 ||
		arguments.DefinitionID == uuid.Nil || arguments.VersionID == uuid.Nil || arguments.ReleaseID == uuid.Nil ||
		arguments.ReleaseRevisionID == uuid.Nil || arguments.FromSubject < 1 ||
		arguments.ToSubject < arguments.FromSubject || arguments.ToSubject > 100 {
		return errors.New("Cloud E2E quality seed configuration is invalid")
	}
	postgres, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer postgres.Close()
	pseudonymizer, err := officialquality.NewPseudonymizer(cfg.QualityActiveKeyID, cfg.QualityKeys)
	if err != nil {
		return errors.New("Cloud E2E quality pseudonym configuration is invalid")
	}
	now := time.Now().UTC()
	day := now.Truncate(24*time.Hour).AddDate(0, 0, -1)
	tx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("Cloud E2E quality seed transaction could not start")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	for subject := arguments.FromSubject; subject <= arguments.ToSubject; subject++ {
		eventID, eventErr := uuid.NewV7()
		if eventErr != nil {
			return errors.New("Cloud E2E quality event ID could not be generated")
		}
		subjectDigest := sha256.Sum256([]byte(fmt.Sprintf("aera-e2e-quality-subject-%03d", subject)))
		bindingDigest := sha256.Sum256([]byte("aera-e2e-quality-binding-" + eventID.String()))
		if _, err := tx.Exec(ctx, `
			INSERT INTO official_quality_events (
				event_id, protocol_version, consent_version, platform_id,
				definition_id, version_id, release_id, release_revision_id,
				desktop_version, runtime_version, event_day, subject_pseudonym,
				binding_proof_digest, event_kind, result_code, latency_bucket,
				total_token_bucket, crash_code, feedback_rating,
				feedback_reason_codes, device_signature, created_at
			) VALUES ($1, 1, 1, $2, $3, $4, $5, $6, 'e2e-desktop', 'e2e-runtime', $7,
				$8, $9, 'metric', 'success', 'lt_1s', '1_1k', NULL, NULL,
				ARRAY[]::TEXT[], $10, $11)
		`, eventID, cfg.PlatformID, arguments.DefinitionID, arguments.VersionID,
			arguments.ReleaseID, arguments.ReleaseRevisionID, day,
			subjectDigest[:], bindingDigest[:], bytes.Repeat([]byte{byte(subject)}, 64), now); err != nil {
			return errors.New("Cloud E2E quality event could not be seeded")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("Cloud E2E quality seed transaction could not be committed")
	}
	maintenance, err := officialquality.NewPostgresMaintenance(officialquality.MaintenanceConfig{
		Postgres: postgres, Pseudonymizer: pseudonymizer,
		RawRetentionDays: cfg.QualityRawRetention, AggregateRetentionDays: cfg.QualityAggregateTTL,
		MinimumSubjects: cfg.QualityMinimumSubjects,
	})
	if err != nil {
		return errors.New("Cloud E2E quality maintenance could not be configured")
	}
	if err := maintenance.Run(ctx, now); err != nil {
		return errors.New("Cloud E2E quality aggregate could not be computed")
	}
	return nil
}

func (c seedConfig) validate() error {
	if c.Environment != "test" {
		return errors.New("Cloud E2E requires the test environment")
	}
	parsed, err := url.Parse(c.DatabaseURL)
	poolConfig, poolErr := pgxpool.ParseConfig(c.DatabaseURL)
	if err != nil || poolErr != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Path == "" || parsed.Path == "/" || poolConfig.ConnConfig.Database == "" {
		return errors.New("Cloud E2E database configuration is invalid")
	}
	if !numericLoopback(poolConfig.ConnConfig.Host) {
		return errors.New("Cloud E2E database must use a loopback host")
	}
	for _, fallback := range poolConfig.ConnConfig.Fallbacks {
		if fallback == nil || !numericLoopback(fallback.Host) {
			return errors.New("Cloud E2E database fallback must use a loopback host")
		}
	}
	return nil
}

func numericLoopback(host string) bool {
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func seed(ctx context.Context, cfg seedConfig, output string) (fixture, error) {
	if ctx == nil || cfg.validate() != nil || !filepath.IsAbs(output) {
		return fixture{}, errors.New("Cloud E2E seed configuration is invalid")
	}
	identityCodec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: cfg.IdentityEncryptionKeys.ActiveKeyID,
		EncryptionKeys:        cfg.IdentityEncryptionKeys.Keys,
		ActiveLookupKeyID:     cfg.IdentityLookupKeys.ActiveKeyID,
		LookupKeys:            cfg.IdentityLookupKeys.Keys,
	})
	if err != nil {
		return fixture{}, errors.New("Cloud E2E identity configuration is invalid")
	}
	outputFile, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fixture{}, errors.New("Cloud E2E fixture output could not be reserved")
	}
	committed := false
	defer func() {
		_ = outputFile.Close()
		if !committed {
			_ = os.Remove(output)
		}
	}()
	if err := outputFile.Chmod(0o600); err != nil {
		return fixture{}, errors.New("Cloud E2E fixture permissions could not be secured")
	}

	postgres, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return fixture{}, err
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		return fixture{}, err
	}
	tx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fixture{}, errors.New("Cloud E2E seed transaction could not start")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	seeded, err := insertFixture(ctx, tx, identityCodec)
	if err != nil {
		return fixture{}, err
	}
	encoder := json.NewEncoder(outputFile)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(seeded); err != nil || outputFile.Sync() != nil || outputFile.Close() != nil {
		return fixture{}, errors.New("Cloud E2E fixture could not be written")
	}
	if err := tx.Commit(ctx); err != nil {
		return fixture{}, errors.New("Cloud E2E seed transaction could not be committed")
	}
	committed = true
	return seeded, nil
}

func insertFixture(ctx context.Context, tx pgx.Tx, identities *secure.IdentityCodec) (fixture, error) {
	userID, officialAudienceUserID := uuid.New(), uuid.New()
	deviceID, sessionID := uuid.New(), uuid.New()
	spaceID, installationID, familyID := uuid.New(), uuid.New(), uuid.New()
	rawIdentity := "cloud.e2e." + strings.ReplaceAll(userID.String(), "-", "") + "@example.test"
	normalized, err := secure.NormalizeIdentity(secure.IdentityEmail, rawIdentity)
	if err != nil || normalized != rawIdentity {
		return fixture{}, errors.New("Cloud E2E identity could not be normalized")
	}
	sealed, err := identities.Seal(secure.IdentityEmail, normalized)
	if err != nil {
		return fixture{}, errors.New("Cloud E2E identity could not be sealed")
	}
	masked, err := admin.MaskIdentity(secure.IdentityEmail, normalized)
	if err != nil {
		return fixture{}, errors.New("Cloud E2E identity could not be masked")
	}
	publicKey, err := secure.RandomBytes(32)
	if err != nil {
		return fixture{}, errors.New("Cloud E2E device key could not be generated")
	}
	refreshHash, err := secure.RandomBytes(32)
	if err != nil {
		return fixture{}, errors.New("Cloud E2E session hash could not be generated")
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (
			id, nickname, status, administratively_disabled, administrative_revision, created_at, updated_at
		) VALUES ($1, 'Cloud E2E User', 'active', FALSE, 1, $2, $2)
	`, userID, now); err != nil {
		return fixture{}, errors.New("Cloud E2E user could not be seeded")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (
			id, nickname, status, administratively_disabled, administrative_revision, created_at, updated_at
		) VALUES ($1, 'Cloud E2E Official Audience', 'active', FALSE, 1, $2, $2)
	`, officialAudienceUserID, now); err != nil {
		return fixture{}, errors.New("Cloud E2E official audience user could not be seeded")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identities (
			id, user_id, kind, encryption_key_id, nonce, ciphertext,
			lookup_key_id, lookup_hmac, verified_at, created_at
		) VALUES ($1, $2, 'email', $3, $4, $5, $6, $7, $8, $8)
	`, uuid.New(), userID, sealed.EncryptionKeyID, sealed.Nonce, sealed.Ciphertext,
		sealed.LookupKeyID, sealed.LookupHMAC, now); err != nil {
		return fixture{}, errors.New("Cloud E2E identity could not be seeded")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, display_name, status, created_at, updated_at)
		VALUES ($1, $2, 'Cloud E2E Space', 'active', $3, $3)
	`, spaceID, userID, now); err != nil {
		return fixture{}, errors.New("Cloud E2E personal space could not be seeded")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Cloud E2E Mac', 'darwin', '1.0.0-e2e',
			'active', $5, $5, $5)
	`, deviceID, userID, installationID, publicKey, now); err != nil {
		return fixture{}, errors.New("Cloud E2E device could not be seeded")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sessions (
			id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, sessionID, userID, deviceID, familyID, refreshHash, now, now.Add(24*time.Hour)); err != nil {
		return fixture{}, errors.New("Cloud E2E session could not be seeded")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO offline_entitlement_issuances (
			jti, user_id, device_id, personal_space_id, installation_id,
			signing_key_id, policy_version, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'e2e-offline-v1', 1, $6, $7)
	`, uuid.New(), userID, deviceID, spaceID, installationID, now, now.Add(24*time.Hour)); err != nil {
		return fixture{}, errors.New("Cloud E2E entitlement could not be seeded")
	}
	return fixture{
		UserID: userID, OfficialAudienceUserID: officialAudienceUserID,
		DeviceID: deviceID, SessionID: sessionID,
		MaskedEmail: masked, RawIdentity: normalized, InitialRevision: 1,
	}, nil
}

func verify(ctx context.Context, cfg seedConfig, fixturePath string) error {
	if ctx == nil || cfg.validate() != nil {
		return errors.New("Cloud E2E verify configuration is invalid")
	}
	seeded, err := loadFixture(fixturePath)
	if err != nil {
		return err
	}
	postgres, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer postgres.Close()
	return verifyFacts(ctx, postgres, seeded)
}

func loadFixture(path string) (fixture, error) {
	if !filepath.IsAbs(path) {
		return fixture{}, errors.New("Cloud E2E fixture path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fixture{}, errors.New("Cloud E2E fixture is unavailable or insecure")
	}
	file, err := os.Open(path)
	if err != nil {
		return fixture{}, errors.New("Cloud E2E fixture could not be read")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumFixtureBytes+1))
	decoder.DisallowUnknownFields()
	var seeded fixture
	if err := decoder.Decode(&seeded); err != nil {
		return fixture{}, errors.New("Cloud E2E fixture is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fixture{}, errors.New("Cloud E2E fixture is invalid")
	}
	if seeded.UserID == uuid.Nil || seeded.OfficialAudienceUserID == uuid.Nil ||
		seeded.OfficialAudienceUserID == seeded.UserID || seeded.DeviceID == uuid.Nil || seeded.SessionID == uuid.Nil ||
		seeded.InitialRevision != 1 || seeded.RawIdentity == "" || seeded.MaskedEmail == "" {
		return fixture{}, errors.New("Cloud E2E fixture is invalid")
	}
	normalized, err := secure.NormalizeIdentity(secure.IdentityEmail, seeded.RawIdentity)
	if err != nil || normalized != seeded.RawIdentity {
		return fixture{}, errors.New("Cloud E2E fixture is invalid")
	}
	masked, err := admin.MaskIdentity(secure.IdentityEmail, normalized)
	if err != nil || masked != seeded.MaskedEmail {
		return fixture{}, errors.New("Cloud E2E fixture is invalid")
	}
	return seeded, nil
}

func verifyFacts(ctx context.Context, postgres *pgxpool.Pool, seeded fixture) error {
	var userStatus string
	var administrativelyDisabled bool
	var revision int64
	var spaceStatus, deviceStatus string
	var deviceRevoked, sessionRevoked, entitlementRevoked bool
	err := postgres.QueryRow(ctx, `
		SELECT u.status, u.administratively_disabled, u.administrative_revision,
		       ps.status, d.status, d.revoked_at IS NOT NULL, s.revoked_at IS NOT NULL,
		       COALESCE(bool_and(oe.revoked_at IS NOT NULL), FALSE)
		FROM users u
		JOIN personal_spaces ps ON ps.owner_user_id = u.id
		JOIN devices d ON d.user_id = u.id AND d.id = $2
		JOIN sessions s ON s.user_id = u.id AND s.device_id = d.id AND s.id = $3
		LEFT JOIN offline_entitlement_issuances oe ON oe.user_id = u.id AND oe.device_id = d.id
		WHERE u.id = $1
		GROUP BY u.id, ps.status, d.id, s.id
	`, seeded.UserID, seeded.DeviceID, seeded.SessionID).Scan(
		&userStatus, &administrativelyDisabled, &revision, &spaceStatus, &deviceStatus,
		&deviceRevoked, &sessionRevoked, &entitlementRevoked,
	)
	if err != nil || userStatus != "disabled" || !administrativelyDisabled ||
		revision < seeded.InitialRevision+2 || spaceStatus != "disabled" || deviceStatus != "revoked" ||
		!deviceRevoked || !sessionRevoked || !entitlementRevoked {
		return errors.New("Cloud E2E final account state is incomplete")
	}
	var officialAudienceStatus string
	var officialAudienceDisabled bool
	if err := postgres.QueryRow(ctx, `
		SELECT status, administratively_disabled FROM users WHERE id = $1
	`, seeded.OfficialAudienceUserID).Scan(&officialAudienceStatus, &officialAudienceDisabled); err != nil ||
		officialAudienceStatus != "active" || officialAudienceDisabled {
		return errors.New("Cloud E2E official audience account is not active")
	}

	sessionCount, err := matchingOperationAuditCount(ctx, postgres, seeded, "revoke_session", "session_admin_revoked", seeded.SessionID)
	if err != nil || sessionCount < 1 {
		return errors.New("Cloud E2E session operation or audit is missing")
	}
	disableCount, err := matchingOperationAuditCount(ctx, postgres, seeded, "disable_user", "account_disabled", seeded.UserID)
	if err != nil || disableCount < 1 {
		return errors.New("Cloud E2E account operation or audit is missing")
	}

	var operationLeaks, auditLeaks, ciphertextLeaks int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM admin_operations o
		WHERE (
			(o.target_type = 'user' AND o.target_id = $1) OR
			(o.target_type = 'device' AND o.target_id = $2) OR
			(o.target_type = 'session' AND o.target_id = $3)
		) AND strpos(o::text, $4) > 0
	`, seeded.UserID, seeded.DeviceID, seeded.SessionID, seeded.RawIdentity).Scan(&operationLeaks); err != nil {
		return errors.New("Cloud E2E operation leakage check failed")
	}
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM audit_events a
		WHERE a.subject_user_id = $1 AND strpos(a::text, $2) > 0
	`, seeded.UserID, seeded.RawIdentity).Scan(&auditLeaks); err != nil {
		return errors.New("Cloud E2E audit leakage check failed")
	}
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM identities i
		WHERE i.user_id = $1 AND position(convert_to($2, 'UTF8') in i.ciphertext) > 0
	`, seeded.UserID, seeded.RawIdentity).Scan(&ciphertextLeaks); err != nil {
		return errors.New("Cloud E2E identity leakage check failed")
	}
	if operationLeaks != 0 || auditLeaks != 0 || ciphertextLeaks != 0 {
		return errors.New("Cloud E2E detected an exact identity leak")
	}
	return nil
}

func matchingOperationAuditCount(
	ctx context.Context,
	postgres *pgxpool.Pool,
	seeded fixture,
	action, eventType string,
	targetID uuid.UUID,
) (int, error) {
	var count int
	err := postgres.QueryRow(ctx, `
		SELECT count(*)
		FROM admin_operations o
		WHERE o.action = $1 AND o.target_id = $2 AND o.status = 'succeeded'
		  AND o.result_revision >= $3
		  AND EXISTS (
			SELECT 1 FROM audit_events a
			WHERE a.event_type = $4 AND a.outcome = 'success'
			  AND a.subject_user_id = $5 AND a.object_id = o.target_id
			  AND a.request_id = o.request_id
			  AND a.metadata->>'operation_id' = o.operation_id::text
		  )
	`, action, targetID, seeded.InitialRevision+1, eventType, seeded.UserID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
