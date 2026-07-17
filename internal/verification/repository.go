package verification

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
}

func (r *PostgresRepository) ExistsByIdempotency(ctx context.Context, hash []byte) (bool, error) {
	var exists bool
	if err := r.postgres.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM verification_challenges WHERE idempotency_key_hash = $1)`,
		hash,
	).Scan(&exists); err != nil {
		return false, errors.New("verification idempotency state could not be read")
	}
	return exists, nil
}

func (r *PostgresRepository) Latest(
	ctx context.Context,
	targetHMACs [][]byte,
	purpose Purpose,
) (Challenge, bool, error) {
	var latest Challenge
	found := false
	for _, targetHMAC := range targetHMACs {
		candidate, ok, err := r.latestForTarget(ctx, targetHMAC, purpose)
		if err != nil {
			return Challenge{}, false, err
		}
		if ok && (!found || candidate.CreatedAt.After(latest.CreatedAt)) {
			latest = candidate
			found = true
		}
	}
	return latest, found, nil
}

func (r *PostgresRepository) latestForTarget(
	ctx context.Context,
	targetHMAC []byte,
	purpose Purpose,
) (Challenge, bool, error) {
	var challenge Challenge
	var kind string
	var purposeText string
	var failedAttempts int16
	var consumedAt pgtype.Timestamptz
	var invalidatedAt pgtype.Timestamptz
	err := r.postgres.QueryRow(ctx, `
		SELECT
			id,
			purpose,
			identity_kind,
			target_lookup_key_id,
			target_lookup_hmac,
			code_key_id,
			code_hmac,
			idempotency_key_hash,
			expires_at,
			resend_after,
			failed_attempts,
			consumed_at,
			invalidated_at,
			created_at
		FROM verification_challenges
		WHERE target_lookup_hmac = $1 AND purpose = $2
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, targetHMAC, purpose).Scan(
		&challenge.ID,
		&purposeText,
		&kind,
		&challenge.TargetLookupKeyID,
		&challenge.TargetLookupHMAC,
		&challenge.CodeKeyID,
		&challenge.CodeHMAC,
		&challenge.IdempotencyKeyHash,
		&challenge.ExpiresAt,
		&challenge.ResendAfter,
		&failedAttempts,
		&consumedAt,
		&invalidatedAt,
		&challenge.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, errors.New("verification challenge could not be read")
	}
	challenge.Purpose = Purpose(purposeText)
	challenge.IdentityKind = secure.IdentityKind(kind)
	challenge.FailedAttempts = int(failedAttempts)
	if consumedAt.Valid {
		value := consumedAt.Time
		challenge.ConsumedAt = &value
	}
	if invalidatedAt.Valid {
		value := invalidatedAt.Time
		challenge.InvalidatedAt = &value
	}
	return challenge, true, nil
}

func (r *PostgresRepository) SaveAfterDelivery(ctx context.Context, challenge Challenge) error {
	_, err := r.postgres.Exec(ctx, `
		INSERT INTO verification_challenges (
			id,
			purpose,
			identity_kind,
			target_lookup_key_id,
			target_lookup_hmac,
			code_key_id,
			code_hmac,
			idempotency_key_hash,
			expires_at,
			resend_after,
			failed_attempts,
			consumed_at,
			invalidated_at,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`,
		challenge.ID,
		challenge.Purpose,
		challenge.IdentityKind,
		challenge.TargetLookupKeyID,
		challenge.TargetLookupHMAC,
		challenge.CodeKeyID,
		challenge.CodeHMAC,
		challenge.IdempotencyKeyHash,
		challenge.ExpiresAt,
		challenge.ResendAfter,
		challenge.FailedAttempts,
		challenge.ConsumedAt,
		challenge.InvalidatedAt,
		challenge.CreatedAt,
	)
	if err != nil {
		return errors.New("verification challenge could not be saved")
	}
	return nil
}

func (r *PostgresRepository) Consume(
	ctx context.Context,
	targetHMAC []byte,
	purpose Purpose,
	codeHMAC []byte,
	now time.Time,
) error {
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("verification challenge transaction could not start")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var challengeID [16]byte
	var expectedCodeHMAC []byte
	var failedAttempts int16
	err = tx.QueryRow(ctx, `
		SELECT id, code_hmac, failed_attempts
		FROM verification_challenges
		WHERE target_lookup_hmac = $1
		  AND purpose = $2
		  AND consumed_at IS NULL
		  AND invalidated_at IS NULL
		  AND expires_at > $3
		ORDER BY created_at DESC, id DESC
		LIMIT 1
		FOR UPDATE
	`, targetHMAC, purpose, now).Scan(&challengeID, &expectedCodeHMAC, &failedAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrChallengeNotFound
	}
	if err != nil {
		return errors.New("verification challenge could not be locked")
	}

	if len(expectedCodeHMAC) != sha256DigestSize || len(codeHMAC) != sha256DigestSize ||
		subtle.ConstantTimeCompare(expectedCodeHMAC, codeHMAC) != 1 {
		failedAttempts++
		if failedAttempts >= 5 {
			_, err = tx.Exec(ctx, `
				UPDATE verification_challenges
				SET failed_attempts = $2, invalidated_at = $3
				WHERE id = $1
			`, challengeID, failedAttempts, now)
		} else {
			_, err = tx.Exec(ctx, `
				UPDATE verification_challenges
				SET failed_attempts = $2
				WHERE id = $1
			`, challengeID, failedAttempts)
		}
		if err != nil {
			return errors.New("verification failure state could not be saved")
		}
		if err := tx.Commit(ctx); err != nil {
			return errors.New("verification failure state could not be committed")
		}
		return ErrCodeMismatch
	}

	if _, err := tx.Exec(ctx, `
		UPDATE verification_challenges
		SET consumed_at = $2
		WHERE id = $1
	`, challengeID, now); err != nil {
		return errors.New("verification challenge could not be consumed")
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("verification challenge consumption could not be committed")
	}
	return nil
}

const sha256DigestSize = 32
