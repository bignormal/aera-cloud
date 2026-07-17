package entitlement

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
}

func (r *PostgresRepository) Record(ctx context.Context, issuance Issuance) error {
	if r == nil || r.postgres == nil {
		return ErrUnavailable
	}
	return recordIssuance(ctx, r.postgres, issuance)
}

func (r *PostgresRepository) RecordInTx(ctx context.Context, tx pgx.Tx, issuance Issuance) error {
	if r == nil || r.postgres == nil || tx == nil {
		return ErrUnavailable
	}
	return recordIssuance(ctx, tx, issuance)
}

type issuanceExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func recordIssuance(ctx context.Context, executor issuanceExecutor, issuance Issuance) error {
	if issuance.JTI == uuid.Nil || !validBinding(issuance.Binding) ||
		issuance.SigningKeyID == "" || issuance.PolicyVersion <= 0 || !issuance.ExpiresAt.After(issuance.IssuedAt) {
		return ErrUnavailable
	}
	_, err := executor.Exec(ctx, `
		INSERT INTO offline_entitlement_issuances (
			jti, user_id, device_id, personal_space_id, installation_id,
			signing_key_id, policy_version, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, issuance.JTI, issuance.Binding.UserID, issuance.Binding.DeviceID, issuance.Binding.PersonalSpaceID,
		issuance.Binding.InstallationID, issuance.SigningKeyID, issuance.PolicyVersion,
		issuance.IssuedAt, issuance.ExpiresAt)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
