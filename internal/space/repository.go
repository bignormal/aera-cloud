package space

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type Executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func InsertPersonal(
	ctx context.Context,
	executor Executor,
	spaceID uuid.UUID,
	ownerUserID uuid.UUID,
	displayName string,
	createdAt time.Time,
) error {
	_, err := executor.Exec(ctx, `
		INSERT INTO personal_spaces (
			id, owner_user_id, display_name, status, created_at, updated_at
		) VALUES ($1, $2, NULLIF($3, ''), 'active', $4, $4)
	`, spaceID, ownerUserID, displayName, createdAt)
	return err
}
