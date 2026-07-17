package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/bignormal/aera-cloud/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationAdvisoryLockID int64 = 4_167_372_001

type migration struct {
	version  int64
	name     string
	contents []byte
	checksum [sha256.Size]byte
}

func ApplyMigrations(ctx context.Context, postgres *pgxpool.Pool) error {
	loaded, err := loadMigrations(migrations.FS)
	if err != nil {
		return err
	}
	tx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("database migration transaction could not start")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationAdvisoryLockID); err != nil {
		return errors.New("database migration lock could not be acquired")
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT PRIMARY KEY,
			name TEXT NOT NULL,
			checksum BYTEA NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT schema_migrations_checksum_length_check CHECK (octet_length(checksum) = 32)
		)
	`); err != nil {
		return errors.New("database migration ledger could not be prepared")
	}

	for _, item := range loaded {
		var existingChecksum []byte
		err := tx.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version = $1`, item.version).Scan(&existingChecksum)
		switch {
		case err == nil:
			if !equalChecksum(existingChecksum, item.checksum[:]) {
				return fmt.Errorf("migration %s checksum does not match the applied version", item.name)
			}
			continue
		case !errors.Is(err, pgx.ErrNoRows):
			return errors.New("database migration ledger could not be read")
		}

		if _, err := tx.Exec(ctx, string(item.contents)); err != nil {
			return fmt.Errorf("migration %s failed: %w", item.name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
			item.version,
			item.name,
			item.checksum[:],
		); err != nil {
			return errors.New("database migration ledger could not be updated")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.New("database migrations could not be committed")
	}
	return nil
}

func loadMigrations(source fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, errors.New("embedded migrations could not be listed")
	}
	loaded := make([]migration, 0, len(entries))
	seenVersions := make(map[int64]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		separator := strings.IndexByte(entry.Name(), '_')
		if separator <= 0 {
			return nil, fmt.Errorf("migration filename %s has no numeric prefix", entry.Name())
		}
		version, err := strconv.ParseInt(entry.Name()[:separator], 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration filename %s has an invalid version", entry.Name())
		}
		if _, duplicate := seenVersions[version]; duplicate {
			return nil, fmt.Errorf("migration version %d is duplicated", version)
		}
		contents, err := fs.ReadFile(source, entry.Name())
		if err != nil || len(strings.TrimSpace(string(contents))) == 0 {
			return nil, fmt.Errorf("migration %s could not be read", entry.Name())
		}
		seenVersions[version] = struct{}{}
		loaded = append(loaded, migration{
			version:  version,
			name:     entry.Name(),
			contents: contents,
			checksum: sha256.Sum256(contents),
		})
	}
	if len(loaded) == 0 {
		return nil, errors.New("no embedded database migrations were found")
	}
	sort.Slice(loaded, func(left, right int) bool { return loaded[left].version < loaded[right].version })
	return loaded, nil
}

func equalChecksum(left, right []byte) bool {
	if len(left) != sha256.Size || len(right) != sha256.Size {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
