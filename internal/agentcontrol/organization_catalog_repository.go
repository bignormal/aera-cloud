package agentcontrol

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const organizationDefinitionQuery = `
	SELECT id, display_name, COALESCE(icon_media_type, ''), icon_data, status,
		latest_version_id, created_at, updated_at
	FROM agent_definitions
	WHERE owner_scope = 'ORGANIZATION' AND organization_id = $1 AND id = $2
`

const organizationVersionQuery = `
	SELECT id, definition_id, version_number, canonical_manifest::text, bundle::text, content_digest,
		signing_key_id, signature, runtime_minimum_version,
		COALESCE(runtime_maximum_version_exclusive, ''), published_at
	FROM agent_versions
	WHERE owner_scope = 'ORGANIZATION' AND organization_id = $1 AND id = $2
`

func (r *PostgresRepository) FindOrganizationDefinition(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	definitionID uuid.UUID,
) (Definition, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) ||
		organizationID == uuid.Nil || definitionID == uuid.Nil {
		return Definition{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Definition{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireOrganizationAgentAccess(
		ctx, tx, principal, organizationID, organizationAgentRead, true,
	); err != nil {
		return Definition{}, false, err
	}
	definition, err := loadOrganizationDefinition(ctx, tx, organizationID, definitionID)
	if errors.Is(err, ErrNotFound) {
		return Definition{}, false, commitTransaction(ctx, tx)
	}
	if err != nil {
		return Definition{}, false, err
	}
	return definition, true, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) ListOrganizationDefinitions(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
) ([]Definition, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireOrganizationAgentAccess(
		ctx, tx, principal, organizationID, organizationAgentRead, true,
	); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, display_name, COALESCE(icon_media_type, ''), icon_data, status,
			latest_version_id, created_at, updated_at
		FROM agent_definitions
		WHERE owner_scope = 'ORGANIZATION' AND organization_id = $1
		ORDER BY updated_at DESC, id
	`, organizationID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	definitions := make([]Definition, 0)
	for rows.Next() {
		definition, scanErr := scanDefinition(rows)
		if scanErr != nil {
			rows.Close()
			return nil, ErrServiceUnavailable
		}
		definitions = append(definitions, definition)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, ErrServiceUnavailable
	}
	return definitions, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) ListOrganizationVersions(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	definitionID uuid.UUID,
) ([]Version, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) ||
		organizationID == uuid.Nil || definitionID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireOrganizationAgentAccess(
		ctx, tx, principal, organizationID, organizationAgentRead, true,
	); err != nil {
		return nil, err
	}
	if _, err := loadOrganizationDefinition(ctx, tx, organizationID, definitionID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, definition_id, version_number, canonical_manifest::text, bundle::text, content_digest,
			signing_key_id, signature, runtime_minimum_version,
			COALESCE(runtime_maximum_version_exclusive, ''), published_at
		FROM agent_versions
		WHERE owner_scope = 'ORGANIZATION' AND organization_id = $1 AND definition_id = $2
		ORDER BY version_number DESC
	`, organizationID, definitionID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	versions := make([]Version, 0)
	for rows.Next() {
		version, scanErr := scanVersion(rows)
		if scanErr != nil {
			rows.Close()
			return nil, ErrServiceUnavailable
		}
		versions = append(versions, version)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, ErrServiceUnavailable
	}
	return versions, commitTransaction(ctx, tx)
}

func loadOrganizationDefinition(
	ctx context.Context,
	queryer queryRower,
	organizationID uuid.UUID,
	definitionID uuid.UUID,
) (Definition, error) {
	definition, err := scanDefinition(queryer.QueryRow(
		ctx, organizationDefinitionQuery, organizationID, definitionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Definition{}, ErrNotFound
	}
	if err != nil {
		return Definition{}, ErrServiceUnavailable
	}
	return definition, nil
}

func loadOrganizationVersion(
	ctx context.Context,
	queryer queryRower,
	organizationID uuid.UUID,
	versionID uuid.UUID,
) (Version, error) {
	version, err := scanVersion(queryer.QueryRow(
		ctx, organizationVersionQuery, organizationID, versionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, ErrServiceUnavailable
	}
	return version, nil
}
