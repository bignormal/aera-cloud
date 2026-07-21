package agentcontrol

import (
	"context"
	"slices"

	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
)

type OrganizationAssetBlockerReader interface {
	OrganizationAssetBlockers(context.Context, uuid.UUID) ([]string, error)
}

type OrganizationAssetGuard struct {
	reader OrganizationAssetBlockerReader
}

func NewOrganizationAssetGuard(reader OrganizationAssetBlockerReader) OrganizationAssetGuard {
	return OrganizationAssetGuard{reader: reader}
}

func (g OrganizationAssetGuard) DissolutionBlockers(
	ctx context.Context,
	organizationID uuid.UUID,
) ([]string, error) {
	if organizationID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	if g.reader == nil {
		return nil, ErrServiceUnavailable
	}
	blockers, err := g.reader.OrganizationAssetBlockers(ctx, organizationID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	for _, blocker := range blockers {
		switch blocker {
		case "pending_submissions", "published_agents", "employee_installations":
		default:
			return nil, ErrServiceUnavailable
		}
	}
	result := append([]string(nil), blockers...)
	slices.Sort(result)
	return slices.Compact(result), nil
}

func (r *PostgresRepository) OrganizationAssetBlockers(
	ctx context.Context,
	organizationID uuid.UUID,
) ([]string, error) {
	if r == nil || r.postgres == nil || organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	var pendingSubmissions bool
	var publishedAgents bool
	var employeeInstallations bool
	err := r.postgres.QueryRow(ctx, `
		SELECT
			EXISTS (
				SELECT 1 FROM organization_agent_submissions
				WHERE organization_id = $1 AND status = 'pending'
			),
			(
				EXISTS (
					SELECT 1 FROM agent_definitions
					WHERE owner_scope = 'ORGANIZATION' AND organization_id = $1
				)
				OR EXISTS (
					SELECT 1 FROM agent_versions
					WHERE owner_scope = 'ORGANIZATION' AND organization_id = $1
				)
			),
			EXISTS (
				SELECT 1
				FROM installations installation
				JOIN agent_versions version ON version.id = installation.selected_version_id
				WHERE installation.owner_scope = 'USER'
				  AND version.owner_scope = 'ORGANIZATION'
				  AND version.organization_id = $1
			)
	`, organizationID).Scan(&pendingSubmissions, &publishedAgents, &employeeInstallations)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	blockers := make([]string, 0, 3)
	if pendingSubmissions {
		blockers = append(blockers, "pending_submissions")
	}
	if publishedAgents {
		blockers = append(blockers, "published_agents")
	}
	if employeeInstallations {
		blockers = append(blockers, "employee_installations")
	}
	return blockers, nil
}

var _ organization.AssetGuard = OrganizationAssetGuard{}
