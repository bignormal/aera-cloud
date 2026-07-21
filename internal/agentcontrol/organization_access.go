package agentcontrol

import (
	"context"
	"errors"

	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type OrganizationAgentAccessMode uint8

const (
	organizationAgentRead OrganizationAgentAccessMode = iota + 1
	organizationAgentReviewRead
	organizationAgentPublish
	organizationAgentReview
	organizationAgentInstall
)

type OrganizationAgentAccess struct {
	OrganizationID   uuid.UUID
	Role             string
	Status           string
	PolicySnapshotID uuid.UUID
	PolicyVersion    int64
	PolicyDocument   organization.PolicyDocument
}

const organizationAgentAccessQuery = `
	SELECT organization.id, organization.status, membership.role,
	       policy.id, policy.policy_version, policy.policy_document
	FROM organizations organization
	JOIN organization_memberships membership
	  ON membership.organization_id = organization.id AND membership.user_id = $2
	JOIN organization_policy_snapshots policy
	  ON policy.organization_id = organization.id
	 AND policy.id = organization.current_policy_snapshot_id
	WHERE organization.id = $1
`

func requireOrganizationAgentAccess(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	principal Principal,
	organizationID uuid.UUID,
	mode OrganizationAgentAccessMode,
	allowArchived bool,
) (OrganizationAgentAccess, error) {
	if principal.UserID == uuid.Nil || organizationID == uuid.Nil {
		return OrganizationAgentAccess{}, ErrOrganizationAgentNotFound
	}

	var access OrganizationAgentAccess
	var policyBytes []byte
	err := queryer.QueryRow(ctx, organizationAgentAccessQuery, organizationID, principal.UserID).Scan(
		&access.OrganizationID,
		&access.Status,
		&access.Role,
		&access.PolicySnapshotID,
		&access.PolicyVersion,
		&policyBytes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationAgentAccess{}, ErrOrganizationAgentNotFound
	}
	if err != nil || access.OrganizationID != organizationID ||
		access.PolicySnapshotID == uuid.Nil || access.PolicyVersion <= 0 {
		return OrganizationAgentAccess{}, ErrServiceUnavailable
	}

	switch access.Status {
	case "active":
	case "archived":
		if !allowArchived || (mode != organizationAgentRead && mode != organizationAgentReviewRead) {
			return OrganizationAgentAccess{}, ErrOrganizationArchived
		}
	default:
		return OrganizationAgentAccess{}, ErrOrganizationAgentNotFound
	}
	if !organizationRoleAllows(access.Role, mode) {
		return OrganizationAgentAccess{}, ErrOrganizationAgentForbidden
	}

	policy, err := organization.DecodePolicyDocument(policyBytes)
	if err != nil {
		return OrganizationAgentAccess{}, ErrServiceUnavailable
	}
	access.PolicyDocument = policy
	return access, nil
}

func organizationRoleAllows(role string, mode OrganizationAgentAccessMode) bool {
	switch mode {
	case organizationAgentRead:
		return role == "owner" || role == "admin" || role == "auditor" || role == "member"
	case organizationAgentReviewRead:
		return role == "owner" || role == "admin" || role == "auditor"
	case organizationAgentPublish, organizationAgentReview:
		return role == "owner" || role == "admin"
	case organizationAgentInstall:
		return role == "owner" || role == "admin" || role == "member"
	default:
		return false
	}
}
