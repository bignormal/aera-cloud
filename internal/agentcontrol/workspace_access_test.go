package agentcontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRequireWorkspaceAgentAccessFailsClosedForDiscoveryAndMutation(t *testing.T) {
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New()}
	workspaceID := uuid.New()
	for _, test := range []struct {
		name   string
		row    workspaceAccessRow
		mode   workspaceAgentAccessMode
		wanted error
	}{
		{
			name: "active member can discover",
			row:  workspaceAccessRow{workspaceStatus: "active", ownerStatus: "active", role: "member", actorStatus: "active", deviceActive: true, fixedOwner: true},
			mode: workspaceAgentRead,
		},
		{
			name: "member cannot publish",
			row:  workspaceAccessRow{workspaceStatus: "active", ownerStatus: "active", role: "member", actorStatus: "active", deviceActive: true, fixedOwner: true},
			mode: workspaceAgentPublish, wanted: ErrWorkspaceForbidden,
		},
		{
			name: "archived discovery is blocked",
			row:  workspaceAccessRow{workspaceStatus: "archived", ownerStatus: "active", role: "owner", actorStatus: "active", deviceActive: true, fixedOwner: true},
			mode: workspaceAgentRead, wanted: ErrWorkspaceArchived,
		},
		{
			name: "owner unavailable discovery is blocked",
			row:  workspaceAccessRow{workspaceStatus: "active", ownerStatus: "pending_deletion", role: "member", actorStatus: "active", deviceActive: true, fixedOwner: true},
			mode: workspaceAgentRead, wanted: ErrWorkspaceOwnerUnavailable,
		},
		{
			name: "unavailable owner receives stable discovery error",
			row:  workspaceAccessRow{workspaceStatus: "active", ownerStatus: "pending_deletion", role: "owner", actorStatus: "pending_deletion", deviceActive: true, fixedOwner: true},
			mode: workspaceAgentRead, wanted: ErrWorkspaceOwnerUnavailable,
		},
		{
			name: "outsider is non enumerating",
			row:  workspaceAccessRow{err: pgx.ErrNoRows},
			mode: workspaceAgentRead, wanted: ErrNotFound,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := requireWorkspaceAgentAccess(
				context.Background(), workspaceAccessQueryer{row: test.row}, principal,
				workspaceID, test.mode, true,
			)
			if !errors.Is(err, test.wanted) {
				t.Fatalf("requireWorkspaceAgentAccess() error = %v, want %v", err, test.wanted)
			}
		})
	}
}

type workspaceAccessQueryer struct {
	row workspaceAccessRow
}

func (q workspaceAccessQueryer) QueryRow(context.Context, string, ...any) pgx.Row {
	return q.row
}

type workspaceAccessRow struct {
	workspaceStatus string
	ownerStatus     string
	role            string
	actorStatus     string
	deviceActive    bool
	fixedOwner      bool
	err             error
}

func (r workspaceAccessRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	*destinations[0].(*string) = r.workspaceStatus
	*destinations[1].(*string) = r.ownerStatus
	*destinations[2].(*string) = r.role
	*destinations[3].(*string) = r.actorStatus
	*destinations[4].(*bool) = r.deviceActive
	*destinations[5].(*bool) = r.fixedOwner
	return nil
}
