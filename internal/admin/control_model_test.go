package admin

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateControlCommand(t *testing.T) {
	targetID, operationID, actorID, approvalID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	valid := Command{
		OperationID: operationID, ActorAdminID: actorID, RequestID: "req-control-1",
		ReasonCode: "session_cleanup", TicketReference: "OPS-123", Note: "manual support action",
		ExpectedRevision: 1,
	}
	tests := []struct {
		name    string
		action  Action
		target  uuid.UUID
		command Command
		wantErr bool
	}{
		{name: "session revoke", action: RevokeSession, target: targetID, command: valid},
		{name: "device revoke", action: RevokeDevice, target: targetID, command: valid},
		{name: "disable needs approval", action: DisableUser, target: targetID, command: valid, wantErr: true},
		{name: "enable needs approval", action: EnableUser, target: targetID, command: valid, wantErr: true},
		{name: "disable approved", action: DisableUser, target: targetID, command: func() Command { c := valid; c.ApprovalID = &approvalID; return c }()},
		{name: "enable approved", action: EnableUser, target: targetID, command: func() Command { c := valid; c.ApprovalID = &approvalID; return c }()},
		{name: "bad reason", action: RevokeSession, target: targetID, command: func() Command { c := valid; c.ReasonCode = "Bad Reason"; return c }(), wantErr: true},
		{name: "zero revision", action: RevokeSession, target: targetID, command: func() Command { c := valid; c.ExpectedRevision = 0; return c }(), wantErr: true},
		{name: "missing target", action: RevokeSession, command: valid, wantErr: true},
		{name: "missing operation", action: RevokeSession, target: targetID, command: func() Command { c := valid; c.OperationID = uuid.Nil; return c }(), wantErr: true},
		{name: "missing actor", action: RevokeSession, target: targetID, command: func() Command { c := valid; c.ActorAdminID = uuid.Nil; return c }(), wantErr: true},
		{name: "unknown action", action: Action("delete_user"), target: targetID, command: valid, wantErr: true},
		{name: "request id leading space", action: RevokeSession, target: targetID, command: func() Command { c := valid; c.RequestID = " req"; return c }(), wantErr: true},
		{name: "empty ticket when present", action: RevokeSession, target: targetID, command: func() Command { c := valid; c.TicketReference = " "; return c }(), wantErr: true},
		{name: "control in note", action: RevokeSession, target: targetID, command: func() Command { c := valid; c.Note = "unsafe\ntext"; return c }(), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateControlCommand(test.action, test.target, test.command)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr = %t", err, test.wantErr)
			}
		})
	}
}

func TestOperationValidation(t *testing.T) {
	now, id := time.Now().UTC(), uuid.New()
	tests := []struct {
		name    string
		value   Operation
		wantErr bool
	}{
		{name: "executing", value: Operation{ID: id, Status: OperationExecuting, UpdatedAt: now}},
		{name: "succeeded", value: Operation{ID: id, Status: OperationSucceeded, AdministrativeRevision: 2, UpdatedAt: now}},
		{name: "failed", value: Operation{ID: id, Status: OperationFailed, ErrorCode: "USER_NOT_FOUND", UpdatedAt: now}},
		{name: "conflict", value: Operation{ID: id, Status: OperationConflict, ErrorCode: "USER_STATE_CONFLICT", UpdatedAt: now}},
		{name: "success without revision", value: Operation{ID: id, Status: OperationSucceeded, UpdatedAt: now}, wantErr: true},
		{name: "success with error", value: Operation{ID: id, Status: OperationSucceeded, ErrorCode: "BAD_STATE", AdministrativeRevision: 2, UpdatedAt: now}, wantErr: true},
		{name: "failure without code", value: Operation{ID: id, Status: OperationFailed, UpdatedAt: now}, wantErr: true},
		{name: "bad error code", value: Operation{ID: id, Status: OperationFailed, ErrorCode: "bad-state", UpdatedAt: now}, wantErr: true},
		{name: "missing id", value: Operation{Status: OperationExecuting, UpdatedAt: now}, wantErr: true},
		{name: "missing update time", value: Operation{ID: id, Status: OperationExecuting}, wantErr: true},
		{name: "unknown status", value: Operation{ID: id, Status: OperationStatus("queued"), UpdatedAt: now}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateOperation(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr = %t", err, test.wantErr)
			}
		})
	}
}

func TestValidateOfficialOperationCommandEnforcesRoleAndApprovalSeparation(t *testing.T) {
	targetID, operationID, actorID := uuid.New(), uuid.New(), uuid.New()
	valid := OfficialOperationCommand{
		OperationID: operationID, ActorAdminID: actorID, ActorAdminRole: "developer",
		RequestID: "req-official-1", ReasonCode: "content_update", ExpectedRevision: 1,
		PayloadDigest: make([]byte, 32),
	}
	tests := []struct {
		name    string
		action  Action
		command OfficialOperationCommand
		wantErr bool
	}{
		{name: "developer draft", action: OfficialDraftUpdate, command: valid},
		{name: "wrong draft role", action: OfficialDraftUpdate, command: func() OfficialOperationCommand { c := valid; c.ActorAdminRole = "support"; return c }(), wantErr: true},
		{name: "reviewer", action: OfficialSubmissionReview, command: func() OfficialOperationCommand { c := valid; c.ActorAdminRole = "super_admin"; return c }()},
		{name: "operator release", action: OfficialReleasePause, command: func() OfficialOperationCommand { c := valid; c.ActorAdminRole = "operator"; return c }()},
		{name: "rollback requires approval", action: OfficialReleaseRollback, command: func() OfficialOperationCommand { c := valid; c.ActorAdminRole = "super_admin"; return c }(), wantErr: true},
		{name: "rollback separated", action: OfficialReleaseRollback, command: func() OfficialOperationCommand {
			c := valid
			c.ActorAdminRole = "super_admin"
			approval, requester := uuid.New(), uuid.New()
			c.ApprovalID, c.RequesterAdminID = &approval, &requester
			return c
		}()},
		{name: "self rollback", action: OfficialReleaseRollback, command: func() OfficialOperationCommand {
			c := valid
			c.ActorAdminRole = "super_admin"
			approval := uuid.New()
			c.ApprovalID, c.RequesterAdminID = &approval, &c.ActorAdminID
			return c
		}(), wantErr: true},
		{name: "bad payload digest", action: OfficialDraftUpdate, command: func() OfficialOperationCommand { c := valid; c.PayloadDigest = []byte{1}; return c }(), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateOfficialOperationCommand(test.action, targetID, test.command)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr = %t", err, test.wantErr)
			}
		})
	}
}
