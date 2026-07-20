package agentcontrol

import (
	"testing"

	"github.com/google/uuid"
)

func TestAssetOwnerValidate(t *testing.T) {
	personalSpaceID := uuid.New()
	userID := uuid.New()
	workspaceID := uuid.New()

	tests := []struct {
		name    string
		owner   AssetOwner
		wantErr bool
	}{
		{
			name: "USER owner",
			owner: AssetOwner{
				Scope: OwnerScopeUser, PersonalSpaceID: personalSpaceID, UserID: userID,
			},
		},
		{
			name:  "WORKSPACE owner",
			owner: AssetOwner{Scope: OwnerScopeWorkspace, WorkspaceID: workspaceID},
		},
		{name: "empty owner", owner: AssetOwner{}, wantErr: true},
		{
			name:  "USER missing personal space",
			owner: AssetOwner{Scope: OwnerScopeUser, UserID: userID}, wantErr: true,
		},
		{
			name: "USER carries workspace",
			owner: AssetOwner{
				Scope: OwnerScopeUser, PersonalSpaceID: personalSpaceID, UserID: userID, WorkspaceID: workspaceID,
			},
			wantErr: true,
		},
		{
			name: "WORKSPACE carries USER owner",
			owner: AssetOwner{
				Scope: OwnerScopeWorkspace, PersonalSpaceID: personalSpaceID, UserID: userID, WorkspaceID: workspaceID,
			},
			wantErr: true,
		},
		{
			name:  "unsupported scope",
			owner: AssetOwner{Scope: OwnerScope("ORGANIZATION"), WorkspaceID: workspaceID}, wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.owner.Validate()
			if test.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want failure")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestAssetOwnerKey(t *testing.T) {
	personalSpaceID := uuid.New()
	userID := uuid.New()
	workspaceID := uuid.New()

	userOwner := AssetOwner{Scope: OwnerScopeUser, PersonalSpaceID: personalSpaceID, UserID: userID}
	if got := userOwner.Key(); got != userID {
		t.Fatalf("USER Key() = %s, want %s", got, userID)
	}
	workspaceOwner := AssetOwner{Scope: OwnerScopeWorkspace, WorkspaceID: workspaceID}
	if got := workspaceOwner.Key(); got != workspaceID {
		t.Fatalf("WORKSPACE Key() = %s, want %s", got, workspaceID)
	}
}
