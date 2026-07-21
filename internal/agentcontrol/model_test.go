package agentcontrol

import (
	"testing"

	"github.com/google/uuid"
)

func TestAssetOwnerValidate(t *testing.T) {
	personalSpaceID := uuid.New()
	userID := uuid.New()
	workspaceID := uuid.New()
	organizationID := uuid.New()

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
		{
			name:  "ORGANIZATION owner",
			owner: AssetOwner{Scope: OwnerScopeOrganization, OrganizationID: organizationID},
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
			name: "USER carries organization",
			owner: AssetOwner{
				Scope: OwnerScopeUser, PersonalSpaceID: personalSpaceID, UserID: userID, OrganizationID: organizationID,
			},
			wantErr: true,
		},
		{
			name:    "WORKSPACE carries organization",
			owner:   AssetOwner{Scope: OwnerScopeWorkspace, WorkspaceID: workspaceID, OrganizationID: organizationID},
			wantErr: true,
		},
		{
			name:    "ORGANIZATION missing organization",
			owner:   AssetOwner{Scope: OwnerScopeOrganization},
			wantErr: true,
		},
		{
			name: "ORGANIZATION carries USER owner",
			owner: AssetOwner{
				Scope: OwnerScopeOrganization, OrganizationID: organizationID,
				PersonalSpaceID: personalSpaceID, UserID: userID,
			},
			wantErr: true,
		},
		{
			name:    "ORGANIZATION carries workspace",
			owner:   AssetOwner{Scope: OwnerScopeOrganization, OrganizationID: organizationID, WorkspaceID: workspaceID},
			wantErr: true,
		},
		{
			name:  "unsupported scope",
			owner: AssetOwner{Scope: OwnerScope("PLATFORM"), OrganizationID: organizationID}, wantErr: true,
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
	organizationID := uuid.New()

	userOwner := AssetOwner{Scope: OwnerScopeUser, PersonalSpaceID: personalSpaceID, UserID: userID}
	if got := userOwner.Key(); got != userID {
		t.Fatalf("USER Key() = %s, want %s", got, userID)
	}
	workspaceOwner := AssetOwner{Scope: OwnerScopeWorkspace, WorkspaceID: workspaceID}
	if got := workspaceOwner.Key(); got != workspaceID {
		t.Fatalf("WORKSPACE Key() = %s, want %s", got, workspaceID)
	}
	organizationOwner := AssetOwner{Scope: OwnerScopeOrganization, OrganizationID: organizationID}
	if got := organizationOwner.Key(); got != organizationID {
		t.Fatalf("ORGANIZATION Key() = %s, want %s", got, organizationID)
	}
}
