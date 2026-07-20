package workspace

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeDisplayNameUsesUnicodeScalarBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "trims Unicode space", value: "\u2003艾拉工作区\u3000", want: "艾拉工作区"},
		{name: "one scalar", value: "界", want: "界"},
		{name: "eighty scalars", value: strings.Repeat("界", 80), want: strings.Repeat("界", 80)},
		{name: "eighty one scalars", value: strings.Repeat("界", 81), wantErr: true},
		{name: "empty", value: "", wantErr: true},
		{name: "whitespace only", value: " \u2003\u3000 ", wantErr: true},
		{name: "embedded NUL", value: "艾\x00拉", wantErr: true},
		{name: "embedded newline", value: "艾\n拉", wantErr: true},
		{name: "trailing newline", value: "艾拉\n", wantErr: true},
		{name: "leading tab", value: "\t艾拉", wantErr: true},
		{name: "embedded delete control", value: "艾\x7f拉", wantErr: true},
		{name: "invalid UTF-8", value: string([]byte{0xff}), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeDisplayName(test.value)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("NormalizeDisplayName() error = %v, want ErrInvalidRequest", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("NormalizeDisplayName() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestWorkspaceStrictEnumsAndPositiveRevision(t *testing.T) {
	for _, value := range []string{"owner", "admin", "member"} {
		role, err := ParseRole(value)
		if err != nil || string(role) != value {
			t.Fatalf("ParseRole(%q) = %q, %v", value, role, err)
		}
	}
	for _, value := range []string{"", "Owner", "viewer", "member "} {
		if _, err := ParseRole(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ParseRole(%q) error = %v, want ErrInvalidRequest", value, err)
		}
	}

	for _, value := range []string{"active", "archived"} {
		status, err := ParseWorkspaceStatus(value)
		if err != nil || string(status) != value {
			t.Fatalf("ParseWorkspaceStatus(%q) = %q, %v", value, status, err)
		}
	}
	for _, value := range []string{"", "deleted", "ACTIVE"} {
		if _, err := ParseWorkspaceStatus(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ParseWorkspaceStatus(%q) error = %v, want ErrInvalidRequest", value, err)
		}
	}

	for _, value := range []string{"writable", "archived", "owner_unavailable"} {
		state, err := ParseMutationState(value)
		if err != nil || string(state) != value {
			t.Fatalf("ParseMutationState(%q) = %q, %v", value, state, err)
		}
	}
	if _, err := ParseMutationState("read_only"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ParseMutationState() error = %v, want ErrInvalidRequest", err)
	}

	if err := ValidateRevision(1); err != nil {
		t.Fatalf("ValidateRevision(1) error = %v", err)
	}
	for _, value := range []int64{0, -1} {
		if err := ValidateRevision(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ValidateRevision(%d) error = %v, want ErrInvalidRequest", value, err)
		}
	}
}

func TestActorValidationRejectsNilUUIDs(t *testing.T) {
	valid := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Actor.Validate() error = %v", err)
	}
	for _, actor := range []Actor{
		{UserID: uuid.Nil, DeviceID: valid.DeviceID},
		{UserID: valid.UserID, DeviceID: uuid.Nil},
	} {
		if err := actor.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Actor.Validate() error = %v, want ErrInvalidRequest", err)
		}
	}
}

func TestNormalizeWorkspaceValidatesAndCopiesUTCValues(t *testing.T) {
	location := time.FixedZone("UTC+8", 8*60*60)
	created := time.Date(2026, 7, 20, 9, 0, 0, 123, location)
	updated := created.Add(time.Hour)
	archived := updated.Add(time.Hour)
	input := Workspace{
		ID:            uuid.New(),
		DisplayName:   "\u2003合作空间\u3000",
		Status:        WorkspaceStatusArchived,
		Revision:      2,
		MutationState: MutationStateArchived,
		ActorRole:     RoleAdmin,
		MemberCount:   2,
		CreatedAt:     created,
		UpdatedAt:     updated,
		ArchivedAt:    &archived,
	}

	got, err := NormalizeWorkspace(input)
	if err != nil {
		t.Fatalf("NormalizeWorkspace() error = %v", err)
	}
	if got.DisplayName != "合作空间" || got.CreatedAt.Location() != time.UTC || got.UpdatedAt.Location() != time.UTC {
		t.Fatalf("NormalizeWorkspace() = %+v", got)
	}
	if got.ArchivedAt == nil || got.ArchivedAt.Location() != time.UTC || !got.ArchivedAt.Equal(archived) {
		t.Fatalf("ArchivedAt = %v, want UTC %v", got.ArchivedAt, archived)
	}
	if got.ArchivedAt == input.ArchivedAt {
		t.Fatal("NormalizeWorkspace() retained the caller's ArchivedAt pointer")
	}

	invalid := input
	invalid.ID = uuid.Nil
	if _, err := NormalizeWorkspace(invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil ID error = %v, want ErrInvalidRequest", err)
	}
	invalid = input
	invalid.Revision = 0
	if _, err := NormalizeWorkspace(invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero revision error = %v, want ErrInvalidRequest", err)
	}
	invalid = input
	invalid.Status = WorkspaceStatusActive
	invalid.MutationState = MutationStateWritable
	if _, err := NormalizeWorkspace(invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("active workspace with archived timestamp error = %v, want ErrInvalidRequest", err)
	}
	invalid = input
	invalid.Status = WorkspaceStatusArchived
	invalid.MutationState = MutationStateWritable
	if _, err := NormalizeWorkspace(invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("archived workspace with writable state error = %v, want ErrInvalidRequest", err)
	}
}
