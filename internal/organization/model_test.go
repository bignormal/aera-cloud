package organization

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeOrganizationNameUsesNFCAndUnicodeScalarBounds(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "trims Unicode space", value: "\u2003Aera 企业\u3000", want: "Aera 企业"},
		{name: "normalizes NFC", value: "Cafe\u0301", want: "Café"},
		{name: "one hundred twenty scalars", value: strings.Repeat("界", 120), want: strings.Repeat("界", 120)},
		{name: "one hundred twenty one scalars", value: strings.Repeat("界", 121), wantErr: true},
		{name: "empty", value: "", wantErr: true},
		{name: "whitespace only", value: " \u2003\u3000 ", wantErr: true},
		{name: "embedded NUL", value: "企\x00业", wantErr: true},
		{name: "trailing newline", value: "企业\n", wantErr: true},
		{name: "leading tab", value: "\t企业", wantErr: true},
		{name: "invalid UTF-8", value: string([]byte{0xff}), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeOrganizationName(test.value)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("NormalizeOrganizationName() error = %v, want ErrInvalidRequest", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("NormalizeOrganizationName() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestNormalizeDepartmentNameDerivesStableCaseFoldedKey(t *testing.T) {
	name, key, err := NormalizeDepartmentName("\u2003Straße\u3000")
	if err != nil || name != "Straße" || key != "strasse" {
		t.Fatalf("NormalizeDepartmentName() = %q, %q, %v", name, key, err)
	}
	otherName, otherKey, err := NormalizeDepartmentName("STRASSE")
	if err != nil || otherName != "STRASSE" || otherKey != key {
		t.Fatalf("case-folded Department = %q, %q, %v; want key %q", otherName, otherKey, err, key)
	}
	if _, _, err := NormalizeDepartmentName(strings.Repeat("部", 81)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("81-scalar Department error = %v, want ErrInvalidRequest", err)
	}
	if _, _, err := NormalizeDepartmentName("安全\n团队"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("control-character Department error = %v, want ErrInvalidRequest", err)
	}
}

func TestOrganizationStrictEnumsRevisionAndQuotas(t *testing.T) {
	for _, value := range []string{"owner", "admin", "auditor", "member"} {
		role, err := ParseRole(value)
		if err != nil || string(role) != value {
			t.Fatalf("ParseRole(%q) = %q, %v", value, role, err)
		}
	}
	for _, value := range []string{"", "Owner", "viewer", "member "} {
		if _, err := ParseRole(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ParseRole(%q) error = %v", value, err)
		}
	}

	for _, value := range []string{"active", "archived", "dissolved"} {
		status, err := ParseOrganizationStatus(value)
		if err != nil || string(status) != value {
			t.Fatalf("ParseOrganizationStatus(%q) = %q, %v", value, status, err)
		}
	}
	for _, value := range []string{"active", "archived"} {
		status, err := ParseDepartmentStatus(value)
		if err != nil || string(status) != value {
			t.Fatalf("ParseDepartmentStatus(%q) = %q, %v", value, status, err)
		}
	}
	for _, value := range []string{"pending", "accepted", "revoked", "expired"} {
		status, err := ParseInvitationStatus(value)
		if err != nil || string(status) != value {
			t.Fatalf("ParseInvitationStatus(%q) = %q, %v", value, status, err)
		}
	}
	for _, value := range []string{"writable", "archived", "dissolved"} {
		state, err := ParseMutationState(value)
		if err != nil || string(state) != value {
			t.Fatalf("ParseMutationState(%q) = %q, %v", value, state, err)
		}
	}
	for _, invalid := range []string{"", "ACTIVE", "deleted", "read_only"} {
		if _, err := ParseOrganizationStatus(invalid); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ParseOrganizationStatus(%q) error = %v", invalid, err)
		}
	}

	if err := ValidateRevision(1); err != nil {
		t.Fatalf("ValidateRevision(1) error = %v", err)
	}
	for _, value := range []int64{0, -1} {
		if err := ValidateRevision(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ValidateRevision(%d) error = %v", value, err)
		}
	}

	if err := (Quotas{Owned: 3, Members: 500, Departments: 50, PendingInvitations: 100}).Validate(); err != nil {
		t.Fatalf("valid Quotas.Validate() error = %v", err)
	}
	for _, quotas := range []Quotas{
		{Owned: 0, Members: 500, Departments: 50, PendingInvitations: 100},
		{Owned: 3, Members: 0, Departments: 50, PendingInvitations: 100},
		{Owned: 3, Members: 500, Departments: 0, PendingInvitations: 100},
		{Owned: 3, Members: 500, Departments: 50, PendingInvitations: 0},
	} {
		if err := quotas.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Quotas.Validate(%+v) error = %v", quotas, err)
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
			t.Fatalf("Actor.Validate() error = %v", err)
		}
	}
}

func TestOrganizationPublicTypesDoNotExposeRuntimeOrPrivateState(t *testing.T) {
	values := []any{
		OrganizationSummary{}, MemberSummary{}, DepartmentSummary{}, InvitationSummary{},
		PolicySummary{}, PolicySnapshot{}, AuditSummary{},
	}
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		if typeOf.NumField() == 0 {
			t.Fatalf("%s has no bounded public fields", typeOf.Name())
		}
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			identity := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{
				"profile", "memory", "session", "conversation", "credential", "api_key", "runtime_binding", "curator", "private_skill", "token_digest",
			} {
				if strings.Contains(identity, forbidden) {
					t.Fatalf("%s.%s exposes forbidden Organization field %q", typeOf.Name(), field.Name, forbidden)
				}
			}
		}
	}
}
