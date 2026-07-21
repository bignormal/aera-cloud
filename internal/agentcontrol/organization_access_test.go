package agentcontrol

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRequireOrganizationAgentAccessReadsCurrentDatabaseSnapshot(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 0x61)
	organizationID := uuid.New()
	firstPolicyID := uuid.New()
	firstPolicy, err := organization.CanonicalizePolicy(organization.DefaultPolicyDocument())
	if err != nil {
		t.Fatalf("CanonicalizePolicy(first) error = %v", err)
	}

	tx, err := fixture.postgres.Begin(fixture.ctx)
	if err != nil {
		t.Fatalf("begin Organization fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organizations (
			id, display_name, status, revision, current_policy_snapshot_id, created_at, updated_at
		) VALUES ($1, 'Organization access', 'active', 1, $2, $3, $3)
	`, organizationID, firstPolicyID, fixture.now); err != nil {
		t.Fatalf("insert Organization: %v", err)
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document, content_digest,
			issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES ($1, $2, 1, 1, $3, $4, 'agentera://test', 'organization-test', $5, $6, $7)
	`, firstPolicyID, organizationID, firstPolicy.CanonicalJSON, firstPolicy.ContentDigest[:],
		bytes.Repeat([]byte{0x31}, 64), owner.UserID, fixture.now); err != nil {
		t.Fatalf("insert first Organization policy: %v", err)
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO organization_memberships (
			organization_id, user_id, role, revision, joined_at, updated_at
		) VALUES ($1, $2, 'owner', 1, $3, $3)
	`, organizationID, owner.UserID, fixture.now); err != nil {
		t.Fatalf("insert Organization Owner: %v", err)
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatalf("commit Organization fixture: %v", err)
	}

	access, err := requireOrganizationAgentAccess(
		fixture.ctx, fixture.postgres, owner, organizationID, organizationAgentPublish, false,
	)
	if err != nil {
		t.Fatalf("requireOrganizationAgentAccess(first) error = %v", err)
	}
	if access.Role != "owner" || access.PolicySnapshotID != firstPolicyID || access.PolicyVersion != 1 {
		t.Fatalf("first access = %+v", access)
	}

	secondPolicyID := uuid.New()
	secondDocument := organization.DefaultPolicyDocument()
	secondDocument.Tools.Allowlist = []string{"files.read"}
	secondPolicy, err := organization.CanonicalizePolicy(secondDocument)
	if err != nil {
		t.Fatalf("CanonicalizePolicy(second) error = %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document, content_digest,
			issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES ($1, $2, 2, 1, $3, $4, 'agentera://test', 'organization-test', $5, $6, $7)
	`, secondPolicyID, organizationID, secondPolicy.CanonicalJSON, secondPolicy.ContentDigest[:],
		bytes.Repeat([]byte{0x32}, 64), owner.UserID, fixture.now.Add(1)); err != nil {
		t.Fatalf("insert second Organization policy: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations
		SET current_policy_snapshot_id = $2, revision = revision + 1, updated_at = $3
		WHERE id = $1
	`, organizationID, secondPolicyID, fixture.now.Add(1)); err != nil {
		t.Fatalf("advance current Organization policy: %v", err)
	}

	access, err = requireOrganizationAgentAccess(
		fixture.ctx, fixture.postgres, owner, organizationID, organizationAgentPublish, false,
	)
	if err != nil {
		t.Fatalf("requireOrganizationAgentAccess(second) error = %v", err)
	}
	if access.PolicySnapshotID != secondPolicyID || access.PolicyVersion != 2 ||
		!slices.Equal(access.PolicyDocument.Tools.Allowlist, []string{"files.read"}) {
		t.Fatalf("current access did not use second policy: %+v", access)
	}
}

func TestRequireOrganizationAgentAccessUsesCurrentLifecycleRoleAndPolicy(t *testing.T) {
	organizationID := uuid.New()
	ownerID := uuid.New()
	adminID := uuid.New()
	auditorID := uuid.New()
	memberID := uuid.New()
	policyID := uuid.New()
	policy, err := organization.CanonicalizePolicy(organization.DefaultPolicyDocument())
	if err != nil {
		t.Fatalf("CanonicalizePolicy() error = %v", err)
	}
	queryer := organizationAccessQueryer{rows: map[uuid.UUID]organizationAccessRow{
		ownerID:   {organizationID: organizationID, status: "active", role: "owner", policyID: policyID, policyVersion: 7, policy: policy.CanonicalJSON},
		adminID:   {organizationID: organizationID, status: "active", role: "admin", policyID: policyID, policyVersion: 7, policy: policy.CanonicalJSON},
		auditorID: {organizationID: organizationID, status: "active", role: "auditor", policyID: policyID, policyVersion: 7, policy: policy.CanonicalJSON},
		memberID:  {organizationID: organizationID, status: "active", role: "member", policyID: policyID, policyVersion: 7, policy: policy.CanonicalJSON},
	}}

	tests := []struct {
		name     string
		user     uuid.UUID
		mode     OrganizationAgentAccessMode
		wantRole string
		wantErr  error
	}{
		{name: "owner publishes", user: ownerID, mode: organizationAgentPublish, wantRole: "owner"},
		{name: "admin reviews", user: adminID, mode: organizationAgentReview, wantRole: "admin"},
		{name: "auditor reads history", user: auditorID, mode: organizationAgentReviewRead, wantRole: "auditor"},
		{name: "member installs", user: memberID, mode: organizationAgentInstall, wantRole: "member"},
		{name: "auditor cannot install", user: auditorID, mode: organizationAgentInstall, wantErr: ErrOrganizationAgentForbidden},
		{name: "member cannot review", user: memberID, mode: organizationAgentReview, wantErr: ErrOrganizationAgentForbidden},
		{name: "outsider is hidden", user: uuid.New(), mode: organizationAgentRead, wantErr: ErrOrganizationAgentNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access, err := requireOrganizationAgentAccess(
				context.Background(), queryer, Principal{UserID: test.user}, organizationID, test.mode, false,
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if access.Role != test.wantRole {
				t.Fatalf("role = %q, want %q", access.Role, test.wantRole)
			}
			if test.wantErr == nil && (access.PolicySnapshotID != policyID || access.PolicyVersion != 7) {
				t.Fatalf("policy snapshot/version = %s/%d", access.PolicySnapshotID, access.PolicyVersion)
			}
		})
	}
}

func TestRequireOrganizationAgentAccessFailsClosedForLifecycleAndPolicy(t *testing.T) {
	organizationID := uuid.New()
	userID := uuid.New()
	policyID := uuid.New()
	policy, err := organization.CanonicalizePolicy(organization.DefaultPolicyDocument())
	if err != nil {
		t.Fatalf("CanonicalizePolicy() error = %v", err)
	}

	archived := organizationAccessQueryer{rows: map[uuid.UUID]organizationAccessRow{
		userID: {organizationID: organizationID, status: "archived", role: "owner", policyID: policyID, policyVersion: 2, policy: policy.CanonicalJSON},
	}}
	if _, err := requireOrganizationAgentAccess(
		context.Background(), archived, Principal{UserID: userID}, organizationID, organizationAgentPublish, false,
	); !errors.Is(err, ErrOrganizationArchived) {
		t.Fatalf("archived publish error = %v, want ErrOrganizationArchived", err)
	}
	if _, err := requireOrganizationAgentAccess(
		context.Background(), archived, Principal{UserID: userID}, organizationID, organizationAgentReviewRead, true,
	); err != nil {
		t.Fatalf("archived history read error = %v", err)
	}

	dissolved := organizationAccessQueryer{rows: map[uuid.UUID]organizationAccessRow{
		userID: {organizationID: organizationID, status: "dissolved", role: "owner", policyID: policyID, policyVersion: 2, policy: policy.CanonicalJSON},
	}}
	if _, err := requireOrganizationAgentAccess(
		context.Background(), dissolved, Principal{UserID: userID}, organizationID, organizationAgentRead, true,
	); !errors.Is(err, ErrOrganizationAgentNotFound) {
		t.Fatalf("dissolved read error = %v, want ErrOrganizationAgentNotFound", err)
	}

	malformed := organizationAccessQueryer{rows: map[uuid.UUID]organizationAccessRow{
		userID: {organizationID: organizationID, status: "active", role: "owner", policyID: policyID, policyVersion: 2, policy: []byte(`{"unexpected":true}`)},
	}}
	if _, err := requireOrganizationAgentAccess(
		context.Background(), malformed, Principal{UserID: userID}, organizationID, organizationAgentRead, false,
	); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("malformed policy error = %v, want ErrServiceUnavailable", err)
	}
}

func TestIntersectOrganizationAgentPolicyOnlyNarrows(t *testing.T) {
	platform := organization.DefaultPolicyDocument()
	platform.Models.Allowlist = []organization.ModelIdentifier{
		{Provider: "openai", Model: "gpt-5.6"},
		{Provider: "anthropic", Model: "claude-opus-5"},
	}
	platform.Tools.Allowlist = []string{"files.read", "shell", "web.search"}
	organizationPolicy := organization.DefaultPolicyDocument()
	organizationPolicy.Models.Allowlist = []organization.ModelIdentifier{
		{Provider: "openai", Model: "gpt-5.6"},
	}
	organizationPolicy.Tools.Allowlist = []string{"files.read", "web.search"}
	version := AgentPolicyConstraints{
		AllowedProviders: []string{"anthropic", "openai"},
		AllowedModels:    []string{"claude-opus-5", "gpt-5.6"},
		AllowedTools:     []string{"files.read", "shell"},
	}

	effective, err := IntersectOrganizationAgentPolicy(platform, organizationPolicy, version)
	if err != nil {
		t.Fatalf("IntersectOrganizationAgentPolicy() error = %v", err)
	}
	if !slices.Equal(effective.AllowedProviders, []string{"openai"}) {
		t.Fatalf("providers = %v, want [openai]", effective.AllowedProviders)
	}
	if !slices.Equal(effective.AllowedModels, []string{"gpt-5.6"}) {
		t.Fatalf("models = %v, want [gpt-5.6]", effective.AllowedModels)
	}
	if !slices.Equal(effective.AllowedTools, []string{"files.read"}) {
		t.Fatalf("tools = %v, want [files.read]", effective.AllowedTools)
	}

	version.AllowedProviders[0] = "mutated"
	organizationPolicy.Tools.Allowlist[0] = "mutated"
	if effective.AllowedProviders[0] != "openai" || effective.AllowedTools[0] != "files.read" {
		t.Fatal("effective policy aliases caller storage")
	}
}

func TestIntersectOrganizationAgentPolicyRejectsEmptyRequiredSetAndPairMismatch(t *testing.T) {
	platform := organization.DefaultPolicyDocument()
	organizationPolicy := organization.DefaultPolicyDocument()
	organizationPolicy.Models.Allowlist = []organization.ModelIdentifier{
		{Provider: "openai", Model: "gpt-5.6"},
		{Provider: "anthropic", Model: "claude-opus-5"},
	}

	_, err := IntersectOrganizationAgentPolicy(platform, organizationPolicy, AgentPolicyConstraints{
		AllowedProviders: []string{"openai"},
		AllowedModels:    []string{"claude-opus-5"},
		AllowedTools:     []string{},
	})
	if !errors.Is(err, ErrOrganizationPublicationPolicyBlocked) {
		t.Fatalf("pair mismatch error = %v, want ErrOrganizationPublicationPolicyBlocked", err)
	}

	organizationPolicy.Models.Allowlist = nil
	organizationPolicy.Tools.Allowlist = []string{"files.read"}
	_, err = IntersectOrganizationAgentPolicy(platform, organizationPolicy, AgentPolicyConstraints{
		AllowedProviders: []string{"openai"},
		AllowedModels:    []string{"gpt-5.6"},
		AllowedTools:     []string{"shell"},
	})
	if !errors.Is(err, ErrOrganizationPublicationPolicyBlocked) {
		t.Fatalf("empty required tool error = %v, want ErrOrganizationPublicationPolicyBlocked", err)
	}
}

type organizationAccessQueryer struct {
	rows map[uuid.UUID]organizationAccessRow
}

func (q organizationAccessQueryer) QueryRow(_ context.Context, _ string, arguments ...any) pgx.Row {
	if len(arguments) != 2 {
		return organizationAccessRow{err: errors.New("unexpected Organization access query arguments")}
	}
	userID, ok := arguments[1].(uuid.UUID)
	if !ok {
		return organizationAccessRow{err: errors.New("Organization access user ID is not a UUID")}
	}
	row, found := q.rows[userID]
	if !found {
		return organizationAccessRow{err: pgx.ErrNoRows}
	}
	return row
}

type organizationAccessRow struct {
	organizationID uuid.UUID
	status         string
	role           string
	policyID       uuid.UUID
	policyVersion  int64
	policy         []byte
	err            error
}

func (row organizationAccessRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	*destinations[0].(*uuid.UUID) = row.organizationID
	*destinations[1].(*string) = row.status
	*destinations[2].(*string) = row.role
	*destinations[3].(*uuid.UUID) = row.policyID
	*destinations[4].(*int64) = row.policyVersion
	*destinations[5].(*[]byte) = append([]byte(nil), row.policy...)
	return nil
}
