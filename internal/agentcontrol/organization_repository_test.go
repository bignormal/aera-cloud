package agentcontrol

import (
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
)

func TestOrganizationCatalogRolesAndNonDisclosure(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	publication := fixture.publishApprovedOrganizationAgent(t, 0xd1, 0xd2)

	for name, principal := range map[string]Principal{
		"owner": fixture.owner, "admin": fixture.admin,
		"auditor": fixture.auditor, "member": fixture.member,
	} {
		t.Run(name, func(t *testing.T) {
			definitions, err := fixture.repository.ListOrganizationDefinitions(
				fixture.ctx, principal, fixture.organizationID,
			)
			if err != nil || len(definitions) != 1 || definitions[0].ID != publication.Definition.ID {
				t.Fatalf("ListOrganizationDefinitions() = %+v error=%v", definitions, err)
			}
			definition, found, err := fixture.repository.FindOrganizationDefinition(
				fixture.ctx, principal, fixture.organizationID, publication.Definition.ID,
			)
			if err != nil || !found || definition.ID != publication.Definition.ID {
				t.Fatalf("FindOrganizationDefinition() = %+v found=%t error=%v", definition, found, err)
			}
			versions, err := fixture.repository.ListOrganizationVersions(
				fixture.ctx, principal, fixture.organizationID, publication.Definition.ID,
			)
			if err != nil || len(versions) != 1 || versions[0].ID != publication.Version.ID {
				t.Fatalf("ListOrganizationVersions() = %+v error=%v", versions, err)
			}
			version, found, err := fixture.repository.FindVersion(fixture.ctx, principal, publication.Version.ID)
			if err != nil || !found || version.ID != publication.Version.ID {
				t.Fatalf("FindVersion() = %+v found=%t error=%v", version, found, err)
			}
		})
	}
	if _, err := fixture.repository.ListOrganizationDefinitions(
		fixture.ctx, fixture.outsider, fixture.organizationID,
	); !errors.Is(err, ErrOrganizationAgentNotFound) {
		t.Fatalf("outsider list error = %v, want ErrOrganizationAgentNotFound", err)
	}
	if _, found, err := fixture.repository.FindOrganizationDefinition(
		fixture.ctx, fixture.outsider, fixture.organizationID, publication.Definition.ID,
	); !errors.Is(err, ErrOrganizationAgentNotFound) || found {
		t.Fatalf("outsider find found=%t error=%v", found, err)
	}
	if _, found, err := fixture.repository.FindVersion(
		fixture.ctx, fixture.outsider, publication.Version.ID,
	); err != nil || found {
		t.Fatalf("outsider FindVersion found=%t error=%v", found, err)
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations
		SET status = 'archived', archived_at = $2, updated_at = $2, revision = revision + 1
		WHERE id = $1
	`, fixture.organizationID, fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("archive Organization: %v", err)
	}
	definitions, err := fixture.repository.ListOrganizationDefinitions(
		fixture.ctx, fixture.auditor, fixture.organizationID,
	)
	if err != nil || len(definitions) != 1 {
		t.Fatalf("archived catalog = %+v error=%v", definitions, err)
	}
}

func TestOrganizationVersionCreatesOnlyUserOwnedInstallationAndSelectionRechecksAccess(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	publication := fixture.publishApprovedOrganizationAgent(t, 0xd3, 0xd4)
	command := fixture.organizationInstallationCommand(publication, fixture.member, 0xd5)
	created, err := fixture.repository.CreatePendingInstallation(fixture.ctx, fixture.member, command)
	if err != nil {
		t.Fatalf("CreatePendingInstallation(Member) error = %v", err)
	}
	var tenantID, ownerID uuid.UUID
	var ownerScope string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT tenant_id, owner_scope, owner_id FROM installations WHERE id = $1
	`, created.Installation.ID).Scan(&tenantID, &ownerScope, &ownerID); err != nil {
		t.Fatalf("read Organization installation owner: %v", err)
	}
	if tenantID != fixture.member.PersonalSpaceID || ownerScope != "USER" || ownerID != fixture.member.UserID {
		t.Fatalf("installation owner = %s/%s/%s", tenantID, ownerScope, ownerID)
	}
	var policyTenantID, policyOwnerID uuid.UUID
	var policyOwnerScope string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT tenant_id, owner_scope, owner_id FROM policy_snapshots WHERE id = $1
	`, created.Policy.ID).Scan(&policyTenantID, &policyOwnerScope, &policyOwnerID); err != nil {
		t.Fatalf("read Organization installation policy owner: %v", err)
	}
	if policyTenantID != fixture.member.PersonalSpaceID || policyOwnerScope != "USER" ||
		policyOwnerID != fixture.member.UserID {
		t.Fatalf("policy owner = %s/%s/%s", policyTenantID, policyOwnerScope, policyOwnerID)
	}

	auditorCommand := fixture.organizationInstallationCommand(publication, fixture.auditor, 0xd6)
	if _, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx, fixture.auditor, auditorCommand,
	); !errors.Is(err, ErrOrganizationAgentForbidden) {
		t.Fatalf("Auditor installation error = %v, want ErrOrganizationAgentForbidden", err)
	}

	profileID := uuid.New()
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, fixture.member, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: profileID,
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest,
		Audit:         fixture.auditEvidence(0xd7), ActivatedAt: fixture.now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}
	next := fixture.submitNext(
		t, fixture.owner, publication.Definition.ID, publication.Version.ID, 0xd8,
	)
	if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
		fixture.ctx, fixture.approvalCommand(t, next, fixture.admin, 0xd9),
	); err != nil {
		t.Fatalf("approve next Organization version: %v", err)
	}
	nextVersionID := fixture.latestVersionID(t, publication.Definition.ID)
	selected, err := fixture.repository.SelectInstallationVersion(fixture.ctx, fixture.member, VersionSelectionCommand{
		InstallationID: created.Installation.ID, VersionID: nextVersionID,
		BuildPolicy: func(policyVersion int64, version Version) (PolicyMaterial, error) {
			return fixture.policy(created.Installation.ID, version.ID, policyVersion, 0xda), nil
		},
		BuildOrganizationPolicy: func(
			policyVersion int64,
			version Version,
			_ EffectiveOrganizationAgentPolicy,
		) (PolicyMaterial, error) {
			return fixture.policy(created.Installation.ID, version.ID, policyVersion, 0xda), nil
		},
		Audit: fixture.auditEvidence(0xda), SelectedAt: fixture.now.Add(6 * time.Minute),
	})
	if err != nil || selected.SelectedVersionID != nextVersionID {
		t.Fatalf("SelectInstallationVersion() = %+v error=%v", selected, err)
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2
	`, fixture.organizationID, fixture.member.UserID); err != nil {
		t.Fatalf("remove Organization member: %v", err)
	}
	if _, err := fixture.repository.SelectInstallationVersion(fixture.ctx, fixture.member, VersionSelectionCommand{
		InstallationID: created.Installation.ID, VersionID: publication.Version.ID,
		BuildPolicy: func(policyVersion int64, version Version) (PolicyMaterial, error) {
			return fixture.policy(created.Installation.ID, version.ID, policyVersion, 0xdb), nil
		},
		BuildOrganizationPolicy: func(
			policyVersion int64,
			version Version,
			_ EffectiveOrganizationAgentPolicy,
		) (PolicyMaterial, error) {
			return fixture.policy(created.Installation.ID, version.ID, policyVersion, 0xdb), nil
		},
		Audit: fixture.auditEvidence(0xdb), SelectedAt: fixture.now.Add(7 * time.Minute),
	}); !errors.Is(err, ErrOrganizationAgentNotFound) {
		t.Fatalf("removed member selection error = %v, want ErrOrganizationAgentNotFound", err)
	}
}

func TestArchivedOrganizationAllowsCatalogButBlocksInstallationAndSelection(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	publication := fixture.publishApprovedOrganizationAgent(t, 0xdc, 0xdd)
	created, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx,
		fixture.member,
		fixture.organizationInstallationCommand(publication, fixture.member, 0xde),
	)
	if err != nil {
		t.Fatalf("CreatePendingInstallation() error = %v", err)
	}
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, fixture.member, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: uuid.New(),
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest,
		Audit:         fixture.auditEvidence(0xdf), ActivatedAt: fixture.now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE organizations
		SET status = 'archived', archived_at = $2, updated_at = $2, revision = revision + 1
		WHERE id = $1
	`, fixture.organizationID, fixture.now.Add(6*time.Minute)); err != nil {
		t.Fatalf("archive Organization: %v", err)
	}
	definitions, err := fixture.repository.ListOrganizationDefinitions(
		fixture.ctx, fixture.member, fixture.organizationID,
	)
	if err != nil || len(definitions) != 1 {
		t.Fatalf("archived catalog = %+v error=%v", definitions, err)
	}
	if _, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx,
		fixture.member,
		fixture.organizationInstallationCommand(publication, fixture.member, 0xe0),
	); !errors.Is(err, ErrOrganizationArchived) {
		t.Fatalf("archived installation error = %v, want ErrOrganizationArchived", err)
	}
	if _, err := fixture.repository.SelectInstallationVersion(
		fixture.ctx,
		fixture.member,
		fixture.organizationSelectionCommand(created.Installation.ID, publication.Version, 0xe1),
	); !errors.Is(err, ErrOrganizationArchived) {
		t.Fatalf("archived selection error = %v, want ErrOrganizationArchived", err)
	}
}

func TestOrganizationInstallationAndSelectionRecheckCurrentPolicy(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	publication := fixture.publishApprovedOrganizationAgent(t, 0xe4, 0xe5)
	created, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx,
		fixture.member,
		fixture.organizationInstallationCommand(publication, fixture.member, 0xe6),
	)
	if err != nil {
		t.Fatalf("CreatePendingInstallation() error = %v", err)
	}
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, fixture.member, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: uuid.New(),
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest,
		Audit:         fixture.auditEvidence(0xe7), ActivatedAt: fixture.now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}
	restricted := organization.DefaultPolicyDocument()
	restricted.Models.Allowlist = []organization.ModelIdentifier{{
		Provider: "google", Model: "gemini-2.5-pro",
	}}
	fixture.replacePolicy(t, restricted)

	if _, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx,
		fixture.member,
		fixture.organizationInstallationCommand(publication, fixture.member, 0xe8),
	); !errors.Is(err, ErrOrganizationPublicationPolicyBlocked) {
		t.Fatalf("current-policy installation error = %v, want policy blocked", err)
	}
	if _, err := fixture.repository.SelectInstallationVersion(
		fixture.ctx,
		fixture.member,
		fixture.organizationSelectionCommand(created.Installation.ID, publication.Version, 0xe9),
	); !errors.Is(err, ErrOrganizationPublicationPolicyBlocked) {
		t.Fatalf("current-policy selection error = %v, want policy blocked", err)
	}
}

func (fixture *organizationSubmissionRepositoryFixture) publishApprovedOrganizationAgent(
	t *testing.T,
	submitDiscriminator byte,
	approveDiscriminator byte,
) Publication {
	t.Helper()
	submission := fixture.submitInitial(t, fixture.owner, submitDiscriminator)
	if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
		fixture.ctx, fixture.approvalCommand(t, submission, fixture.admin, approveDiscriminator),
	); err != nil {
		t.Fatalf("approve Organization Agent: %v", err)
	}
	versionID := fixture.latestVersionID(t, submission.DefinitionID)
	definition, found, err := fixture.repository.FindOrganizationDefinition(
		fixture.ctx, fixture.owner, fixture.organizationID, submission.DefinitionID,
	)
	if err != nil || !found {
		t.Fatalf("FindOrganizationDefinition() found=%t error=%v", found, err)
	}
	versions, err := fixture.repository.ListOrganizationVersions(
		fixture.ctx, fixture.owner, fixture.organizationID, submission.DefinitionID,
	)
	if err != nil || len(versions) != 1 || versions[0].ID != versionID {
		t.Fatalf("ListOrganizationVersions() = %+v error=%v", versions, err)
	}
	return Publication{Definition: definition, Version: versions[0]}
}

func (fixture *organizationSubmissionRepositoryFixture) organizationInstallationCommand(
	publication Publication,
	principal Principal,
	discriminator byte,
) CreateInstallationCommand {
	command := fixture.pendingInstallation(
		principal, publication.Definition.ID, publication.Version.ID, 1, discriminator,
	)
	command.SourceOrganizationID = &fixture.organizationID
	command.BuildOrganizationPolicy = func(
		version Version,
		_ EffectiveOrganizationAgentPolicy,
	) (PolicyMaterial, error) {
		return fixture.policy(command.InstallationID, version.ID, 1, discriminator), nil
	}
	return command
}

func (fixture *organizationSubmissionRepositoryFixture) organizationSelectionCommand(
	installationID uuid.UUID,
	version Version,
	discriminator byte,
) VersionSelectionCommand {
	return VersionSelectionCommand{
		InstallationID: installationID,
		VersionID:      version.ID,
		BuildPolicy: func(policyVersion int64, version Version) (PolicyMaterial, error) {
			return fixture.policy(installationID, version.ID, policyVersion, discriminator), nil
		},
		BuildOrganizationPolicy: func(
			policyVersion int64,
			version Version,
			_ EffectiveOrganizationAgentPolicy,
		) (PolicyMaterial, error) {
			return fixture.policy(installationID, version.ID, policyVersion, discriminator), nil
		},
		Audit: fixture.auditEvidence(discriminator), SelectedAt: fixture.now.Add(7 * time.Minute),
	}
}
