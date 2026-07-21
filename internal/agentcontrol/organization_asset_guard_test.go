package agentcontrol

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func TestOrganizationAgentAssetGuardSortsCompactsAndValidatesBlockers(t *testing.T) {
	organizationID := uuid.New()
	guard := NewOrganizationAssetGuard(staticOrganizationAssetReader{
		blockers: []string{"published_agents", "employee_installations", "published_agents", "pending_submissions"},
	})
	blockers, err := guard.DissolutionBlockers(context.Background(), organizationID)
	if err != nil {
		t.Fatalf("DissolutionBlockers() error = %v", err)
	}
	want := []string{"employee_installations", "pending_submissions", "published_agents"}
	if !slices.Equal(blockers, want) {
		t.Fatalf("blockers = %v, want %v", blockers, want)
	}
	blockers[0] = "mutated"
	again, err := guard.DissolutionBlockers(context.Background(), organizationID)
	if err != nil || !slices.Equal(again, want) {
		t.Fatalf("second blockers = %v error=%v, want detached %v", again, err, want)
	}
	if _, err := NewOrganizationAssetGuard(staticOrganizationAssetReader{err: errors.New("database unavailable")}).DissolutionBlockers(
		context.Background(), organizationID,
	); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("reader failure error = %v, want ErrServiceUnavailable", err)
	}
	if _, err := guard.DissolutionBlockers(context.Background(), uuid.Nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil Organization error = %v, want ErrInvalidRequest", err)
	}
}

func TestOrganizationAgentAssetGuardReadsRealProtectedCategories(t *testing.T) {
	fixture := newOrganizationSubmissionRepositoryFixture(t)
	guard := NewOrganizationAssetGuard(fixture.repository)
	blockers, err := guard.DissolutionBlockers(fixture.ctx, fixture.organizationID)
	if err != nil || len(blockers) != 0 {
		t.Fatalf("empty blockers = %v error=%v", blockers, err)
	}
	submission := fixture.submitInitial(t, fixture.owner, 0xe1)
	blockers, err = guard.DissolutionBlockers(fixture.ctx, fixture.organizationID)
	if err != nil || !slices.Equal(blockers, []string{"pending_submissions"}) {
		t.Fatalf("pending blockers = %v error=%v", blockers, err)
	}
	if _, err := fixture.repository.ReviewOrganizationAgentSubmission(
		fixture.ctx, fixture.approvalCommand(t, submission, fixture.admin, 0xe2),
	); err != nil {
		t.Fatalf("approve Organization Agent: %v", err)
	}
	blockers, err = guard.DissolutionBlockers(fixture.ctx, fixture.organizationID)
	if err != nil || !slices.Equal(blockers, []string{"published_agents"}) {
		t.Fatalf("published blockers = %v error=%v", blockers, err)
	}
	publication := fixture.publishExistingOrganizationAgent(t, submission.DefinitionID)
	if _, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx, fixture.member, fixture.organizationInstallationCommand(publication, fixture.member, 0xe3),
	); err != nil {
		t.Fatalf("create employee installation: %v", err)
	}
	blockers, err = guard.DissolutionBlockers(fixture.ctx, fixture.organizationID)
	want := []string{"employee_installations", "published_agents"}
	if err != nil || !slices.Equal(blockers, want) {
		t.Fatalf("installation blockers = %v, want %v, error=%v", blockers, want, err)
	}
}

type staticOrganizationAssetReader struct {
	blockers []string
	err      error
}

func (reader staticOrganizationAssetReader) OrganizationAssetBlockers(
	context.Context,
	uuid.UUID,
) ([]string, error) {
	return append([]string(nil), reader.blockers...), reader.err
}

func (fixture *organizationSubmissionRepositoryFixture) publishExistingOrganizationAgent(
	t *testing.T,
	definitionID uuid.UUID,
) Publication {
	t.Helper()
	definition, found, err := fixture.repository.FindOrganizationDefinition(
		fixture.ctx, fixture.owner, fixture.organizationID, definitionID,
	)
	if err != nil || !found {
		t.Fatalf("FindOrganizationDefinition() found=%t error=%v", found, err)
	}
	versions, err := fixture.repository.ListOrganizationVersions(
		fixture.ctx, fixture.owner, fixture.organizationID, definitionID,
	)
	if err != nil || len(versions) == 0 {
		t.Fatalf("ListOrganizationVersions() = %+v error=%v", versions, err)
	}
	return Publication{Definition: definition, Version: versions[0]}
}
