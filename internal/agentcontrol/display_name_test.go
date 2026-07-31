package agentcontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type nextDisplayNameHTTPService struct {
	*stubAgentControlHTTPService
	userRequests      []PublishNextRequest
	workspaceRequests []PublishNextRequest
}

func (s *nextDisplayNameHTTPService) PublishNext(
	ctx context.Context,
	principal Principal,
	request PublishNextRequest,
) (Publication, error) {
	s.userRequests = append(s.userRequests, request)
	return s.stubAgentControlHTTPService.PublishNext(ctx, principal, request)
}

func (s *nextDisplayNameHTTPService) PublishWorkspaceNext(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	request PublishNextRequest,
) (Publication, error) {
	s.workspaceRequests = append(s.workspaceRequests, request)
	return s.stubAgentControlHTTPService.PublishWorkspaceNext(ctx, principal, workspaceID, request)
}

func TestHTTPPublishNextForwardsUpdatedDisplayName(t *testing.T) {
	for _, test := range []struct {
		name      string
		workspace bool
	}{
		{name: "user"},
		{name: "workspace", workspace: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentControlHTTPFixture(t)
			service := &nextDisplayNameHTTPService{stubAgentControlHTTPService: fixture.service}
			handler := NewHandler(HTTPConfig{Service: service, AccessTokens: fixture.authenticator})
			path := "/api/v1/agent-definitions/" + fixture.definitionID.String() + "/versions"
			if test.workspace {
				path = "/api/v1/workspaces/" + fixture.workspaceID.String() + "/agent-definitions/" + fixture.definitionID.String() + "/versions"
			}
			body := strings.Replace(
				nextPublicationJSON(fixture.versionID),
				`{"base_version_id":`,
				`{"display_name":"Renamed Research Agent","base_version_id":`,
				1,
			)
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "rename-next-"+test.name)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), http.StatusCreated)
			}
			captured := service.userRequests
			if test.workspace {
				captured = service.workspaceRequests
			}
			if len(captured) != 1 {
				t.Fatalf("captured next requests = %d, want 1", len(captured))
			}
			if captured[0].DisplayName == nil || *captured[0].DisplayName != "Renamed Research Agent" {
				t.Fatalf("display name = %v, want %q", captured[0].DisplayName, "Renamed Research Agent")
			}
		})
	}
}

func TestServicePublishNextCarriesDisplayNameInCommandAndRequestHash(t *testing.T) {
	fixture := newAgentControlServiceFixture(t)
	manifest, bundle := validManifestFixture()
	definitionID, baseVersionID := uuid.New(), uuid.New()
	var commands []NextPublicationCommand
	fixture.repository.publishNext = func(
		_ context.Context,
		_ Principal,
		command NextPublicationCommand,
	) (Publication, error) {
		if command.DisplayName == nil {
			t.Fatal("next publication command omitted DisplayName")
		}
		material, err := command.BuildVersion(int64(len(commands) + 2))
		if err != nil {
			return Publication{}, err
		}
		commands = append(commands, command)
		latest := material.ID
		return Publication{
			Definition: Definition{
				ID: command.DefinitionID, DisplayName: *command.DisplayName,
				Status: definitionStatusActive, LatestVersionID: &latest,
			},
			Version: versionFromMaterial(command.DefinitionID, material, fixture.now),
		}, nil
	}

	for _, displayName := range []string{"Renamed Research Agent", "Renamed Research Agent Again"} {
		name := displayName
		request := PublishNextRequest{
			DefinitionID: definitionID, BaseVersionID: baseVersionID,
			DisplayName: &name,
			Manifest:    manifest, Bundle: bundle,
			IdempotencyKey: "rename-next", RequestID: "rename-next-request",
		}
		if _, err := fixture.service.PublishNext(context.Background(), fixture.principal, request); err != nil {
			t.Fatalf("PublishNext(%q) error = %v", displayName, err)
		}
	}
	if len(commands) != 2 {
		t.Fatalf("commands = %d, want 2", len(commands))
	}
	if commands[0].DisplayName == nil || *commands[0].DisplayName != "Renamed Research Agent" {
		t.Fatalf("first command display name = %v", commands[0].DisplayName)
	}
	if commands[0].Idempotency.RequestHash == commands[1].Idempotency.RequestHash {
		t.Fatal("changing display_name did not change the next-publication request hash")
	}
}

func TestRepositoryPublishNextAtomicallyUpdatesDefinitionDisplayName(t *testing.T) {
	t.Run("user", func(t *testing.T) {
		fixture := newAgentControlRepositoryFixture(t)
		principal := fixture.principal(t, 71)
		initial := fixture.initialPublication(principal, "Research Agent", 71)
		first, err := fixture.repository.PublishInitial(fixture.ctx, principal, initial)
		if err != nil {
			t.Fatalf("PublishInitial() error = %v", err)
		}
		next := fixture.nextPublication(principal, first.Definition.ID, first.Version.ID, 72)
		renamed := "Renamed Research Agent"
		next.DisplayName = &renamed
		second, err := fixture.repository.PublishNext(fixture.ctx, principal, next)
		if err != nil {
			t.Fatalf("PublishNext() error = %v", err)
		}
		if second.Definition.DisplayName != "Renamed Research Agent" {
			t.Fatalf("publication display name = %q", second.Definition.DisplayName)
		}
		stored, found, err := fixture.repository.FindDefinition(fixture.ctx, principal, first.Definition.ID)
		if err != nil || !found || stored.DisplayName != "Renamed Research Agent" {
			t.Fatalf("stored definition = %+v found=%v error=%v", stored, found, err)
		}
	})

	t.Run("workspace", func(t *testing.T) {
		fixture := newAgentControlRepositoryFixture(t)
		owner := fixture.principal(t, 73)
		admin := fixture.principal(t, 74)
		workspaceID := seedAgentWorkspace(t, fixture, owner, admin, Principal{})
		initial := fixture.initialPublication(owner, "Workspace Research Agent", 73)
		first, err := fixture.repository.PublishWorkspaceInitial(fixture.ctx, owner, workspaceID, initial)
		if err != nil {
			t.Fatalf("PublishWorkspaceInitial() error = %v", err)
		}
		next := fixture.nextPublication(admin, first.Definition.ID, first.Version.ID, 74)
		renamed := "Renamed Workspace Agent"
		next.DisplayName = &renamed
		second, err := fixture.repository.PublishWorkspaceNext(fixture.ctx, admin, workspaceID, next)
		if err != nil {
			t.Fatalf("PublishWorkspaceNext() error = %v", err)
		}
		if second.Definition.DisplayName != "Renamed Workspace Agent" {
			t.Fatalf("publication display name = %q", second.Definition.DisplayName)
		}
		stored, found, err := fixture.repository.FindWorkspaceDefinition(
			fixture.ctx, admin, workspaceID, first.Definition.ID,
		)
		if err != nil || !found || stored.DisplayName != "Renamed Workspace Agent" {
			t.Fatalf("stored Workspace definition = %+v found=%v error=%v", stored, found, err)
		}
	})
}
