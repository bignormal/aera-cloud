package officialquality

import (
	"bytes"
	"context"
	"errors"

	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/google/uuid"
)

type platformDraftService interface {
	GetVersion(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.Version, error)
	GetDefinition(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.PlatformDefinitionDetail, error)
	ListDrafts(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.PageRequest) (agentcontrol.PlatformDraftPage, error)
	UpdateDraft(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.UpdatePlatformDraftCommand) (agentcontrol.PlatformAgentDraft, error)
}

type AgentControlDraftCloner struct {
	service platformDraftService
}

func NewAgentControlDraftCloner(service platformDraftService) (*AgentControlDraftCloner, error) {
	if service == nil {
		return nil, errors.New("official quality platform draft service is required")
	}
	return &AgentControlDraftCloner{service: service}, nil
}

func (cloner *AgentControlDraftCloner) CloneApprovedProposal(
	ctx context.Context,
	command CloneApprovedProposalCommand,
) (uuid.UUID, error) {
	if cloner == nil || cloner.service == nil || command.ProposalID == uuid.Nil ||
		command.PlatformID == uuid.Nil || command.DefinitionID == uuid.Nil ||
		command.BaseVersionID == uuid.Nil || command.ActorAdminID == uuid.Nil ||
		command.ActorRole != QualityRoleDeveloper ||
		!qualityRequestIDPattern.MatchString(command.RequestID) || command.IdempotencyKey == "" {
		return uuid.Nil, ErrInvalidRequest
	}
	actor := agentcontrol.PlatformAdminActor{
		AdminID: command.ActorAdminID, Role: command.ActorRole, RequestID: command.RequestID,
	}
	version, err := cloner.service.GetVersion(ctx, actor, command.BaseVersionID)
	if err != nil {
		return uuid.Nil, mapPlatformCloneError(err)
	}
	if version.ID != command.BaseVersionID || version.DefinitionID != command.DefinitionID {
		return uuid.Nil, ErrProposalStateConflict
	}
	manifest, err := agentcontrol.DecodeManifest(version.CanonicalManifest)
	if err != nil {
		return uuid.Nil, ErrServiceUnavailable
	}
	bundle, err := agentcontrol.DecodeBundle(version.Bundle)
	if err != nil {
		return uuid.Nil, ErrServiceUnavailable
	}
	canonical, err := agentcontrol.CanonicalizeVersion(manifest, bundle)
	if err != nil || canonical.ContentDigest != version.ContentDigest ||
		!bytes.Equal(canonical.ManifestJSON, version.CanonicalManifest) ||
		!bytes.Equal(canonical.BundleJSON, version.Bundle) {
		return uuid.Nil, ErrServiceUnavailable
	}
	definition, err := cloner.service.GetDefinition(ctx, actor, command.DefinitionID)
	if err != nil {
		return uuid.Nil, mapPlatformCloneError(err)
	}
	if definition.PlatformID != command.PlatformID || definition.Definition.ID != command.DefinitionID {
		return uuid.Nil, ErrProposalStateConflict
	}
	draft, err := cloner.findDefinitionDraft(ctx, actor, command.DefinitionID)
	if err != nil {
		return uuid.Nil, err
	}
	if draft.PlatformID != command.PlatformID || draft.Status != agentcontrol.PlatformDraftActive ||
		draft.ContentDigest != version.ContentDigest {
		return uuid.Nil, ErrProposalStateConflict
	}
	if draft.Kind == agentcontrol.PlatformDraftNext && draft.BaseVersionID == version.ID {
		return draft.ID, nil
	}
	if draft.Kind != agentcontrol.PlatformDraftInitial || draft.BaseVersionID != uuid.Nil {
		return uuid.Nil, ErrProposalStateConflict
	}
	updated, err := cloner.service.UpdateDraft(ctx, actor, agentcontrol.UpdatePlatformDraftCommand{
		DraftID: draft.ID, ExpectedRevision: draft.Revision,
		Kind: agentcontrol.PlatformDraftNext, BaseVersionID: version.ID,
		DisplayName:   definition.Definition.DisplayName,
		IconMediaType: definition.Definition.IconMediaType,
		IconData:      append([]byte(nil), definition.Definition.IconData...),
		Manifest:      manifest, Bundle: bundle, IdempotencyKey: command.IdempotencyKey,
	})
	if err != nil {
		return uuid.Nil, mapPlatformCloneError(err)
	}
	if updated.ID != draft.ID {
		return uuid.Nil, ErrServiceUnavailable
	}
	return updated.ID, nil
}

func (cloner *AgentControlDraftCloner) findDefinitionDraft(
	ctx context.Context,
	actor agentcontrol.PlatformAdminActor,
	definitionID uuid.UUID,
) (agentcontrol.PlatformAgentDraft, error) {
	after := uuid.Nil
	seen := make(map[uuid.UUID]struct{})
	for pageNumber := 0; pageNumber < 1024; pageNumber++ {
		page, err := cloner.service.ListDrafts(ctx, actor, agentcontrol.PageRequest{After: after, Limit: 100})
		if err != nil {
			return agentcontrol.PlatformAgentDraft{}, mapPlatformCloneError(err)
		}
		var match agentcontrol.PlatformAgentDraft
		for _, candidate := range page.Items {
			if candidate.DefinitionID == definitionID {
				if match.ID != uuid.Nil {
					return agentcontrol.PlatformAgentDraft{}, ErrServiceUnavailable
				}
				match = candidate
			}
		}
		if match.ID != uuid.Nil {
			return match, nil
		}
		if page.Next == uuid.Nil {
			return agentcontrol.PlatformAgentDraft{}, ErrProposalStateConflict
		}
		if _, duplicate := seen[page.Next]; duplicate {
			return agentcontrol.PlatformAgentDraft{}, ErrServiceUnavailable
		}
		seen[page.Next] = struct{}{}
		after = page.Next
	}
	return agentcontrol.PlatformAgentDraft{}, ErrServiceUnavailable
}

func mapPlatformCloneError(err error) error {
	switch {
	case errors.Is(err, agentcontrol.ErrNotFound),
		errors.Is(err, agentcontrol.ErrVersionConflict),
		errors.Is(err, agentcontrol.ErrOfficialSubmissionConflict),
		errors.Is(err, agentcontrol.ErrPlatformForbidden):
		return ErrProposalStateConflict
	default:
		return ErrServiceUnavailable
	}
}
