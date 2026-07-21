package organization

import (
	"testing"

	"github.com/google/uuid"
)

func TestFoundationAssetGuardHasNoOrganizationAgentAssets(t *testing.T) {
	blockers, err := NewFoundationAssetGuard().DissolutionBlockers(t.Context(), uuid.New())
	if err != nil || len(blockers) != 0 {
		t.Fatalf("DissolutionBlockers() = %v, %v", blockers, err)
	}
}
