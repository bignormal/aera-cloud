package organization

import (
	"context"

	"github.com/google/uuid"
)

// FoundationAssetGuard is valid only while Organization Foundation owns no
// Organization-scoped Agent assets. Organization Agent V1 must replace it with
// a guard backed by the Organization asset repository before those assets can
// be created.
type FoundationAssetGuard struct{}

func NewFoundationAssetGuard() FoundationAssetGuard {
	return FoundationAssetGuard{}
}

func (FoundationAssetGuard) DissolutionBlockers(context.Context, uuid.UUID) ([]string, error) {
	return nil, nil
}
