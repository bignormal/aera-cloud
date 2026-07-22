package officialquality

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	ConsentGranted = "granted"
	ConsentRevoked = "revoked"
)

type ConsentRequest struct {
	Purpose        string
	ConsentVersion int64
	State          string
}

type RecordConsentCommand struct {
	ReceiptID      uuid.UUID
	Principal      Principal
	Purpose        string
	ConsentVersion int64
	State          string
	RecordedAt     time.Time
}

type ConsentReceipt struct {
	ID             uuid.UUID
	Purpose        string
	ConsentVersion int64
	State          string
	Revision       int64
	RecordedAt     time.Time
	Replayed       bool
}

type ConsentRepository interface {
	RecordConsent(context.Context, RecordConsentCommand) (ConsentReceipt, error)
}

type ConsentServiceConfig struct {
	Repository ConsentRepository
	Clock      func() time.Time
	NewID      func() uuid.UUID
}

type ConsentService struct {
	repository ConsentRepository
	clock      func() time.Time
	newID      func() uuid.UUID
}

func NewConsentService(config ConsentServiceConfig) (*ConsentService, error) {
	if config.Repository == nil {
		return nil, errors.New("official quality consent repository is required")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	newID := config.NewID
	if newID == nil {
		newID = uuid.New
	}
	return &ConsentService{repository: config.Repository, clock: clock, newID: newID}, nil
}

func (s *ConsentService) Set(
	ctx context.Context,
	principal Principal,
	request ConsentRequest,
) (ConsentReceipt, error) {
	if s == nil || !principal.valid() || !validPurpose(request.Purpose) || request.ConsentVersion <= 0 ||
		(request.State != ConsentGranted && request.State != ConsentRevoked) {
		return ConsentReceipt{}, ErrInvalidRequest
	}
	receiptID := s.newID()
	if receiptID == uuid.Nil {
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	receipt, err := s.repository.RecordConsent(ctx, RecordConsentCommand{
		ReceiptID: receiptID, Principal: principal, Purpose: request.Purpose,
		ConsentVersion: request.ConsentVersion, State: request.State, RecordedAt: s.clock().UTC(),
	})
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			return ConsentReceipt{}, ErrInvalidRequest
		}
		return ConsentReceipt{}, ErrServiceUnavailable
	}
	return receipt, nil
}
