package officialquality

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConsentServiceKeepsPurposesIndependentAndVersioned(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	repository := &fakeConsentRepository{}
	service, err := NewConsentService(ConsentServiceConfig{
		Repository: repository, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewConsentService() error = %v", err)
	}
	principal := validQualityPrincipal()

	metric, err := service.Set(context.Background(), principal, ConsentRequest{
		Purpose: PurposeMetrics, ConsentVersion: 1, State: ConsentGranted,
	})
	if err != nil {
		t.Fatalf("Set(metric) error = %v", err)
	}
	explicit, err := service.Set(context.Background(), principal, ConsentRequest{
		Purpose: PurposeExplicitFeedback, ConsentVersion: 2, State: ConsentRevoked,
	})
	if err != nil {
		t.Fatalf("Set(explicit) error = %v", err)
	}
	if metric.Purpose != PurposeMetrics || explicit.Purpose != PurposeExplicitFeedback || len(repository.commands) != 2 {
		t.Fatalf("consent results = %+v / %+v; commands=%+v", metric, explicit, repository.commands)
	}
	if repository.commands[0].Principal != principal || !repository.commands[0].RecordedAt.Equal(now) {
		t.Fatalf("metric consent command = %+v", repository.commands[0])
	}
	if repository.commands[1].State != ConsentRevoked {
		t.Fatalf("explicit consent command = %+v", repository.commands[1])
	}
}

func TestConsentServiceRejectsUnknownPurposeStateAndVersion(t *testing.T) {
	service, err := NewConsentService(ConsentServiceConfig{
		Repository: &fakeConsentRepository{}, Clock: time.Now,
	})
	if err != nil {
		t.Fatalf("NewConsentService() error = %v", err)
	}
	for name, request := range map[string]ConsentRequest{
		"purpose": {Purpose: "all_analytics", ConsentVersion: 1, State: ConsentGranted},
		"version": {Purpose: PurposeMetrics, ConsentVersion: 0, State: ConsentGranted},
		"state":   {Purpose: PurposeMetrics, ConsentVersion: 1, State: "enabled"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Set(context.Background(), validQualityPrincipal(), request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Set() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

type fakeConsentRepository struct {
	commands []RecordConsentCommand
}

func (f *fakeConsentRepository) RecordConsent(_ context.Context, command RecordConsentCommand) (ConsentReceipt, error) {
	f.commands = append(f.commands, command)
	return ConsentReceipt{
		ID: command.ReceiptID, Purpose: command.Purpose, ConsentVersion: command.ConsentVersion,
		State: command.State, Revision: int64(len(f.commands)), RecordedAt: command.RecordedAt,
	}, nil
}
