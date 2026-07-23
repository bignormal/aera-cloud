package jobs

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSequentialMaintenanceRunsInOrder(t *testing.T) {
	var calls []string
	now := time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC)
	maintenance, err := NewSequentialMaintenance(
		maintenanceFunc(func(_ context.Context, received time.Time) error {
			calls = append(calls, "security")
			if !received.Equal(now) {
				t.Fatalf("security maintenance time = %s, want %s", received, now)
			}
			return nil
		}),
		maintenanceFunc(func(_ context.Context, received time.Time) error {
			calls = append(calls, "official-quality")
			if !received.Equal(now) {
				t.Fatalf("official quality maintenance time = %s, want %s", received, now)
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("NewSequentialMaintenance() error = %v", err)
	}

	if err := maintenance.Run(context.Background(), now); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if want := []string{"security", "official-quality"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestSequentialMaintenanceStopsAndReturnsFailureForRunnerRetry(t *testing.T) {
	wantErr := errors.New("official quality unavailable")
	var calls []string
	maintenance, err := NewSequentialMaintenance(
		maintenanceFunc(func(context.Context, time.Time) error {
			calls = append(calls, "security")
			return nil
		}),
		maintenanceFunc(func(context.Context, time.Time) error {
			calls = append(calls, "official-quality")
			return wantErr
		}),
		maintenanceFunc(func(context.Context, time.Time) error {
			calls = append(calls, "after-failure")
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("NewSequentialMaintenance() error = %v", err)
	}

	err = maintenance.Run(context.Background(), time.Now())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run() error = %v, want %v", err, wantErr)
	}
	if want := []string{"security", "official-quality"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestSequentialMaintenanceRejectsMissingStages(t *testing.T) {
	if _, err := NewSequentialMaintenance(); err == nil {
		t.Fatal("NewSequentialMaintenance() accepted no stages")
	}
	if _, err := NewSequentialMaintenance(maintenanceFunc(nil)); err == nil {
		t.Fatal("NewSequentialMaintenance() accepted a nil stage")
	}
}

type maintenanceFunc func(context.Context, time.Time) error

func (function maintenanceFunc) Run(ctx context.Context, now time.Time) error {
	if function == nil {
		return errors.New("nil maintenance function")
	}
	return function(ctx, now)
}
