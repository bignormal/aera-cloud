package jobs

import (
	"context"
	"errors"
	"reflect"
	"time"
)

type SequentialMaintenance struct {
	stages []Maintenance
}

func NewSequentialMaintenance(stages ...Maintenance) (*SequentialMaintenance, error) {
	if len(stages) == 0 {
		return nil, errors.New("at least one maintenance stage is required")
	}
	for _, stage := range stages {
		if maintenanceIsNil(stage) {
			return nil, errors.New("maintenance stages must not be nil")
		}
	}
	return &SequentialMaintenance{stages: append([]Maintenance(nil), stages...)}, nil
}

func (maintenance *SequentialMaintenance) Run(ctx context.Context, now time.Time) error {
	if maintenance == nil || len(maintenance.stages) == 0 || now.IsZero() {
		return ErrMaintenanceUnavailable
	}
	for _, stage := range maintenance.stages {
		if err := stage.Run(ctx, now); err != nil {
			return err
		}
	}
	return nil
}

func maintenanceIsNil(maintenance Maintenance) bool {
	if maintenance == nil {
		return true
	}
	value := reflect.ValueOf(maintenance)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
