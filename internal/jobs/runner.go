package jobs

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
)

const maintenanceLeaseName = "account-maintenance-v1"

var ErrLeaseUnavailable = errors.New("maintenance lease is unavailable")

type Lease interface {
	Acquire(context.Context, string, string, time.Duration) (bool, error)
	Release(context.Context, string, string) error
}

type Maintenance interface {
	Run(context.Context, time.Time) error
}

type RunnerConfig struct {
	Lease       Lease
	Maintenance Maintenance
	Owner       string
	LeaseTTL    time.Duration
	Interval    time.Duration
	Clock       func() time.Time
	Logger      *slog.Logger
}

type Runner struct {
	lease       Lease
	maintenance Maintenance
	owner       string
	leaseTTL    time.Duration
	interval    time.Duration
	clock       func() time.Time
	logger      *slog.Logger
}

func NewRunner(config RunnerConfig) (*Runner, error) {
	if config.Lease == nil || config.Maintenance == nil || strings.TrimSpace(config.Owner) == "" ||
		config.LeaseTTL <= 0 || config.Interval <= 0 {
		return nil, errors.New("maintenance runner configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		lease: config.Lease, maintenance: config.Maintenance, owner: config.Owner,
		leaseTTL: config.LeaseTTL, interval: config.Interval, clock: clock, logger: logger,
	}, nil
}

// RunOnce deliberately acquires the external lease before touching PostgreSQL.
// A Redis error therefore pauses all cleanup and deletion finalization.
func (r *Runner) RunOnce(ctx context.Context) error {
	if r == nil {
		return ErrLeaseUnavailable
	}
	acquired, err := r.lease.Acquire(ctx, maintenanceLeaseName, r.owner, r.leaseTTL)
	if err != nil {
		return ErrLeaseUnavailable
	}
	if !acquired {
		return nil
	}
	defer func() {
		if err := r.lease.Release(context.WithoutCancel(ctx), maintenanceLeaseName, r.owner); err != nil {
			r.logger.Warn("maintenance lease release failed")
		}
	}()
	return r.maintenance.Run(ctx, r.clock().UTC())
}

func (r *Runner) Run(ctx context.Context) {
	if r == nil {
		return
	}
	r.runAndLog(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runAndLog(ctx)
		}
	}
}

func (r *Runner) runAndLog(ctx context.Context) {
	if err := r.RunOnce(ctx); err != nil && ctx.Err() == nil {
		r.logger.Warn("maintenance pass paused", "error", err)
	}
}
