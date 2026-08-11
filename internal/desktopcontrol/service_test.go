package desktopcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceHeartbeatClaimsOneCommandAndUsesServerStatus(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	principal := DevicePrincipal{UserID: uuid.New(), DeviceID: uuid.New()}
	fake := &serviceRepositoryFake{
		instance: Instance{
			DeviceID: principal.DeviceID, UserID: principal.UserID,
			UserStatus: "active", DeviceStatus: "active",
			LastHeartbeatAt: timePointer(now), HealthStatus: HealthUnknown,
		},
		claimed: &Command{ID: uuid.New(), DeviceID: principal.DeviceID, Type: CommandHealthCheck, State: CommandClaimed},
	}
	service := NewService(fake, func() time.Time { return now })
	receipt, err := service.Heartbeat(context.Background(), principal, Heartbeat{
		DisplayName: "Aera Mac", ClientVersion: "0.7.4", Platform: "darwin", Arch: "arm64",
		Capabilities: []string{CapabilityHealthRead},
	})
	if err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	if receipt.ServerTime != now || receipt.NextHeartbeatSeconds != 60 || receipt.Command == nil || receipt.Command.ID != fake.claimed.ID {
		t.Fatalf("Heartbeat() receipt = %+v", receipt)
	}
	if receipt.Instance.EffectiveStatusValue != EffectiveOnline || receipt.Instance.HealthStatus != HealthUnknown {
		t.Fatalf("Heartbeat() instance = %+v", receipt.Instance)
	}
	if fake.heartbeatCalls != 1 || fake.claimCalls != 1 {
		t.Fatalf("repository calls = heartbeat:%d claim:%d", fake.heartbeatCalls, fake.claimCalls)
	}
}

func TestServiceRejectsPrivateHeartbeatFields(t *testing.T) {
	for _, field := range []string{
		"user_id", "device_id", "prompt", "conversation", "memory", "file", "workspace",
		"path", "log", "secret", "token", "credential",
	} {
		t.Run(field, func(t *testing.T) {
			payload := fmt.Sprintf(`{"display_name":"Aera Mac","client_version":"0.7.4","platform":"darwin","arch":"arm64","capabilities":[],"uptime_seconds":1,%q:"private"}`, field)
			var heartbeat Heartbeat
			if err := json.Unmarshal([]byte(payload), &heartbeat); err == nil {
				t.Fatalf("private heartbeat field %q was accepted", field)
			}
		})
	}
	var heartbeat Heartbeat
	if err := json.Unmarshal([]byte(`{"display_name":"Aera Mac","client_version":"0.7.4","platform":"darwin","arch":"arm64","capabilities":[],"uptime_seconds":1,"health":{"desktop_status":"healthy","runtime_status":"healthy","gateway_status":"healthy","code":"HEALTHY","duration_ms":1,"log":"private"}}`), &heartbeat); err == nil {
		t.Fatal("private nested health field was accepted")
	}
}

func TestServiceRejectsHeartbeatLimitsAndUnknownCapabilities(t *testing.T) {
	valid := Heartbeat{
		DisplayName: "Aera Mac", ClientVersion: "0.7.4", Platform: "darwin", Arch: "arm64",
		Capabilities: []string{CapabilityHealthRead}, UptimeSeconds: 1,
	}
	tests := []struct {
		name   string
		mutate func(*Heartbeat)
	}{
		{"display name", func(value *Heartbeat) { value.DisplayName = strings.Repeat("a", 101) }},
		{"client version", func(value *Heartbeat) { value.ClientVersion = " 0.7.4" }},
		{"platform", func(value *Heartbeat) { value.Platform = "ios" }},
		{"architecture", func(value *Heartbeat) { value.Arch = "amd64" }},
		{"unknown capability", func(value *Heartbeat) { value.Capabilities = []string{"diagnostics.log.read"} }},
		{"duplicate capability", func(value *Heartbeat) { value.Capabilities = []string{CapabilityHealthRead, CapabilityHealthRead} }},
		{"uptime", func(value *Heartbeat) { value.UptimeSeconds = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &serviceRepositoryFake{}
			service := NewService(fake, time.Now)
			heartbeat := valid
			test.mutate(&heartbeat)
			_, err := service.Heartbeat(context.Background(), DevicePrincipal{UserID: uuid.New(), DeviceID: uuid.New()}, heartbeat)
			if !errors.Is(err, ErrInvalidInput) || fake.heartbeatCalls != 0 {
				t.Fatalf("Heartbeat() error/calls = %v/%d", err, fake.heartbeatCalls)
			}
		})
	}
}

func TestServiceRejectsPrivateCommandResultFields(t *testing.T) {
	var result CommandResult
	if err := json.Unmarshal([]byte(`{"state":"running","path":"private"}`), &result); err == nil {
		t.Fatal("private command result field was accepted")
	}
}

func TestServiceHashesHealthCheckIdempotencyAndValidatesActor(t *testing.T) {
	deviceID := uuid.New()
	actor := AdminActor{AdminID: uuid.New(), ServiceSubject: "aera-admin-test", RequestID: "req-health-service"}
	fake := &serviceRepositoryFake{queueCommand: Command{ID: uuid.New(), DeviceID: deviceID, State: CommandQueued}}
	service := NewService(fake, time.Now)
	command, err := service.QueueHealthCheck(context.Background(), actor, deviceID, "health-check-key-1")
	if err != nil || command.ID != fake.queueCommand.ID {
		t.Fatalf("QueueHealthCheck() = %+v error=%v", command, err)
	}
	wantHash := sha256.Sum256([]byte("health-check-key-1"))
	if !bytes.Equal(fake.queueInput.IdempotencyKeyHash, wantHash[:]) || fake.queueInput.Actor != actor {
		t.Fatalf("queue input = %+v", fake.queueInput)
	}
	fake.queueCalls = 0
	_, err = service.QueueHealthCheck(context.Background(), AdminActor{}, deviceID, "health-check-key-2")
	if !errors.Is(err, ErrInvalidInput) || fake.queueCalls != 0 {
		t.Fatalf("invalid actor error/calls = %v/%d", err, fake.queueCalls)
	}
}

func TestServiceRejectsInvalidHealthResult(t *testing.T) {
	fake := &serviceRepositoryFake{}
	service := NewService(fake, time.Now)
	_, err := service.SubmitResult(context.Background(), DevicePrincipal{UserID: uuid.New(), DeviceID: uuid.New()}, uuid.New(), CommandResult{
		State: CommandSucceeded, Code: HealthCodeRuntimeUnavailable,
		Summary: &HealthSummary{Code: HealthCodeRuntimeUnavailable, DesktopStatus: "healthy", RuntimeStatus: "unhealthy", GatewayStatus: "healthy"},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("SubmitResult() error = %v, want ErrInvalidInput", err)
	}
}

type serviceRepositoryFake struct {
	instance       Instance
	claimed        *Command
	queueCommand   Command
	queueInput     QueueHealthCheckCommand
	heartbeatCalls int
	claimCalls     int
	queueCalls     int
}

func (f *serviceRepositoryFake) AcceptHeartbeat(_ context.Context, _ DevicePrincipal, heartbeat Heartbeat) (Instance, error) {
	f.heartbeatCalls++
	if heartbeat.Health != nil {
		f.instance.HealthStatus = healthStatusFor(heartbeat.Health)
		f.instance.HealthSummary = heartbeat.Health
	}
	return f.instance, nil
}

func (f *serviceRepositoryFake) QueueHealthCheck(_ context.Context, input QueueHealthCheckCommand) (Command, error) {
	f.queueCalls++
	f.queueInput = input
	return f.queueCommand, nil
}

func (f *serviceRepositoryFake) ClaimNextCommand(context.Context, DevicePrincipal) (*Command, error) {
	f.claimCalls++
	return f.claimed, nil
}

func (f *serviceRepositoryFake) AdvanceCommand(context.Context, DevicePrincipal, uuid.UUID, CommandResult) (Command, error) {
	return Command{}, nil
}

func (f *serviceRepositoryFake) ListInstances(context.Context, InstanceFilter) (InstancePage, error) {
	return InstancePage{}, nil
}

func (f *serviceRepositoryFake) ListUserInstances(context.Context, uuid.UUID, InstanceFilter) (InstancePage, error) {
	return InstancePage{}, nil
}

func (f *serviceRepositoryFake) GetInstance(context.Context, uuid.UUID) (Instance, error) {
	return f.instance, nil
}

func (f *serviceRepositoryFake) GetCommand(context.Context, uuid.UUID) (Command, error) {
	return Command{}, nil
}
