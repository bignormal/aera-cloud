package adminapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/desktopcontrol"
	"github.com/google/uuid"
)

func TestDesktopControlRoutesRequireExactScopes(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	deviceID := uuid.New()
	desktop := &desktopControlAdminStub{
		page: desktopcontrol.InstancePage{Items: []desktopcontrol.Instance{{
			DeviceID: deviceID, UserID: uuid.New(), DisplayName: "Aera Mac", ClientVersion: "0.7.4",
			Platform: "darwin", Arch: "arm64", Capabilities: []string{desktopcontrol.CapabilityHealthRead},
			EffectiveStatusValue: desktopcontrol.EffectiveOnline, HealthStatus: desktopcontrol.HealthUnknown,
		}}, Total: 1, ServerTime: now},
		command: desktopcontrol.Command{ID: uuid.New(), DeviceID: deviceID, Type: desktopcontrol.CommandHealthCheck, State: desktopcontrol.CommandQueued, ExpiresAt: now.Add(10 * time.Minute)},
	}
	handler, privateKey := newDesktopControlAdminHandler(t, now, desktop)

	read := desktopAdminRequest(t, privateKey, now, http.MethodGet,
		"/internal/admin/v1/desktop-control/instances?device_id="+deviceID.String()+"&platform=darwin&effective_status=online&limit=25&offset=0",
		"", ScopeDesktopControlRead, false)
	readResponse := httptest.NewRecorder()
	handler.ServeHTTP(readResponse, read)
	if readResponse.Code != http.StatusOK || !strings.Contains(readResponse.Body.String(), `"effective_status":"online"`) || !strings.Contains(readResponse.Body.String(), `"server_time"`) {
		t.Fatalf("read response = %d %s", readResponse.Code, readResponse.Body.String())
	}
	if desktop.listFilter.DeviceID == nil || *desktop.listFilter.DeviceID != deviceID || desktop.listFilter.Platform != "darwin" || desktop.listFilter.Limit != 25 {
		t.Fatalf("list filter = %+v", desktop.listFilter)
	}

	wrongRead := desktopAdminRequest(t, privateKey, now, http.MethodGet,
		"/internal/admin/v1/desktop-control/instances", "", ScopeUsersRead, false)
	wrongReadResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongReadResponse, wrongRead)
	if wrongReadResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong read scope response = %d %s", wrongReadResponse.Code, wrongReadResponse.Body.String())
	}

	command := desktopAdminRequest(t, privateKey, now, http.MethodPost,
		"/internal/admin/v1/desktop-control/instances/"+deviceID.String()+"/health-check", `{}`,
		ScopeDesktopControlCommand, true)
	command.Header.Set("Idempotency-Key", "desktop-health-check-1")
	commandResponse := httptest.NewRecorder()
	handler.ServeHTTP(commandResponse, command)
	if commandResponse.Code != http.StatusOK || desktop.queueDeviceID != deviceID || desktop.idempotencyKey != "desktop-health-check-1" {
		t.Fatalf("command response=%d device=%s key=%q body=%s", commandResponse.Code, desktop.queueDeviceID, desktop.idempotencyKey, commandResponse.Body.String())
	}
	if desktop.actor.AdminID != authAdminID || desktop.actor.ServiceSubject != "aera-admin-e2e" || desktop.actor.RequestID != "request-desktop-control-test" {
		t.Fatalf("command actor = %+v", desktop.actor)
	}

	wrongCommand := desktopAdminRequest(t, privateKey, now, http.MethodPost,
		"/internal/admin/v1/desktop-control/instances/"+deviceID.String()+"/health-check", `{}`,
		ScopeDesktopControlRead, true)
	wrongCommand.Header.Set("Idempotency-Key", "desktop-health-check-2")
	wrongCommandResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongCommandResponse, wrongCommand)
	if wrongCommandResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong command scope response = %d %s", wrongCommandResponse.Code, wrongCommandResponse.Body.String())
	}
}

func TestDesktopControlCommandRequiresActorAndMapsConflicts(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	deviceID := uuid.New()
	desktop := &desktopControlAdminStub{err: desktopcontrol.ErrConflict}
	handler, privateKey := newDesktopControlAdminHandler(t, now, desktop)

	withoutActor := desktopAdminRequest(t, privateKey, now, http.MethodPost,
		"/internal/admin/v1/desktop-control/instances/"+deviceID.String()+"/health-check", `{}`,
		ScopeDesktopControlCommand, false)
	withoutActor.Header.Set("Idempotency-Key", "desktop-health-check-no-actor")
	withoutActorResponse := httptest.NewRecorder()
	handler.ServeHTTP(withoutActorResponse, withoutActor)
	if withoutActorResponse.Code != http.StatusUnauthorized || desktop.queueCalls != 0 {
		t.Fatalf("missing actor response=%d calls=%d body=%s", withoutActorResponse.Code, desktop.queueCalls, withoutActorResponse.Body.String())
	}

	conflict := desktopAdminRequest(t, privateKey, now, http.MethodPost,
		"/internal/admin/v1/desktop-control/instances/"+deviceID.String()+"/health-check", `{}`,
		ScopeDesktopControlCommand, true)
	conflict.Header.Set("Idempotency-Key", "desktop-health-check-conflict")
	conflictResponse := httptest.NewRecorder()
	handler.ServeHTTP(conflictResponse, conflict)
	if conflictResponse.Code != http.StatusConflict || !strings.Contains(conflictResponse.Body.String(), "DESKTOP_CONTROL_CONFLICT") {
		t.Fatalf("conflict response=%d %s", conflictResponse.Code, conflictResponse.Body.String())
	}
}

type desktopControlAdminStub struct {
	page           desktopcontrol.InstancePage
	instance       desktopcontrol.Instance
	command        desktopcontrol.Command
	err            error
	listFilter     desktopcontrol.InstanceFilter
	queueDeviceID  uuid.UUID
	idempotencyKey string
	actor          desktopcontrol.AdminActor
	queueCalls     int
}

func (stub *desktopControlAdminStub) ListInstances(_ context.Context, filter desktopcontrol.InstanceFilter) (desktopcontrol.InstancePage, error) {
	stub.listFilter = filter
	return stub.page, stub.err
}

func (stub *desktopControlAdminStub) ListUserInstances(context.Context, uuid.UUID, desktopcontrol.InstanceFilter) (desktopcontrol.InstancePage, error) {
	return stub.page, stub.err
}

func (stub *desktopControlAdminStub) GetInstance(context.Context, uuid.UUID) (desktopcontrol.Instance, error) {
	return stub.instance, stub.err
}

func (stub *desktopControlAdminStub) QueueHealthCheck(_ context.Context, actor desktopcontrol.AdminActor, deviceID uuid.UUID, idempotencyKey string) (desktopcontrol.Command, error) {
	stub.queueCalls++
	stub.actor = actor
	stub.queueDeviceID = deviceID
	stub.idempotencyKey = idempotencyKey
	return stub.command, stub.err
}

func (stub *desktopControlAdminStub) GetCommand(context.Context, uuid.UUID) (desktopcontrol.Command, error) {
	return stub.command, stub.err
}

func newDesktopControlAdminHandler(t *testing.T, now time.Time, desktop *desktopControlAdminStub) (http.Handler, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(AuthenticatorConfig{
		PublicKey: publicKey, Issuer: "aera-admin", Subject: "aera-admin-e2e", Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerConfig{
		Service: newHandlerServiceStub(now), DesktopControl: desktop, Auth: auth,
		PostgreSQL: &handlerHealthStub{}, Redis: &handlerHealthStub{}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, privateKey
}

func desktopAdminRequest(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, method, path, body, scope string, actor bool) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://cloud.test"+path, strings.NewReader(body))
	setVerifiedClientCertificate(request)
	claims := validServiceClaims(now)
	claims["scope"] = []string{scope}
	if actor {
		claims["admin_id"] = authAdminID.String()
		claims["admin_role"] = "operator"
	}
	request.Header.Set("Authorization", "Bearer "+signServiceToken(t, privateKey, validServiceHeader(), claims))
	request.Header.Set("X-Request-ID", "request-desktop-control-test")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}
