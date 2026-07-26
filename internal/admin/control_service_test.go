package admin

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
)

func TestControlServiceNormalizesLookupAndNeverReturnsRawIdentity(t *testing.T) {
	repository := &controlRepositoryStub{lookupUser: User{
		ID: uuid.New(), MaskedEmail: "a***@example.com", Status: UserActive,
		AdministrativeRevision: 1, CreatedAt: time.Now().UTC(),
	}}
	service, err := NewControlService(ControlServiceConfig{
		Queries: repository, Protector: testProtector(t), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.LookupUser(context.Background(), LookupRequest{
		Kind: secure.IdentityEmail, Value: " Alice@Example.COM ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.normalizedLookup != "alice@example.com" || user.MaskedEmail != "a***@example.com" {
		t.Fatalf("lookup = %q / %+v", repository.normalizedLookup, user)
	}
}

func TestControlServiceProducesNonNullPagesAndScopedCursors(t *testing.T) {
	userID := uuid.New()
	next := &PagePosition{Time: time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC), ID: uuid.New()}
	repository := &controlRepositoryStub{
		userPage:    DataPage[User]{Next: next},
		devicePage:  DataPage[Device]{Next: next},
		sessionPage: DataPage[Session]{Next: next},
	}
	service, err := NewControlService(ControlServiceConfig{
		Queries: repository, Protector: testProtector(t), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	users, err := service.ListUsers(context.Background(), ListUsersRequest{})
	if err != nil || users.Items == nil || len(users.Items) != 0 || users.NextCursor == "" || repository.userQuery.Limit != 50 {
		t.Fatalf("ListUsers() = %+v, %v; query = %+v", users, err, repository.userQuery)
	}
	if _, err := service.ListUsers(context.Background(), ListUsersRequest{PageRequest: PageRequest{Cursor: users.NextCursor}}); err != nil {
		t.Fatalf("ListUsers(cursor) error = %v", err)
	}
	if repository.userQuery.After == nil || repository.userQuery.After.ID != next.ID {
		t.Fatalf("decoded user cursor = %+v", repository.userQuery.After)
	}

	devices, err := service.ListUserDevices(context.Background(), userID, PageRequest{})
	if err != nil || devices.Items == nil || devices.NextCursor == "" {
		t.Fatalf("ListUserDevices() = %+v, %v", devices, err)
	}
	if _, err := service.ListUserDevices(context.Background(), uuid.New(), PageRequest{Cursor: devices.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-user device cursor error = %v", err)
	}

	sessions, err := service.ListUserSessions(context.Background(), userID, PageRequest{})
	if err != nil || sessions.Items == nil || sessions.NextCursor == "" || repository.sessionQuery.Now.IsZero() {
		t.Fatalf("ListUserSessions() = %+v, %v; query = %+v", sessions, err, repository.sessionQuery)
	}
}

type officialAuditDataStub struct {
	page  DataPage[OfficialAuditEvent]
	query OfficialAuditQuery
}

func (s *officialAuditDataStub) ListOfficialAuditEvents(
	_ context.Context,
	query OfficialAuditQuery,
) (DataPage[OfficialAuditEvent], error) {
	s.query = query
	return s.page, nil
}

func TestControlServiceReturnsSafeOfficialAuditPage(t *testing.T) {
	next := &PagePosition{Time: time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC), ID: uuid.New()}
	audits := &officialAuditDataStub{page: DataPage[OfficialAuditEvent]{Items: []OfficialAuditEvent{{
		ID: uuid.New(), EventType: "official_release_pause", ObjectType: "official_release",
		ObjectID: uuid.New(), Outcome: "success", RequestID: "req-audit", ActorAdminID: uuid.New(),
		ActorAdminRole: "operator", CreatedAt: time.Date(2026, 7, 22, 11, 0, 0, 0, time.UTC),
	}}, Next: next}}
	service, err := NewControlService(ControlServiceConfig{
		Queries: &controlRepositoryStub{}, OfficialAudit: audits,
		Protector: testProtector(t), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.ListOfficialAuditEvents(context.Background(), PageRequest{Limit: 20})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" || audits.query.Limit != 20 {
		t.Fatalf("audit page = %+v / %v / %+v", page, err, audits.query)
	}
	if page.Items[0].ActorAdminRole != "operator" || page.Items[0].EventType != "official_release_pause" {
		t.Fatalf("audit item = %+v", page.Items[0])
	}
}

type operationCommandDataStub struct {
	operation Operation
}

func (s *operationCommandDataStub) Execute(context.Context, Action, uuid.UUID, Command) (Operation, error) {
	return Operation{}, errors.New("unexpected Execute call")
}

func (s *operationCommandDataStub) GetOperation(context.Context, uuid.UUID) (Operation, error) {
	return s.operation, nil
}

func TestControlServiceRejectsMismatchedOperationIdentity(t *testing.T) {
	requested := uuid.New()
	commands := &operationCommandDataStub{operation: Operation{
		ID: uuid.New(), Status: OperationSucceeded, AdministrativeRevision: 1,
		UpdatedAt: time.Now().UTC(),
	}}
	service, err := NewControlService(ControlServiceConfig{
		Queries: &controlRepositoryStub{}, Commands: commands,
		Protector: testProtector(t), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetOperation(context.Background(), requested); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("mismatched operation error = %v", err)
	}
}

func TestControlServiceRejectsInvalidReadRequestsBeforeStorage(t *testing.T) {
	repository := &controlRepositoryStub{}
	service, err := NewControlService(ControlServiceConfig{
		Queries: repository, Protector: testProtector(t), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		call func() error
		want error
	}{
		{name: "bad status", call: func() error {
			_, err := service.ListUsers(context.Background(), ListUsersRequest{Status: UserStatus("deleted")})
			return err
		}, want: ErrInvalidCommand},
		{name: "limit too high", call: func() error {
			_, err := service.ListUsers(context.Background(), ListUsersRequest{PageRequest: PageRequest{Limit: 101}})
			return err
		}, want: ErrInvalidCommand},
		{name: "bad cursor", call: func() error {
			_, err := service.ListUsers(context.Background(), ListUsersRequest{PageRequest: PageRequest{Cursor: "bad+cursor"}})
			return err
		}, want: ErrInvalidCursor},
		{name: "bad lookup", call: func() error {
			_, err := service.LookupUser(context.Background(), LookupRequest{Kind: secure.IdentityEmail, Value: "not-an-email"})
			return err
		}, want: ErrInvalidCommand},
		{name: "missing user", call: func() error { _, err := service.GetUser(context.Background(), uuid.Nil); return err }, want: ErrInvalidCommand},
		{name: "missing device owner", call: func() error {
			_, err := service.ListUserDevices(context.Background(), uuid.Nil, PageRequest{})
			return err
		}, want: ErrInvalidCommand},
		{name: "missing session owner", call: func() error {
			_, err := service.ListUserSessions(context.Background(), uuid.Nil, PageRequest{})
			return err
		}, want: ErrInvalidCommand},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if repository.calls != 0 {
		t.Fatalf("storage calls = %d, want 0", repository.calls)
	}
}

func TestNewControlServiceRequiresReadDependencies(t *testing.T) {
	repository := &controlRepositoryStub{}
	protector := testProtector(t)
	tests := []ControlServiceConfig{
		{Protector: protector, Clock: time.Now},
		{Queries: repository, Clock: time.Now},
		{Queries: repository, Protector: protector},
	}
	for index, config := range tests {
		if _, err := NewControlService(config); err == nil {
			t.Fatalf("config %d was accepted", index)
		}
	}
}

type controlRepositoryStub struct {
	calls            int
	normalizedLookup string
	lookupUser       User
	userPage         DataPage[User]
	devicePage       DataPage[Device]
	sessionPage      DataPage[Session]
	stats            PlatformStats
	statsErr         error
	deviceStats      DeviceStats
	deviceStatsErr   error
	memberships      UserMemberships
	membershipsErr   error
	userQuery        UserQuery
	deviceQuery      DeviceQuery
	sessionQuery     SessionQuery
}

func (s *controlRepositoryStub) LookupUser(_ context.Context, _ secure.IdentityKind, normalized string) (User, error) {
	s.calls++
	s.normalizedLookup = normalized
	return s.lookupUser, nil
}

func (s *controlRepositoryStub) ListUsers(_ context.Context, query UserQuery) (DataPage[User], error) {
	s.calls++
	s.userQuery = query
	return s.userPage, nil
}

func (s *controlRepositoryStub) GetUser(context.Context, uuid.UUID) (User, error) {
	s.calls++
	return s.lookupUser, nil
}

func (s *controlRepositoryStub) Stats(context.Context) (PlatformStats, error) {
	s.calls++
	return s.stats, s.statsErr
}

func (s *controlRepositoryStub) DeviceStats(context.Context) (DeviceStats, error) {
	s.calls++
	return s.deviceStats, s.deviceStatsErr
}

func (s *controlRepositoryStub) UserMemberships(context.Context, uuid.UUID) (UserMemberships, error) {
	s.calls++
	return s.memberships, s.membershipsErr
}

func (s *controlRepositoryStub) ListUserDevices(_ context.Context, query DeviceQuery) (DataPage[Device], error) {
	s.calls++
	s.deviceQuery = query
	return s.devicePage, nil
}

func (s *controlRepositoryStub) ListUserSessions(_ context.Context, query SessionQuery) (DataPage[Session], error) {
	s.calls++
	s.sessionQuery = query
	return s.sessionPage, nil
}

func testProtector(t *testing.T) *Protector {
	t.Helper()
	protector, err := NewProtector("test-v1", map[string][]byte{"test-v1": bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return protector
}
