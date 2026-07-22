package admin

import (
	"bytes"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProtectorSeparatesDomainsAndRejectsCursorCrossUse(t *testing.T) {
	protector, err := NewProtector("v1", map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse("019f0000-0000-7000-8000-000000000071")
	digests := protector.IdempotencyCandidates(id)
	fingerprint := protector.RequestFingerprint("v1", RevokeSession, id, validCommand(id))
	if len(digests) != 1 || len(digests[0].Sum) != 32 || len(fingerprint) != 32 {
		t.Fatalf("digest lengths = %d / %d", len(digests), len(fingerprint))
	}
	if bytes.Equal(digests[0].Sum, fingerprint) {
		t.Fatal("HMAC domains overlap")
	}
	cursor, err := protector.EncodeCursor("users", PagePosition{Time: time.Unix(10, 0).UTC(), ID: id})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`).MatchString(cursor) {
		t.Fatalf("cursor = %q, want base64url token", cursor)
	}
	if _, err := protector.DecodeCursor("sessions", cursor); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-resource cursor error = %v", err)
	}
	position, err := protector.DecodeCursor("users", cursor)
	if err != nil || position.ID != id || !position.Time.Equal(time.Unix(10, 0).UTC()) {
		t.Fatalf("decoded position = %+v, %v", position, err)
	}
}

func TestProtectorUsesActiveKeyFirstAndCopiesKeys(t *testing.T) {
	active := bytes.Repeat([]byte{7}, 32)
	keys := map[string][]byte{
		"v1": bytes.Repeat([]byte{6}, 32),
		"v2": active,
	}
	protector, err := NewProtector("v2", keys)
	if err != nil {
		t.Fatal(err)
	}
	keys["v2"][0] ^= 0xff

	id := uuid.MustParse("019f0000-0000-7000-8000-000000000071")
	digests := protector.IdempotencyCandidates(id)
	if len(digests) != 2 || digests[0].KeyID != "v2" || digests[1].KeyID != "v1" {
		t.Fatalf("digest order = %+v", digests)
	}
	second, err := NewProtector("v2", map[string][]byte{
		"v1": bytes.Repeat([]byte{6}, 32),
		"v2": bytes.Repeat([]byte{7}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digests[0].Sum, second.IdempotencyCandidates(id)[0].Sum) {
		t.Fatal("protector retained caller-owned key memory")
	}
}

func TestProtectorRejectsTamperedAndMalformedCursors(t *testing.T) {
	protector, err := NewProtector("v1", map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	position := PagePosition{Time: time.Date(2026, 7, 22, 10, 0, 0, 123, time.UTC), ID: uuid.New()}
	cursor, err := protector.EncodeCursor("devices", position)
	if err != nil {
		t.Fatal(err)
	}
	tampered := cursor[:len(cursor)-1] + map[bool]string{true: "A", false: "B"}[cursor[len(cursor)-1] != 'A']
	for _, invalid := range []string{"", "not+padded", tampered, string(bytes.Repeat([]byte{'A'}, 513))} {
		if _, err := protector.DecodeCursor("devices", invalid); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("DecodeCursor(%q) error = %v", invalid, err)
		}
	}
	if _, err := protector.EncodeCursor("", position); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("empty resource error = %v", err)
	}
	if _, err := protector.EncodeCursor("devices", PagePosition{}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("zero position error = %v", err)
	}
}

func TestProtectorBindsCursorToParentResourceScope(t *testing.T) {
	protector, err := NewProtector("v1", map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	firstUserID, secondUserID := uuid.New(), uuid.New()
	position := PagePosition{Time: time.Now().UTC(), ID: uuid.New()}
	cursor, err := protector.EncodeCursor("devices/"+firstUserID.String(), position)
	if err != nil {
		t.Fatalf("EncodeCursor() error = %v", err)
	}
	if _, err := protector.DecodeCursor("devices/"+secondUserID.String(), cursor); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-user cursor error = %v", err)
	}
}

func TestRequestFingerprintCoversEveryCommandField(t *testing.T) {
	protector, err := NewProtector("v1", map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	targetID := uuid.New()
	command := validCommand(uuid.New())
	approvalID := uuid.New()
	command.ApprovalID = &approvalID
	command.TicketReference = "OPS-123"
	command.Note = "support action"
	baseline := protector.RequestFingerprint("v1", DisableUser, targetID, command)
	if len(baseline) != 32 {
		t.Fatalf("fingerprint length = %d", len(baseline))
	}

	variants := []Command{command, command, command, command, command, command, command}
	variants[0].OperationID = uuid.New()
	variants[1].ActorAdminID = uuid.New()
	otherApproval := uuid.New()
	variants[2].ApprovalID = &otherApproval
	variants[3].RequestID = "req-other"
	variants[4].ReasonCode = "another_reason"
	variants[5].TicketReference = "OPS-124"
	variants[6].Note = "different note"
	for index, variant := range variants {
		if bytes.Equal(baseline, protector.RequestFingerprint("v1", DisableUser, targetID, variant)) {
			t.Fatalf("command variant %d did not change fingerprint", index)
		}
	}
	revisionVariant := command
	revisionVariant.ExpectedRevision++
	if bytes.Equal(baseline, protector.RequestFingerprint("v1", DisableUser, targetID, revisionVariant)) {
		t.Fatal("revision did not change fingerprint")
	}
	if bytes.Equal(baseline, protector.RequestFingerprint("v1", EnableUser, targetID, command)) {
		t.Fatal("action did not change fingerprint")
	}
	if bytes.Equal(baseline, protector.RequestFingerprint("v1", DisableUser, uuid.New(), command)) {
		t.Fatal("target did not change fingerprint")
	}
	if got := protector.RequestFingerprint("missing", DisableUser, targetID, command); got != nil {
		t.Fatalf("unknown key fingerprint = %x", got)
	}
}

func TestNewProtectorRejectsInvalidKeyRings(t *testing.T) {
	tests := []struct {
		name   string
		active string
		keys   map[string][]byte
	}{
		{name: "empty", active: "v1", keys: nil},
		{name: "missing active", active: "v2", keys: map[string][]byte{"v1": bytes.Repeat([]byte{1}, 32)}},
		{name: "short key", active: "v1", keys: map[string][]byte{"v1": bytes.Repeat([]byte{1}, 31)}},
		{name: "blank id", active: "", keys: map[string][]byte{"": bytes.Repeat([]byte{1}, 32)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProtector(test.active, test.keys); err == nil {
				t.Fatal("NewProtector() succeeded")
			}
		})
	}
}

func validCommand(operationID uuid.UUID) Command {
	return Command{
		OperationID:      operationID,
		ActorAdminID:     uuid.MustParse("019f0000-0000-7000-8000-000000000081"),
		RequestID:        "req-protector-1",
		ReasonCode:       "session_cleanup",
		ExpectedRevision: 1,
	}
}
