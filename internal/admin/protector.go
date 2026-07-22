package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	idempotencyDomain = "aera-cloud.admin.idempotency.v1"
	requestDomain     = "aera-cloud.admin.request.v1"
	cursorDomain      = "aera-cloud.admin.cursor.v1"
	cursorVersion     = byte(1)
	cursorMACSize     = sha256.Size
)

var (
	protectorKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	cursorResourcePattern = regexp.MustCompile(`^[a-z][a-z0-9_./:-]{0,127}$`)
	cursorTokenPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
)

type Protector struct {
	activeKeyID string
	keys        map[string][]byte
	keyOrder    []string
}

func NewProtector(activeKeyID string, keys map[string][]byte) (*Protector, error) {
	if !protectorKeyIDPattern.MatchString(activeKeyID) || len(keys) == 0 {
		return nil, errors.New("admin protector key ring is invalid")
	}
	copied := make(map[string][]byte, len(keys))
	ordered := make([]string, 0, len(keys))
	for keyID, material := range keys {
		if !protectorKeyIDPattern.MatchString(keyID) || len(material) != sha256.Size {
			return nil, errors.New("admin protector key ring is invalid")
		}
		copied[keyID] = append([]byte(nil), material...)
		if keyID != activeKeyID {
			ordered = append(ordered, keyID)
		}
	}
	if _, ok := copied[activeKeyID]; !ok {
		return nil, errors.New("admin protector active key is unavailable")
	}
	sort.Strings(ordered)
	ordered = append([]string{activeKeyID}, ordered...)
	return &Protector{activeKeyID: activeKeyID, keys: copied, keyOrder: ordered}, nil
}

func (p *Protector) IdempotencyCandidates(operationID uuid.UUID) []Digest {
	if p == nil || operationID == uuid.Nil {
		return nil
	}
	digests := make([]Digest, 0, len(p.keyOrder))
	for _, keyID := range p.keyOrder {
		digests = append(digests, Digest{
			KeyID: keyID,
			Sum:   protectedDigest(p.keys[keyID], idempotencyDomain, operationID[:]),
		})
	}
	return digests
}

func (p *Protector) RequestFingerprint(keyID string, action Action, targetID uuid.UUID, command Command) []byte {
	if p == nil {
		return nil
	}
	key, ok := p.keys[keyID]
	if !ok {
		return nil
	}
	operationID := command.OperationID
	actorID := command.ActorAdminID
	approval := []byte(nil)
	if command.ApprovalID != nil {
		approvalID := *command.ApprovalID
		approval = approvalID[:]
	}
	revision := make([]byte, 8)
	binary.BigEndian.PutUint64(revision, uint64(command.ExpectedRevision))
	return protectedDigest(
		key,
		requestDomain,
		[]byte(action),
		targetID[:],
		operationID[:],
		actorID[:],
		approval,
		[]byte(command.RequestID),
		[]byte(command.ReasonCode),
		[]byte(command.TicketReference),
		[]byte(command.Note),
		revision,
	)
}

func (p *Protector) EncodeCursor(resource string, position PagePosition) (string, error) {
	if p == nil || !cursorResourcePattern.MatchString(resource) || position.Time.IsZero() || position.ID == uuid.Nil {
		return "", ErrInvalidCursor
	}
	keyID := p.activeKeyID
	payload := make([]byte, 0, 2+len(keyID)+8+len(position.ID))
	payload = append(payload, cursorVersion, byte(len(keyID)))
	payload = append(payload, keyID...)
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(position.Time.UTC().UnixNano()))
	payload = append(payload, timestamp...)
	payload = append(payload, position.ID[:]...)
	mac := protectedDigest(p.keys[keyID], cursorDomain, []byte(resource), payload)
	encoded := base64.RawURLEncoding.EncodeToString(append(payload, mac...))
	if !cursorTokenPattern.MatchString(encoded) {
		return "", ErrInvalidCursor
	}
	return encoded, nil
}

func (p *Protector) DecodeCursor(resource, cursor string) (*PagePosition, error) {
	if p == nil || !cursorResourcePattern.MatchString(resource) || !cursorTokenPattern.MatchString(cursor) {
		return nil, ErrInvalidCursor
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != cursor || len(decoded) < 2+1+8+16+cursorMACSize {
		return nil, ErrInvalidCursor
	}
	if decoded[0] != cursorVersion {
		return nil, ErrInvalidCursor
	}
	keyIDLength := int(decoded[1])
	payloadLength := 2 + keyIDLength + 8 + 16
	if keyIDLength < 1 || payloadLength+cursorMACSize != len(decoded) {
		return nil, ErrInvalidCursor
	}
	keyID := string(decoded[2 : 2+keyIDLength])
	key, ok := p.keys[keyID]
	if !ok {
		return nil, ErrInvalidCursor
	}
	payload := decoded[:payloadLength]
	providedMAC := decoded[payloadLength:]
	expectedMAC := protectedDigest(key, cursorDomain, []byte(resource), payload)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return nil, ErrInvalidCursor
	}

	timestampStart := 2 + keyIDLength
	nanoseconds := int64(binary.BigEndian.Uint64(decoded[timestampStart : timestampStart+8]))
	var id uuid.UUID
	copy(id[:], decoded[timestampStart+8:payloadLength])
	if id == uuid.Nil {
		return nil, ErrInvalidCursor
	}
	return &PagePosition{Time: time.Unix(0, nanoseconds).UTC(), ID: id}, nil
}

func protectedDigest(key []byte, domain string, fields ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	length := make([]byte, 4)
	for _, field := range fields {
		binary.BigEndian.PutUint32(length, uint32(len(field)))
		_, _ = mac.Write(length)
		_, _ = mac.Write(field)
	}
	return mac.Sum(nil)
}
