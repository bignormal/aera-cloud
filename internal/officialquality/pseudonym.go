package officialquality

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
)

const pseudonymDomain = "official-quality-v1"

type Pseudonymizer struct {
	activeKeyID string
	keyIDs      []string
	keys        map[string][]byte
}

func NewPseudonymizer(activeKeyID string, keys map[string][]byte) (*Pseudonymizer, error) {
	if activeKeyID == "" || len(keys) == 0 {
		return nil, errors.New("official quality pseudonym key ring is invalid")
	}
	copied := make(map[string][]byte, len(keys))
	ids := make([]string, 0, len(keys))
	for keyID, key := range keys {
		if keyID == "" || len(key) != sha256.Size {
			return nil, errors.New("official quality pseudonym key ring is invalid")
		}
		copied[keyID] = append([]byte(nil), key...)
		ids = append(ids, keyID)
	}
	if _, ok := copied[activeKeyID]; !ok {
		return nil, errors.New("official quality active pseudonym key is unavailable")
	}
	sort.Strings(ids)
	for index, keyID := range ids {
		if keyID == activeKeyID {
			ids = append([]string{keyID}, append(ids[:index], ids[index+1:]...)...)
			break
		}
	}
	return &Pseudonymizer{activeKeyID: activeKeyID, keyIDs: ids, keys: copied}, nil
}

func (p *Pseudonymizer) Active(userID uuid.UUID, purpose string, day time.Time) []byte {
	if p == nil {
		return nil
	}
	return derivePseudonym(p.keys[p.activeKeyID], userID, purpose, day)
}

func (p *Pseudonymizer) Candidates(userID uuid.UUID, purpose string, day time.Time) [][]byte {
	if p == nil {
		return nil
	}
	values := make([][]byte, 0, len(p.keyIDs))
	for _, keyID := range p.keyIDs {
		values = append(values, derivePseudonym(p.keys[keyID], userID, purpose, day))
	}
	return values
}

func (p *Pseudonymizer) BindingProofDigest(bindingProof uuid.UUID, purpose string, day time.Time) []byte {
	if p == nil || bindingProof == uuid.Nil {
		return nil
	}
	mac := hmac.New(sha256.New, p.keys[p.activeKeyID])
	_, _ = mac.Write([]byte(pseudonymDomain + "-binding\x00" + purpose + "\x00" +
		bindingProof.String() + "\x00" + day.UTC().Format("2006-01-02")))
	return mac.Sum(nil)
}

func derivePseudonym(key []byte, userID uuid.UUID, purpose string, day time.Time) []byte {
	if len(key) != sha256.Size || userID == uuid.Nil ||
		(purpose != PurposeMetrics && purpose != PurposeExplicitFeedback) || day.IsZero() {
		return nil
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(pseudonymDomain + "\x00" + purpose + "\x00" +
		userID.String() + "\x00" + day.UTC().Format("2006-01-02")))
	return mac.Sum(nil)
}
