package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type IdentityKind string

const (
	IdentityEmail IdentityKind = "email"
	IdentityPhone IdentityKind = "phone"
)

type IdentityCodecConfig struct {
	ActiveEncryptionKeyID string
	EncryptionKeys        map[string][]byte
	ActiveLookupKeyID     string
	LookupKeys            map[string][]byte
}

type SealedIdentity struct {
	EncryptionKeyID string
	Nonce           []byte
	Ciphertext      []byte
	LookupKeyID     string
	LookupHMAC      []byte
}

type LookupIndex struct {
	KeyID string
	HMAC  []byte
}

type IdentityCodec struct {
	activeEncryptionKeyID string
	encryptionKeys        map[string][]byte
	activeLookupKeyID     string
	lookupKeys            map[string][]byte
	lookupOrder           []string
}

func NormalizeIdentity(kind IdentityKind, raw string) (string, error) {
	switch kind {
	case IdentityEmail:
		return normalizeEmail(raw)
	case IdentityPhone:
		return normalizeMainlandPhone(raw)
	default:
		return "", errors.New("unsupported identity kind")
	}
}

func NewIdentityCodec(config IdentityCodecConfig) (*IdentityCodec, error) {
	encryptionKeys, err := copyAndValidateKeys(config.EncryptionKeys, 32, true)
	if err != nil {
		return nil, err
	}
	if _, ok := encryptionKeys[config.ActiveEncryptionKeyID]; !ok || config.ActiveEncryptionKeyID == "" {
		return nil, errors.New("active identity encryption key is unavailable")
	}
	lookupKeys, err := copyAndValidateKeys(config.LookupKeys, 32, false)
	if err != nil {
		return nil, err
	}
	if _, ok := lookupKeys[config.ActiveLookupKeyID]; !ok || config.ActiveLookupKeyID == "" {
		return nil, errors.New("active identity lookup key is unavailable")
	}

	lookupOrder := make([]string, 0, len(lookupKeys))
	for keyID := range lookupKeys {
		if keyID != config.ActiveLookupKeyID {
			lookupOrder = append(lookupOrder, keyID)
		}
	}
	sort.Strings(lookupOrder)
	lookupOrder = append([]string{config.ActiveLookupKeyID}, lookupOrder...)

	return &IdentityCodec{
		activeEncryptionKeyID: config.ActiveEncryptionKeyID,
		encryptionKeys:        encryptionKeys,
		activeLookupKeyID:     config.ActiveLookupKeyID,
		lookupKeys:            lookupKeys,
		lookupOrder:           lookupOrder,
	}, nil
}

func (c *IdentityCodec) Seal(kind IdentityKind, normalized string) (SealedIdentity, error) {
	if !validIdentityKind(kind) || normalized == "" {
		return SealedIdentity{}, errors.New("identity kind and normalized value are required")
	}
	block, err := aes.NewCipher(c.encryptionKeys[c.activeEncryptionKeyID])
	if err != nil {
		return SealedIdentity{}, errors.New("identity encryption is unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return SealedIdentity{}, errors.New("identity encryption is unavailable")
	}
	nonce, err := RandomBytes(aead.NonceSize())
	if err != nil {
		return SealedIdentity{}, err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(normalized), identityAAD(kind))
	lookup := c.lookup(kind, normalized, c.activeLookupKeyID)
	return SealedIdentity{
		EncryptionKeyID: c.activeEncryptionKeyID,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
		LookupKeyID:     lookup.KeyID,
		LookupHMAC:      lookup.HMAC,
	}, nil
}

func (c *IdentityCodec) Open(kind IdentityKind, sealed SealedIdentity) (string, error) {
	if !validIdentityKind(kind) {
		return "", errors.New("unsupported identity kind")
	}
	key, ok := c.encryptionKeys[sealed.EncryptionKeyID]
	if !ok {
		return "", errors.New("identity encryption key is unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("identity decryption is unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed.Nonce) != aead.NonceSize() {
		return "", errors.New("encrypted identity is malformed")
	}
	plaintext, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, identityAAD(kind))
	if err != nil {
		return "", errors.New("encrypted identity could not be authenticated")
	}
	return string(plaintext), nil
}

func (c *IdentityCodec) LookupCandidates(kind IdentityKind, normalized string) []LookupIndex {
	if !validIdentityKind(kind) || normalized == "" {
		return nil
	}
	indices := make([]LookupIndex, 0, len(c.lookupOrder))
	for _, keyID := range c.lookupOrder {
		indices = append(indices, c.lookup(kind, normalized, keyID))
	}
	return indices
}

func (c *IdentityCodec) lookup(kind IdentityKind, normalized, keyID string) LookupIndex {
	mac := hmac.New(sha256.New, c.lookupKeys[keyID])
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(normalized))
	return LookupIndex{KeyID: keyID, HMAC: mac.Sum(nil)}
}

func copyAndValidateKeys(keys map[string][]byte, minimumLength int, exact bool) (map[string][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("identity key ring is empty")
	}
	copied := make(map[string][]byte, len(keys))
	for keyID, material := range keys {
		invalidLength := len(material) < minimumLength
		if exact {
			invalidLength = len(material) != minimumLength
		}
		if strings.TrimSpace(keyID) == "" || invalidLength {
			return nil, errors.New("identity key ring contains an invalid key")
		}
		copied[keyID] = append([]byte(nil), material...)
	}
	return copied, nil
}

func normalizeEmail(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if !utf8.ValidString(normalized) || len(normalized) > 254 || strings.Count(normalized, "@") != 1 {
		return "", errors.New("invalid email address")
	}
	local, domain, _ := strings.Cut(normalized, "@")
	if local == "" || len(local) > 64 || domain == "" || !strings.Contains(domain, ".") {
		return "", errors.New("invalid email address")
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", errors.New("invalid email address")
	}
	for _, character := range normalized {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", errors.New("invalid email address")
		}
	}
	return normalized, nil
}

func normalizeMainlandPhone(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid mainland phone number")
	}
	var compact strings.Builder
	for index, character := range trimmed {
		switch {
		case character >= '0' && character <= '9':
			compact.WriteRune(character)
		case character == '+' && index == 0:
			compact.WriteRune(character)
		case character == '-' || character == '(' || character == ')' || unicode.IsSpace(character):
		default:
			return "", errors.New("invalid mainland phone number")
		}
	}
	value := compact.String()
	switch {
	case strings.HasPrefix(value, "+"):
		if !strings.HasPrefix(value, "+86") {
			return "", errors.New("phone number must use mainland China country code")
		}
		value = strings.TrimPrefix(value, "+86")
	case strings.HasPrefix(value, "00"):
		if !strings.HasPrefix(value, "0086") {
			return "", errors.New("phone number must use mainland China country code")
		}
		value = strings.TrimPrefix(value, "0086")
	case len(value) == 13 && strings.HasPrefix(value, "86"):
		value = strings.TrimPrefix(value, "86")
	}
	if len(value) != 11 || value[0] != '1' || value[1] < '3' || value[1] > '9' {
		return "", errors.New("invalid mainland mobile number")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return "", errors.New("invalid mainland mobile number")
		}
	}
	return "+86" + value, nil
}

func validIdentityKind(kind IdentityKind) bool {
	return kind == IdentityEmail || kind == IdentityPhone
}

func identityAAD(kind IdentityKind) []byte {
	return []byte("agentera.identity.v1\x00" + string(kind))
}
