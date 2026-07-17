package secure

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/google/uuid"
)

func RandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("random value size must be positive")
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, errors.New("secure random source is unavailable")
	}
	return value, nil
}

func RandomToken(size int) (string, error) {
	value, err := RandomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func RandomUUID() (uuid.UUID, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return uuid.Nil, errors.New("secure random source is unavailable")
	}
	return value, nil
}
