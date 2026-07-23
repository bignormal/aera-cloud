package encryptedbackup

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/google/uuid"
)

const maxCiphertextObjectBytes int64 = 1 << 30

var (
	ErrCiphertextNotFound      = errors.New("ciphertext object not found")
	ErrCiphertextAlreadyExists = errors.New("ciphertext object already exists")
	ErrCiphertextMismatch      = errors.New("ciphertext size or digest mismatch")
	ErrObjectStoreUnavailable  = errors.New("ciphertext object store unavailable")

	ciphertextObjectIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type CiphertextObjectRef struct {
	userID   uuid.UUID
	backupID uuid.UUID
	objectID string
}

func NewCiphertextObjectRef(userID, backupID uuid.UUID, objectID string) (CiphertextObjectRef, error) {
	if userID == uuid.Nil || backupID == uuid.Nil || !ciphertextObjectIDPattern.MatchString(objectID) {
		return CiphertextObjectRef{}, errors.New("invalid ciphertext object reference")
	}
	return CiphertextObjectRef{
		userID:   userID,
		backupID: backupID,
		objectID: objectID,
	}, nil
}

func (ref CiphertextObjectRef) objectKey() string {
	return fmt.Sprintf(
		"users/%s/backups/%s/%s",
		ref.userID.String(),
		ref.backupID.String(),
		ref.objectID,
	)
}

func (ref CiphertextObjectRef) ObjectID() string {
	return ref.objectID
}

type CiphertextMetadata struct {
	Key    string
	Size   int64
	SHA256 [sha256.Size]byte
}

type CiphertextDownload struct {
	Body     io.ReadCloser
	Metadata CiphertextMetadata
}

type ObjectStore interface {
	PutCiphertext(
		ctx context.Context,
		ref CiphertextObjectRef,
		body io.Reader,
		size int64,
		digest [sha256.Size]byte,
	) (CiphertextMetadata, error)
	GetCiphertext(ctx context.Context, ref CiphertextObjectRef) (CiphertextDownload, error)
	HeadCiphertext(ctx context.Context, ref CiphertextObjectRef) (CiphertextMetadata, error)
	DeleteCiphertexts(ctx context.Context, refs []CiphertextObjectRef) error
}
