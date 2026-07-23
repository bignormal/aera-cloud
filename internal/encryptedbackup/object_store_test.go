package encryptedbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMinIOStoreRoundTripsExactCiphertextWithoutOverwrite(t *testing.T) {
	store := newMinIOIntegrationStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	ref := mustCiphertextRef(t, uuid.New(), uuid.New(), "round-trip")
	t.Cleanup(func() {
		_ = store.DeleteCiphertexts(context.Background(), []CiphertextObjectRef{ref})
	})

	ciphertext := bytes.Repeat([]byte{0xa5}, 64*1024+17)
	digest := sha256.Sum256(ciphertext)
	stored, err := store.PutCiphertext(ctx, ref, bytes.NewReader(ciphertext), int64(len(ciphertext)), digest)
	if err != nil {
		t.Fatalf("PutCiphertext() error = %v", err)
	}
	if stored.Key != ref.objectKey() || stored.Size != int64(len(ciphertext)) || stored.SHA256 != digest {
		t.Fatalf("PutCiphertext() metadata = %+v", stored)
	}

	head, err := store.HeadCiphertext(ctx, ref)
	if err != nil {
		t.Fatalf("HeadCiphertext() error = %v", err)
	}
	if head != stored {
		t.Fatalf("HeadCiphertext() = %+v, want %+v", head, stored)
	}

	download, err := store.GetCiphertext(ctx, ref)
	if err != nil {
		t.Fatalf("GetCiphertext() error = %v", err)
	}
	got, readErr := io.ReadAll(download.Body)
	closeErr := download.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read/close ciphertext = %v / %v", readErr, closeErr)
	}
	if !bytes.Equal(got, ciphertext) || download.Metadata != stored {
		t.Fatalf("GetCiphertext() returned different ciphertext or metadata")
	}

	_, err = store.PutCiphertext(ctx, ref, bytes.NewReader(ciphertext), int64(len(ciphertext)), digest)
	if !errors.Is(err, ErrCiphertextAlreadyExists) {
		t.Fatalf("second PutCiphertext() error = %v, want ErrCiphertextAlreadyExists", err)
	}
}

func TestMinIOStoreRejectsWrongSizeAndDigestWithoutLeavingObjects(t *testing.T) {
	store := newMinIOIntegrationStore(t)
	cases := []struct {
		name       string
		declared   int64
		digest     [sha256.Size]byte
		ciphertext []byte
	}{
		{
			name:       "declared size too small",
			declared:   31,
			digest:     sha256.Sum256(bytes.Repeat([]byte{0x11}, 32)),
			ciphertext: bytes.Repeat([]byte{0x11}, 32),
		},
		{
			name:       "declared size too large",
			declared:   33,
			digest:     sha256.Sum256(bytes.Repeat([]byte{0x12}, 32)),
			ciphertext: bytes.Repeat([]byte{0x12}, 32),
		},
		{
			name:       "digest mismatch",
			declared:   32,
			digest:     sha256.Sum256([]byte("different ciphertext")),
			ciphertext: bytes.Repeat([]byte{0x13}, 32),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			ref := mustCiphertextRef(t, uuid.New(), uuid.New(), test.name)
			_, err := store.PutCiphertext(
				ctx,
				ref,
				bytes.NewReader(test.ciphertext),
				test.declared,
				test.digest,
			)
			if !errors.Is(err, ErrCiphertextMismatch) {
				t.Fatalf("PutCiphertext() error = %v, want ErrCiphertextMismatch", err)
			}
			if _, err := store.HeadCiphertext(ctx, ref); !errors.Is(err, ErrCiphertextNotFound) {
				t.Fatalf("HeadCiphertext() after rejected put = %v, want ErrCiphertextNotFound", err)
			}
		})
	}
}

func TestMinIOStoreMissingAndDeleteAreDeterministic(t *testing.T) {
	store := newMinIOIntegrationStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ref := mustCiphertextRef(t, uuid.New(), uuid.New(), "missing")

	if _, err := store.HeadCiphertext(ctx, ref); !errors.Is(err, ErrCiphertextNotFound) {
		t.Fatalf("HeadCiphertext() error = %v, want ErrCiphertextNotFound", err)
	}
	if _, err := store.GetCiphertext(ctx, ref); !errors.Is(err, ErrCiphertextNotFound) {
		t.Fatalf("GetCiphertext() error = %v, want ErrCiphertextNotFound", err)
	}
	if err := store.DeleteCiphertexts(ctx, []CiphertextObjectRef{ref, ref}); err != nil {
		t.Fatalf("DeleteCiphertexts() missing object error = %v", err)
	}

	ciphertext := []byte("authenticated ciphertext")
	digest := sha256.Sum256(ciphertext)
	if _, err := store.PutCiphertext(ctx, ref, bytes.NewReader(ciphertext), int64(len(ciphertext)), digest); err != nil {
		t.Fatalf("PutCiphertext() error = %v", err)
	}
	if err := store.DeleteCiphertexts(ctx, []CiphertextObjectRef{ref}); err != nil {
		t.Fatalf("DeleteCiphertexts() error = %v", err)
	}
	if err := store.DeleteCiphertexts(ctx, []CiphertextObjectRef{ref}); err != nil {
		t.Fatalf("DeleteCiphertexts() retry error = %v", err)
	}
	if _, err := store.HeadCiphertext(ctx, ref); !errors.Is(err, ErrCiphertextNotFound) {
		t.Fatalf("HeadCiphertext() after delete = %v, want ErrCiphertextNotFound", err)
	}
}

func TestCiphertextObjectRefRejectsClientControlledPaths(t *testing.T) {
	userID := uuid.New()
	backupID := uuid.New()
	for _, objectID := range []string{
		"",
		"manifest",
		"../escape",
		strings.Repeat("a", 63),
		strings.Repeat("A", 64),
		strings.Repeat("g", 64),
	} {
		t.Run(objectID, func(t *testing.T) {
			if _, err := NewCiphertextObjectRef(userID, backupID, objectID); err == nil {
				t.Fatalf("NewCiphertextObjectRef() accepted %q", objectID)
			}
		})
	}
	ref := mustCiphertextRef(t, userID, backupID, "valid")
	wantPrefix := "users/" + userID.String() + "/backups/" + backupID.String() + "/"
	if !strings.HasPrefix(ref.objectKey(), wantPrefix) {
		t.Fatalf("object key %q does not use server-owned prefix %q", ref.objectKey(), wantPrefix)
	}
}

func newMinIOIntegrationStore(t *testing.T) ObjectStore {
	t.Helper()
	if os.Getenv("AERA_INTEGRATION_TESTS") != "1" {
		t.Skip("set AERA_INTEGRATION_TESTS=1 to run MinIO integration tests")
	}
	cfg := MinIOStoreConfig{
		Endpoint:  requiredObjectStoreEnv(t, "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENDPOINT"),
		Bucket:    requiredObjectStoreEnv(t, "AGENTERA_CLOUD_ENCRYPTED_BACKUP_BUCKET"),
		Region:    requiredObjectStoreEnv(t, "AGENTERA_CLOUD_ENCRYPTED_BACKUP_REGION"),
		AccessKey: requiredObjectStoreEnv(t, "AGENTERA_CLOUD_ENCRYPTED_BACKUP_ACCESS_KEY"),
		SecretKey: requiredObjectStoreEnv(t, "AGENTERA_CLOUD_ENCRYPTED_BACKUP_SECRET_KEY"),
		UseTLS:    false,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := NewMinIOStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewMinIOStore() error = %v", err)
	}
	return store
}

func requiredObjectStoreEnv(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		t.Fatalf("%s is required for MinIO integration tests", key)
	}
	return value
}

func mustCiphertextRef(t *testing.T, userID, backupID uuid.UUID, seed string) CiphertextObjectRef {
	t.Helper()
	objectID := sha256.Sum256([]byte(seed + userID.String() + backupID.String()))
	ref, err := NewCiphertextObjectRef(userID, backupID, stringHex(objectID[:]))
	if err != nil {
		t.Fatalf("NewCiphertextObjectRef() error = %v", err)
	}
	return ref
}

func stringHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, item := range value {
		encoded[index*2] = alphabet[item>>4]
		encoded[index*2+1] = alphabet[item&0x0f]
	}
	return string(encoded)
}
