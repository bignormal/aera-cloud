package encryptedbackup

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const ciphertextDigestMetadataKey = "ciphertext-sha256"

type MinIOStoreConfig struct {
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	UseTLS    bool
}

type MinIOStore struct {
	client *minio.Client
	bucket string
}

func NewMinIOStore(ctx context.Context, cfg MinIOStoreConfig) (*MinIOStore, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" ||
		strings.TrimSpace(cfg.Bucket) == "" ||
		strings.TrimSpace(cfg.Region) == "" ||
		strings.TrimSpace(cfg.AccessKey) == "" ||
		strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, fmt.Errorf("%w: incomplete configuration", ErrObjectStoreUnavailable)
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseTLS,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: create client", ErrObjectStoreUnavailable)
	}
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect bucket", ErrObjectStoreUnavailable)
	}
	if !exists {
		return nil, fmt.Errorf("%w: bucket does not exist", ErrObjectStoreUnavailable)
	}
	return &MinIOStore{client: client, bucket: cfg.Bucket}, nil
}

func (store *MinIOStore) PutCiphertext(
	ctx context.Context,
	ref CiphertextObjectRef,
	body io.Reader,
	size int64,
	digest [sha256.Size]byte,
) (CiphertextMetadata, error) {
	if body == nil || size <= 0 || size > maxCiphertextObjectBytes {
		return CiphertextMetadata{}, ErrCiphertextMismatch
	}

	tracker := &digestingReader{
		reader: io.LimitReader(body, size),
		hash:   sha256.New(),
	}
	options := minio.PutObjectOptions{
		ContentType: "application/octet-stream",
		UserMetadata: map[string]string{
			ciphertextDigestMetadataKey: hex.EncodeToString(digest[:]),
		},
	}
	options.SetMatchETagExcept("*")
	key := ref.objectKey()
	upload, err := store.client.PutObject(ctx, store.bucket, key, tracker, size, options)
	if err != nil {
		if isMinIOPreconditionFailure(err) {
			return CiphertextMetadata{}, ErrCiphertextAlreadyExists
		}
		if ctx.Err() != nil {
			return CiphertextMetadata{}, fmt.Errorf("%w: %v", ErrObjectStoreUnavailable, ctx.Err())
		}
		if tracker.count != size || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			_ = store.removeCiphertext(context.Background(), ref)
			return CiphertextMetadata{}, ErrCiphertextMismatch
		}
		return CiphertextMetadata{}, fmt.Errorf("%w: put ciphertext", ErrObjectStoreUnavailable)
	}

	if upload.Size != size || tracker.count != size {
		if cleanupErr := store.removeCiphertext(context.Background(), ref); cleanupErr != nil {
			return CiphertextMetadata{}, cleanupErr
		}
		return CiphertextMetadata{}, ErrCiphertextMismatch
	}
	trailing := make([]byte, 1)
	trailingCount, trailingErr := body.Read(trailing)
	if trailingCount != 0 || (trailingErr != nil && !errors.Is(trailingErr, io.EOF)) {
		if cleanupErr := store.removeCiphertext(context.Background(), ref); cleanupErr != nil {
			return CiphertextMetadata{}, cleanupErr
		}
		return CiphertextMetadata{}, ErrCiphertextMismatch
	}
	actualDigest := tracker.sum()
	if subtle.ConstantTimeCompare(actualDigest[:], digest[:]) != 1 {
		if cleanupErr := store.removeCiphertext(context.Background(), ref); cleanupErr != nil {
			return CiphertextMetadata{}, cleanupErr
		}
		return CiphertextMetadata{}, ErrCiphertextMismatch
	}

	metadata, err := store.HeadCiphertext(ctx, ref)
	if err != nil {
		_ = store.removeCiphertext(context.Background(), ref)
		return CiphertextMetadata{}, err
	}
	if metadata.Size != size || subtle.ConstantTimeCompare(metadata.SHA256[:], digest[:]) != 1 {
		if cleanupErr := store.removeCiphertext(context.Background(), ref); cleanupErr != nil {
			return CiphertextMetadata{}, cleanupErr
		}
		return CiphertextMetadata{}, ErrCiphertextMismatch
	}
	return metadata, nil
}

func (store *MinIOStore) GetCiphertext(
	ctx context.Context,
	ref CiphertextObjectRef,
) (CiphertextDownload, error) {
	metadata, err := store.HeadCiphertext(ctx, ref)
	if err != nil {
		return CiphertextDownload{}, err
	}
	body, err := store.client.GetObject(ctx, store.bucket, ref.objectKey(), minio.GetObjectOptions{})
	if err != nil {
		return CiphertextDownload{}, mapMinIOReadError(err)
	}
	return CiphertextDownload{Body: body, Metadata: metadata}, nil
}

func (store *MinIOStore) HeadCiphertext(
	ctx context.Context,
	ref CiphertextObjectRef,
) (CiphertextMetadata, error) {
	info, err := store.client.StatObject(ctx, store.bucket, ref.objectKey(), minio.StatObjectOptions{})
	if err != nil {
		return CiphertextMetadata{}, mapMinIOReadError(err)
	}
	digestText := minioUserMetadata(info, ciphertextDigestMetadataKey)
	digestBytes, err := hex.DecodeString(digestText)
	if err != nil || len(digestBytes) != sha256.Size {
		return CiphertextMetadata{}, ErrCiphertextMismatch
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	return CiphertextMetadata{
		Key:    ref.objectKey(),
		Size:   info.Size,
		SHA256: digest,
	}, nil
}

func (store *MinIOStore) DeleteCiphertexts(
	ctx context.Context,
	refs []CiphertextObjectRef,
) error {
	for _, ref := range refs {
		if err := store.removeCiphertext(ctx, ref); err != nil {
			if errors.Is(err, ErrCiphertextNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

func (store *MinIOStore) removeCiphertext(ctx context.Context, ref CiphertextObjectRef) error {
	err := store.client.RemoveObject(ctx, store.bucket, ref.objectKey(), minio.RemoveObjectOptions{})
	if err == nil || isMinIONotFound(err) {
		return nil
	}
	return fmt.Errorf("%w: delete ciphertext", ErrObjectStoreUnavailable)
}

type digestingReader struct {
	reader io.Reader
	hash   hash.Hash
	count  int64
}

func (reader *digestingReader) Read(target []byte) (int, error) {
	count, err := reader.reader.Read(target)
	if count > 0 {
		_, _ = reader.hash.Write(target[:count])
		reader.count += int64(count)
	}
	return count, err
}

func (reader *digestingReader) sum() [sha256.Size]byte {
	var result [sha256.Size]byte
	copy(result[:], reader.hash.Sum(nil))
	return result
}

func minioUserMetadata(info minio.ObjectInfo, name string) string {
	for key, values := range info.Metadata {
		normalized := strings.TrimPrefix(strings.ToLower(key), "x-amz-meta-")
		if normalized == name && len(values) > 0 {
			return values[0]
		}
	}
	for key, value := range info.UserMetadata {
		normalized := strings.TrimPrefix(strings.ToLower(key), "x-amz-meta-")
		if normalized == name {
			return value
		}
	}
	return ""
}

func mapMinIOReadError(err error) error {
	if isMinIONotFound(err) {
		return ErrCiphertextNotFound
	}
	return fmt.Errorf("%w: read ciphertext", ErrObjectStoreUnavailable)
}

func isMinIONotFound(err error) bool {
	switch minio.ToErrorResponse(err).Code {
	case "NoSuchKey", "NoSuchObject", "NotFound", "NoSuchBucket":
		return true
	default:
		return false
	}
}

func isMinIOPreconditionFailure(err error) bool {
	return minio.ToErrorResponse(err).Code == "PreconditionFailed"
}
