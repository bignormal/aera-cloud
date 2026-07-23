package encryptedbackup

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPublicEnvelopeSignatureIsCanonicalAndRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	envelope := testPublicEnvelope()
	signature := ed25519.Sign(privateKey, PublicEnvelopeSigningDigest(envelope))

	if err := VerifyPublicEnvelopeSignature(publicKey, envelope, signature); err != nil {
		t.Fatalf("VerifyPublicEnvelopeSignature() error = %v", err)
	}
	copied := envelope
	copied.Chunks = append([]ChunkSpec(nil), envelope.Chunks...)
	if got, want := PublicEnvelopeSigningDigest(copied), PublicEnvelopeSigningDigest(envelope); string(got) != string(want) {
		t.Fatal("canonical digest changed for an equivalent envelope")
	}

	tampered := copied
	tampered.Chunks[0].CiphertextSize++
	if err := VerifyPublicEnvelopeSignature(publicKey, tampered, signature); err != ErrInvalidSignature {
		t.Fatalf("tampered signature error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestBackupDeviceRegistrationSignatureBindsRevisionAndKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	registration := BackupDeviceRegistration{
		UserID: uuid.New(), DeviceID: uuid.New(), KeyEpoch: 3, Revision: 7,
		PublicKey: testBytes(32, 0x41),
	}
	signature := ed25519.Sign(privateKey, BackupDeviceRegistrationSigningDigest(registration))
	if err := VerifyBackupDeviceRegistrationSignature(publicKey, registration, signature); err != nil {
		t.Fatalf("VerifyBackupDeviceRegistrationSignature() error = %v", err)
	}
	registration.Revision++
	if err := VerifyBackupDeviceRegistrationSignature(publicKey, registration, signature); err != ErrInvalidSignature {
		t.Fatalf("replayed revision error = %v, want %v", err, ErrInvalidSignature)
	}
}

func testPublicEnvelope() PublicEnvelope {
	manifestDigest := sha256.Sum256([]byte("manifest ciphertext"))
	chunkDigest := sha256.Sum256([]byte("chunk ciphertext"))
	return PublicEnvelope{
		FormatVersion:        BackupFormatVersion,
		CipherSuite:          BackupCipherSuite,
		BackupID:             uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		ProfileLineageID:     uuid.MustParse("10000000-0000-4000-8000-000000000002"),
		SourceDeviceID:       uuid.MustParse("10000000-0000-4000-8000-000000000003"),
		SourceInstallationID: uuid.MustParse("10000000-0000-4000-8000-000000000004"),
		SourceDefinitionID:   uuid.MustParse("10000000-0000-4000-8000-000000000005"),
		SourceVersionID:      uuid.MustParse("10000000-0000-4000-8000-000000000006"),
		BaseOwnerScope:       "USER",
		KeyEpoch:             1,
		CreatedAt:            time.Date(2026, 7, 23, 2, 3, 4, 0, time.UTC),
		Manifest: ObjectSpec{
			ObjectID:         testObjectID(0x51),
			CiphertextDigest: manifestDigest,
			CiphertextSize:   48,
		},
		Chunks: []ChunkSpec{{
			Index: 0,
			ObjectSpec: ObjectSpec{
				ObjectID:         testObjectID(0x52),
				CiphertextDigest: chunkDigest,
				CiphertextSize:   64,
			},
		}},
		TotalCiphertextSize:        64,
		RecoveryEnvelopeDigest:     sha256.Sum256([]byte("recovery envelope")),
		WrappedDataKeyDigest:       sha256.Sum256([]byte("wrapped data key")),
		SourceDeviceEnvelopeDigest: sha256.Sum256([]byte("source device envelope")),
	}
}

func testObjectID(fill byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, 64)
	for index := range result {
		result[index] = alphabet[int(fill+byte(index))%len(alphabet)]
	}
	return string(result)
}

func testBytes(length int, fill byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = fill
	}
	return result
}
