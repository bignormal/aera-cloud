package secure

import (
	"strings"
	"testing"
)

func TestPasswordHasherHashesAndVerifiesWithoutEmbeddingPassword(t *testing.T) {
	hasher := newTestPasswordHasher(t, 2)
	encoded, version, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if version != 2 {
		t.Fatalf("version = %d, want 2", version)
	}
	if strings.Contains(encoded, "correct horse battery staple") {
		t.Fatal("encoded hash contains plaintext password")
	}

	ok, rehash, err := hasher.Verify("correct horse battery staple", encoded)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok || rehash {
		t.Fatalf("Verify() = ok:%v rehash:%v, want true false", ok, rehash)
	}

	ok, rehash, err = hasher.Verify("wrong password value", encoded)
	if err != nil {
		t.Fatalf("Verify(wrong) error = %v", err)
	}
	if ok || rehash {
		t.Fatalf("Verify(wrong) = ok:%v rehash:%v, want false false", ok, rehash)
	}
}

func TestPasswordHasherUsesRandomSalt(t *testing.T) {
	hasher := newTestPasswordHasher(t, 2)
	first, _, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("first Hash() error = %v", err)
	}
	second, _, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("second Hash() error = %v", err)
	}
	if first == second {
		t.Fatal("two hashes reused the same salt")
	}
}

func TestPasswordHasherEnforcesRuneLengthWithoutNormalizing(t *testing.T) {
	hasher := newTestPasswordHasher(t, 2)
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "nine runes", value: "123456789", wantErr: true},
		{name: "ten unicode runes", value: "密码密码密码密码密码", wantErr: false},
		{name: "128 runes", value: strings.Repeat("a", 128), wantErr: false},
		{name: "129 runes", value: strings.Repeat("a", 129), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := hasher.Hash(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Hash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordHasherSignalsParameterVersionUpgrade(t *testing.T) {
	oldHasher := newTestPasswordHasher(t, 1)
	encoded, _, err := oldHasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("old Hash() error = %v", err)
	}

	currentHasher := newTestPasswordHasher(t, 2)
	ok, rehash, err := currentHasher.Verify("correct horse battery staple", encoded)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok || !rehash {
		t.Fatalf("Verify() = ok:%v rehash:%v, want true true", ok, rehash)
	}
}

func TestPasswordHasherRejectsMalformedOrUnregisteredHashes(t *testing.T) {
	hasher := newTestPasswordHasher(t, 2)
	values := []string{
		"not-a-password-hash",
		"$agentera$99$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA",
		"$agentera$2$argon2id$v=19$m=999999999,t=9,p=9$c2FsdA$aGFzaA",
	}
	for _, value := range values {
		if _, _, err := hasher.Verify("correct horse battery staple", value); err == nil {
			t.Errorf("Verify() accepted malformed hash %q", value)
		}
	}
}

func TestDefaultPasswordHasherUsesProductionStrength(t *testing.T) {
	hasher, err := DefaultPasswordHasher()
	if err != nil {
		t.Fatalf("DefaultPasswordHasher() error = %v", err)
	}
	params := hasher.Params(hasher.CurrentVersion())
	if params.MemoryKiB < 64*1024 || params.Iterations < 3 || params.SaltLength < 16 || params.KeyLength < 32 {
		t.Fatalf("default params are too weak: %+v", params)
	}
}

func newTestPasswordHasher(t *testing.T, currentVersion int) *PasswordHasher {
	t.Helper()
	hasher, err := NewPasswordHasher(PasswordHasherConfig{
		CurrentVersion: currentVersion,
		Versions: map[int]Argon2Params{
			1: {MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
			2: {MemoryKiB: 128, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		},
	})
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v", err)
	}
	return hasher
}
