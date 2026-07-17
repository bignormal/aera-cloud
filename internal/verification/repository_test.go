package verification

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
)

func TestPostgresRepositoryPersistsAndConsumesChallengeAtomically(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE verification_challenges`); err != nil {
		t.Fatalf("truncate verification challenges: %v", err)
	}
	repository := NewPostgresRepository(postgres)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	challenge := repositoryTestChallenge(t, now, 1)
	if err := repository.SaveAfterDelivery(ctx, challenge); err != nil {
		t.Fatalf("SaveAfterDelivery() error = %v", err)
	}
	exists, err := repository.ExistsByIdempotency(ctx, challenge.IdempotencyKeyHash)
	if err != nil {
		t.Fatalf("ExistsByIdempotency() error = %v", err)
	}
	if !exists {
		t.Fatal("saved challenge is not visible by idempotency hash")
	}
	latest, found, err := repository.Latest(ctx, [][]byte{bytes.Repeat([]byte{9}, 32), challenge.TargetLookupHMAC}, challenge.Purpose)
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if !found || latest.ID != challenge.ID || !bytes.Equal(latest.CodeHMAC, challenge.CodeHMAC) {
		t.Fatalf("Latest() = found:%v ID:%s", found, latest.ID)
	}

	for attempt := 1; attempt <= 4; attempt++ {
		err := repository.Consume(ctx, challenge.TargetLookupHMAC, challenge.Purpose, bytes.Repeat([]byte{7}, 32), now)
		if !errors.Is(err, ErrCodeMismatch) {
			t.Fatalf("wrong Consume() attempt %d error = %v", attempt, err)
		}
		latest, found, err = repository.Latest(ctx, [][]byte{challenge.TargetLookupHMAC}, challenge.Purpose)
		if err != nil || !found {
			t.Fatalf("Latest() after attempt %d = found:%v error:%v", attempt, found, err)
		}
		if latest.FailedAttempts != attempt || latest.InvalidatedAt != nil {
			t.Fatalf("attempt %d state = failures:%d invalidated:%v", attempt, latest.FailedAttempts, latest.InvalidatedAt)
		}
	}
	if err := repository.Consume(ctx, challenge.TargetLookupHMAC, challenge.Purpose, challenge.CodeHMAC, now); err != nil {
		t.Fatalf("correct Consume() error = %v", err)
	}
	if err := repository.Consume(ctx, challenge.TargetLookupHMAC, challenge.Purpose, challenge.CodeHMAC, now); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("second Consume() error = %v, want ErrChallengeNotFound", err)
	}
}

func TestPostgresRepositoryInvalidatesOnFifthFailureAndRejectsExpiry(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE verification_challenges`); err != nil {
		t.Fatalf("truncate verification challenges: %v", err)
	}
	repository := NewPostgresRepository(postgres)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	challenge := repositoryTestChallenge(t, now, 2)
	if err := repository.SaveAfterDelivery(ctx, challenge); err != nil {
		t.Fatalf("SaveAfterDelivery() error = %v", err)
	}
	wrong := bytes.Repeat([]byte{8}, 32)
	for attempt := 1; attempt <= 5; attempt++ {
		if err := repository.Consume(ctx, challenge.TargetLookupHMAC, challenge.Purpose, wrong, now); !errors.Is(err, ErrCodeMismatch) {
			t.Fatalf("wrong Consume() attempt %d error = %v", attempt, err)
		}
	}
	latest, found, err := repository.Latest(ctx, [][]byte{challenge.TargetLookupHMAC}, challenge.Purpose)
	if err != nil || !found {
		t.Fatalf("Latest() after invalidation = found:%v error:%v", found, err)
	}
	if latest.FailedAttempts != 5 || latest.InvalidatedAt == nil {
		t.Fatalf("invalidated challenge state = failures:%d invalidated:%v", latest.FailedAttempts, latest.InvalidatedAt)
	}
	if err := repository.Consume(ctx, challenge.TargetLookupHMAC, challenge.Purpose, challenge.CodeHMAC, now); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("Consume() after invalidation error = %v", err)
	}

	expired := repositoryTestChallenge(t, now.Add(-10*time.Minute), 3)
	if err := repository.SaveAfterDelivery(ctx, expired); err != nil {
		t.Fatalf("SaveAfterDelivery(expired) error = %v", err)
	}
	if err := repository.Consume(ctx, expired.TargetLookupHMAC, expired.Purpose, expired.CodeHMAC, now); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("Consume(expired) error = %v", err)
	}
}

func repositoryTestChallenge(t *testing.T, createdAt time.Time, discriminator byte) Challenge {
	t.Helper()
	id, err := secure.RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID() error = %v", err)
	}
	return Challenge{
		ID:                 id,
		Purpose:            PurposeRegistration,
		IdentityKind:       secure.IdentityEmail,
		TargetLookupKeyID:  "lookup-v1",
		TargetLookupHMAC:   bytes.Repeat([]byte{discriminator}, 32),
		CodeKeyID:          "code-v1",
		CodeHMAC:           bytes.Repeat([]byte{discriminator + 10}, 32),
		IdempotencyKeyHash: bytes.Repeat([]byte{discriminator + 20}, 32),
		CreatedAt:          createdAt,
		ExpiresAt:          createdAt.Add(5 * time.Minute),
		ResendAfter:        createdAt.Add(time.Minute),
	}
}
