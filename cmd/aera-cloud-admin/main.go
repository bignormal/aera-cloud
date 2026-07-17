package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const adminCommandTimeout = 30 * time.Second

type invocation struct {
	DatabaseURL string
	Operator    string
	Command     string
	TargetID    uuid.UUID
	Limit       int
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), adminCommandTimeout)
	defer cancel()
	if err := execute(
		ctx,
		os.Args[1:],
		os.Getenv("AGENTERA_CLOUD_DATABASE_URL"),
		os.Getenv("AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS"),
		os.Stdout,
	); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(
	ctx context.Context,
	args []string,
	environmentDatabaseURL string,
	recoveryEncryptionKeys string,
	output io.Writer,
) error {
	parsed, err := parseInvocation(args, environmentDatabaseURL)
	if err != nil {
		return err
	}
	postgres, err := store.OpenPostgres(ctx, parsed.DatabaseURL)
	if err != nil {
		return err
	}
	defer postgres.Close()
	commands, err := admin.NewCommands(admin.NewPostgresRepository(postgres), time.Now)
	if err != nil {
		return errors.New("restricted command could not be initialized")
	}
	switch parsed.Command {
	case "disable-account":
		err = commands.DisableAccount(ctx, parsed.Operator, parsed.TargetID)
	case "enable-account":
		err = commands.EnableAccount(ctx, parsed.Operator, parsed.TargetID)
	case "revoke-session":
		err = commands.RevokeSession(ctx, parsed.Operator, parsed.TargetID)
	case "audit":
		var events []admin.RedactedAuditEvent
		events, err = commands.Audit(ctx, parsed.Operator, parsed.TargetID, parsed.Limit)
		if err == nil {
			return json.NewEncoder(output).Encode(struct {
				Events []admin.RedactedAuditEvent `json:"events"`
			}{Events: events})
		}
	case "verify-identities":
		var keys map[string][]byte
		keys, err = parseRecoveryEncryptionKeys(recoveryEncryptionKeys)
		if err == nil {
			var count int
			count, err = verifyEncryptedIdentities(ctx, postgres, keys)
			if err == nil {
				return json.NewEncoder(output).Encode(struct {
					Status             string `json:"status"`
					IdentitiesVerified int    `json:"identities_verified"`
				}{Status: "ok", IdentitiesVerified: count})
			}
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]string{"status": "ok"})
}

func parseInvocation(args []string, environmentDatabaseURL string) (invocation, error) {
	global := flag.NewFlagSet("aera-cloud-admin", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	operator := global.String("operator", "", "explicit operator identity")
	databaseURL := global.String("database-url", environmentDatabaseURL, "PostgreSQL connection URL")
	if err := global.Parse(args); err != nil {
		return invocation{}, errors.New("restricted command arguments are invalid")
	}
	remaining := global.Args()
	if strings.TrimSpace(*operator) == "" || strings.TrimSpace(*databaseURL) == "" || len(remaining) < 1 {
		return invocation{}, errors.New("operator, database URL, and command are required")
	}
	parsed := invocation{DatabaseURL: *databaseURL, Operator: *operator, Command: remaining[0]}
	switch parsed.Command {
	case "disable-account", "enable-account":
		target, err := parseTargetFlag(parsed.Command, remaining[1:], "user-id")
		if err != nil {
			return invocation{}, err
		}
		parsed.TargetID = target
	case "revoke-session":
		target, err := parseTargetFlag(parsed.Command, remaining[1:], "session-id")
		if err != nil {
			return invocation{}, err
		}
		parsed.TargetID = target
	case "audit":
		command := flag.NewFlagSet(parsed.Command, flag.ContinueOnError)
		command.SetOutput(io.Discard)
		userID := command.String("user-id", "", "target user UUID")
		limit := command.Int("limit", 50, "maximum redacted events")
		if command.Parse(remaining[1:]) != nil || len(command.Args()) != 0 {
			return invocation{}, errors.New("audit arguments are invalid")
		}
		target, err := uuid.Parse(*userID)
		if err != nil || *limit < 1 || *limit > 200 {
			return invocation{}, errors.New("audit target or limit is invalid")
		}
		parsed.TargetID, parsed.Limit = target, *limit
	case "verify-identities":
		if len(remaining) != 1 {
			return invocation{}, errors.New("verify-identities arguments are invalid")
		}
	default:
		return invocation{}, errors.New("unsupported restricted command")
	}
	return parsed, nil
}

func parseRecoveryEncryptionKeys(raw string) (map[string][]byte, error) {
	var encoded map[string]string
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &encoded) != nil || len(encoded) == 0 {
		return nil, errors.New("identity recovery encryption key set is required")
	}
	keys := make(map[string][]byte, len(encoded))
	for keyID, value := range encoded {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if strings.TrimSpace(keyID) == "" || keyID != strings.TrimSpace(keyID) || err != nil || len(decoded) != 32 ||
			base64.StdEncoding.EncodeToString(decoded) != value {
			return nil, errors.New("identity recovery encryption key set is invalid")
		}
		keys[keyID] = append([]byte(nil), decoded...)
	}
	return keys, nil
}

func verifyEncryptedIdentities(ctx context.Context, postgres *pgxpool.Pool, keys map[string][]byte) (int, error) {
	if postgres == nil || len(keys) == 0 {
		return 0, errors.New("identity recovery verification is unavailable")
	}
	keyIDs := make([]string, 0, len(keys))
	for keyID := range keys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	codec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: keyIDs[0],
		EncryptionKeys:        keys,
		ActiveLookupKeyID:     "restore-verification-only",
		LookupKeys:            map[string][]byte{"restore-verification-only": make([]byte, 32)},
	})
	if err != nil {
		return 0, errors.New("identity recovery verification is unavailable")
	}
	rows, err := postgres.Query(ctx, `
		SELECT kind, encryption_key_id, nonce, ciphertext
		FROM identities
		ORDER BY id
	`)
	if err != nil {
		return 0, errors.New("restored identities could not be read")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var kind secure.IdentityKind
		var sealed secure.SealedIdentity
		if rows.Scan(&kind, &sealed.EncryptionKeyID, &sealed.Nonce, &sealed.Ciphertext) != nil {
			return 0, errors.New("restored identity record is malformed")
		}
		plaintext, openErr := codec.Open(kind, sealed)
		normalized, normalizeErr := secure.NormalizeIdentity(kind, plaintext)
		if openErr != nil || normalizeErr != nil || normalized != plaintext {
			return 0, errors.New("restored identity decryption verification failed")
		}
		count++
	}
	if rows.Err() != nil {
		return 0, errors.New("restored identities could not be read")
	}
	return count, nil
}

func parseTargetFlag(commandName string, args []string, flagName string) (uuid.UUID, error) {
	command := flag.NewFlagSet(commandName, flag.ContinueOnError)
	command.SetOutput(io.Discard)
	targetValue := command.String(flagName, "", "target UUID")
	if command.Parse(args) != nil || len(command.Args()) != 0 {
		return uuid.Nil, errors.New("restricted command target is invalid")
	}
	target, err := uuid.Parse(*targetValue)
	if err != nil {
		return uuid.Nil, errors.New("restricted command target is invalid")
	}
	return target, nil
}
