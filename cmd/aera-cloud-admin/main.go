package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/google/uuid"
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
	if err := execute(ctx, os.Args[1:], os.Getenv("AGENTERA_CLOUD_DATABASE_URL"), os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string, environmentDatabaseURL string, output io.Writer) error {
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
	default:
		return invocation{}, errors.New("unsupported restricted command")
	}
	return parsed, nil
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
