package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

var (
	ErrInvalidEvent   = errors.New("audit event is invalid")
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	jwtPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}$`)
	agentMetadataKeys = map[string]struct{}{
		"tenant_id": {}, "owner_scope": {}, "owner_id": {},
		"workspace_id":        {},
		"agent_definition_id": {}, "agent_version_id": {},
		"agent_installation_id": {}, "policy_snapshot_id": {},
		"content_digest": {}, "source_owner_scope": {}, "source_workspace_id": {},
		"source_organization_id": {}, "platform_id": {},
		"official_release_id": {}, "official_release_revision_id": {},
		"product_context_scope":   {},
		"experience_candidate_id": {}, "decision": {}, "reason_code": {},
	}
	workspaceMetadataKeys = map[string]struct{}{
		"workspace_id": {}, "membership_user_id": {}, "invitation_id": {},
		"role": {}, "previous_role": {},
	}
	organizationMetadataKeys = map[string]struct{}{
		"organization_id": {}, "membership_user_id": {}, "department_id": {}, "invitation_id": {},
		"policy_snapshot_id": {}, "role": {}, "previous_role": {}, "policy_version": {},
		"revision": {}, "previous_revision": {}, "status": {}, "previous_status": {},
		"content_digest": {},
	}
)

type Event struct {
	ID             uuid.UUID
	EventType      string
	ActorUserID    *uuid.UUID
	DeviceID       *uuid.UUID
	OrganizationID *uuid.UUID
	ObjectType     string
	ObjectID       *uuid.UUID
	Outcome        Outcome
	ReasonCode     string
	RequestID      string
	IPHMAC         []byte
	Metadata       map[string]string
	OccurredAt     time.Time
}

type Recorder interface {
	Record(context.Context, Event) error
}

type Executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type PostgresRecorder struct {
	executor Executor
	clock    func() time.Time
}

func NewPostgresRecorder(postgres *pgxpool.Pool) (*PostgresRecorder, error) {
	if postgres == nil {
		return nil, errors.New("audit PostgreSQL pool is required")
	}
	return NewRecorder(postgres)
}

func NewRecorder(executor Executor) (*PostgresRecorder, error) {
	if executor == nil {
		return nil, errors.New("audit executor is required")
	}
	return &PostgresRecorder{executor: executor, clock: time.Now}, nil
}

func (r *PostgresRecorder) Record(ctx context.Context, event Event) error {
	if r == nil || r.executor == nil || !validEvent(event) {
		return ErrInvalidEvent
	}
	if event.ID == uuid.Nil {
		generated, err := uuid.NewRandom()
		if err != nil {
			return errors.New("audit event identifier could not be generated")
		}
		event.ID = generated
	}
	if event.OccurredAt.IsZero() {
		clock := r.clock
		if clock == nil {
			clock = time.Now
		}
		event.OccurredAt = clock().UTC()
	}
	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		return ErrInvalidEvent
	}

	_, err = r.executor.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, device_id, object_type, object_id,
			outcome, reason_code, request_id, ip_hmac, metadata, created_at, organization_id
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10, $11::jsonb, $12, $13)
	`,
		event.ID,
		event.EventType,
		event.ActorUserID,
		event.DeviceID,
		event.ObjectType,
		event.ObjectID,
		event.Outcome,
		event.ReasonCode,
		event.RequestID,
		nilIfEmpty(event.IPHMAC),
		string(encodedMetadata),
		event.OccurredAt.UTC(),
		event.OrganizationID,
	)
	if err != nil {
		return errors.New("audit event could not be recorded")
	}
	return nil
}

func validEvent(event Event) bool {
	if !namePattern.MatchString(event.EventType) ||
		(event.Outcome != OutcomeSuccess && event.Outcome != OutcomeFailure && event.Outcome != OutcomeDenied) ||
		(event.ReasonCode != "" && !namePattern.MatchString(event.ReasonCode)) ||
		(event.ObjectType != "" && !namePattern.MatchString(event.ObjectType)) ||
		(event.RequestID != "" && !requestPattern.MatchString(event.RequestID)) ||
		(len(event.IPHMAC) != 0 && len(event.IPHMAC) != 32) {
		return false
	}
	if event.ActorUserID != nil && *event.ActorUserID == uuid.Nil {
		return false
	}
	if event.DeviceID != nil && *event.DeviceID == uuid.Nil {
		return false
	}
	if event.OrganizationID != nil && *event.OrganizationID == uuid.Nil {
		return false
	}
	if event.ObjectID != nil && *event.ObjectID == uuid.Nil {
		return false
	}
	isOrganizationEvent := strings.HasPrefix(event.EventType, "organization_")
	if isOrganizationEvent != (event.OrganizationID != nil) {
		return false
	}
	return validMetadata(event.EventType, event.Metadata, event.OrganizationID)
}

func validMetadata(eventType string, metadata map[string]string, organizationID *uuid.UUID) bool {
	if len(metadata) == 0 {
		return true
	}
	if len(metadata) > 12 {
		return false
	}
	if strings.HasPrefix(eventType, "workspace_") {
		return validWorkspaceMetadata(metadata)
	}
	if strings.HasPrefix(eventType, "organization_") {
		return validOrganizationMetadata(metadata, organizationID)
	}
	if !strings.HasPrefix(eventType, "agent_") && !strings.HasPrefix(eventType, "runtime_binding_") {
		return false
	}
	ownerScope, hasOwnerScope := metadata["owner_scope"]
	_, hasWorkspaceID := metadata["workspace_id"]
	_, hasTenantID := metadata["tenant_id"]
	_, hasOwnerID := metadata["owner_id"]
	sourceOwnerScope, hasSourceOwnerScope := metadata["source_owner_scope"]
	_, hasSourceWorkspaceID := metadata["source_workspace_id"]
	_, hasSourceOrganizationID := metadata["source_organization_id"]
	_, hasPlatformID := metadata["platform_id"]
	_, hasOfficialReleaseID := metadata["official_release_id"]
	_, hasOfficialReleaseRevisionID := metadata["official_release_revision_id"]
	productContextScope, hasProductContextScope := metadata["product_context_scope"]
	hasOfficialProvenance := hasPlatformID || hasOfficialReleaseID || hasOfficialReleaseRevisionID || hasProductContextScope
	if hasWorkspaceID && (!hasOwnerScope || ownerScope != "WORKSPACE" || hasTenantID || hasOwnerID) {
		return false
	}
	if hasOwnerScope {
		switch ownerScope {
		case "USER":
			if hasWorkspaceID {
				return false
			}
		case "WORKSPACE":
			if !hasWorkspaceID || hasTenantID || hasOwnerID {
				return false
			}
			if eventType != "agent_definition_published" && eventType != "agent_version_published" &&
				!strings.HasPrefix(eventType, "agent_experience_candidate_") {
				return false
			}
		default:
			return false
		}
	}
	if hasSourceOwnerScope || hasSourceWorkspaceID || hasSourceOrganizationID {
		if !hasSourceOwnerScope || !hasOwnerScope || ownerScope != "USER" {
			return false
		}
		if eventType != "agent_installation_created" &&
			(eventType != "agent_installation_managed_version_selected" || sourceOwnerScope != "PLATFORM") {
			return false
		}
		switch sourceOwnerScope {
		case "USER":
			if hasSourceWorkspaceID || hasSourceOrganizationID || hasOfficialProvenance {
				return false
			}
		case "WORKSPACE":
			if !hasSourceWorkspaceID || hasSourceOrganizationID || hasOfficialProvenance {
				return false
			}
		case "ORGANIZATION":
			if hasSourceWorkspaceID || !hasSourceOrganizationID || hasOfficialProvenance {
				return false
			}
		case "PLATFORM":
			if hasSourceWorkspaceID || hasSourceOrganizationID || !hasPlatformID || !hasOfficialReleaseID ||
				!hasOfficialReleaseRevisionID || !hasProductContextScope {
				return false
			}
		default:
			return false
		}
	} else if hasOfficialProvenance {
		return false
	}
	for key, value := range metadata {
		if !namePattern.MatchString(key) {
			return false
		}
		if _, allowed := agentMetadataKeys[key]; !allowed || !safeMetadataValue(value) {
			return false
		}
		switch key {
		case "owner_scope", "source_owner_scope":
			continue
		case "product_context_scope":
			if sourceOwnerScope != "PLATFORM" ||
				(productContextScope != "USER" && productContextScope != "WORKSPACE" && productContextScope != "ORGANIZATION") {
				return false
			}
			continue
		case "decision":
			if !strings.HasPrefix(eventType, "agent_experience_candidate_") ||
				(value != "APPROVED" && value != "REJECTED") {
				return false
			}
			continue
		case "reason_code":
			if !strings.HasPrefix(eventType, "agent_experience_candidate_") || !namePattern.MatchString(value) {
				return false
			}
			continue
		case "content_digest":
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
				return false
			}
		default:
			if key == "experience_candidate_id" && !strings.HasPrefix(eventType, "agent_experience_candidate_") {
				return false
			}
			if _, err := uuid.Parse(value); err != nil {
				return false
			}
		}
	}
	return true
}

func validOrganizationMetadata(metadata map[string]string, organizationID *uuid.UUID) bool {
	if organizationID == nil || len(metadata) > len(organizationMetadataKeys) {
		return false
	}
	for key, value := range metadata {
		if !namePattern.MatchString(key) || !safeMetadataValue(value) {
			return false
		}
		if _, allowed := organizationMetadataKeys[key]; !allowed {
			return false
		}
		switch key {
		case "role", "previous_role":
			if value != "owner" && value != "admin" && value != "auditor" && value != "member" {
				return false
			}
		case "policy_version", "revision", "previous_revision":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != value {
				return false
			}
		case "status", "previous_status":
			switch value {
			case "active", "archived", "dissolved", "pending", "accepted", "revoked", "expired",
				"approved", "rejected", "withdrawn", "superseded":
			default:
				return false
			}
		case "content_digest":
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
				return false
			}
		default:
			parsed, err := uuid.Parse(value)
			if err != nil || (key == "organization_id" && parsed != *organizationID) {
				return false
			}
		}
	}
	return true
}

func validWorkspaceMetadata(metadata map[string]string) bool {
	if len(metadata) > len(workspaceMetadataKeys) {
		return false
	}
	for key, value := range metadata {
		if !namePattern.MatchString(key) || !safeMetadataValue(value) {
			return false
		}
		if _, allowed := workspaceMetadataKeys[key]; !allowed {
			return false
		}
		switch key {
		case "role", "previous_role":
			if value != "owner" && value != "admin" && value != "member" {
				return false
			}
		default:
			if _, err := uuid.Parse(value); err != nil {
				return false
			}
		}
	}
	return true
}

func safeMetadataValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	return value == trimmed && utf8.ValidString(value) && len([]byte(value)) <= 128 && value != "" &&
		!strings.ContainsAny(value, "\r\n\x00/@\\{}[]\"") && !strings.HasPrefix(lower, "bearer ") && !jwtPattern.MatchString(value)
}

func nilIfEmpty(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}
