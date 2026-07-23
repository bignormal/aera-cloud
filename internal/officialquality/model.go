package officialquality

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	ProtocolVersion       = 1
	maximumVersionLength  = 128
	maximumEventAgeInDays = 30
	eventSignatureDomain  = "official-quality-event-v1"

	EventKindMetric           = "metric"
	EventKindExplicitFeedback = "explicit_feedback"

	ResultSuccess       = "success"
	ResultUserCancelled = "user_cancelled"
	ResultModelError    = "model_error"
	ResultToolError     = "tool_error"
	ResultRuntimeCrash  = "runtime_crash"
	ResultTimeout       = "timeout"

	PurposeMetrics          = "official_quality_metrics"
	PurposeExplicitFeedback = "official_explicit_feedback"
)

var ErrInvalidRequest = errors.New("official quality request is invalid")

var (
	publicEnvelopeFields = []string{
		"protocol_version", "consent_version", "event_id", "platform_id", "definition_id",
		"version_id", "release_id", "release_revision_id", "desktop_version", "runtime_version",
		"event_day", "kind", "result", "latency_bucket", "total_token_bucket", "crash_code",
		"feedback_rating", "feedback_reason_codes", "binding_proof", "device_signature",
	}
	allowedResults = []string{
		ResultSuccess, ResultUserCancelled, ResultModelError,
		ResultToolError, ResultRuntimeCrash, ResultTimeout,
	}
	allowedLatencyBuckets = []string{
		"lt_1s", "1s_5s", "5s_15s", "15s_60s", "60s_180s", "gte_180s",
	}
	allowedTokenBuckets = []string{
		"0", "1_1k", "1k_4k", "4k_16k", "16k_64k", "gte_64k",
	}
	allowedCrashCodes = []string{
		"gateway_unavailable", "runtime_process_exit",
		"runtime_protocol_failure", "unclassified_runtime_failure",
	}
	allowedRatings     = []string{"helpful", "not_helpful"}
	allowedReasonCodes = []string{
		"incorrect", "incomplete", "tool_failed", "too_slow",
		"unsafe_or_inappropriate", "other_without_text",
	}
)

type PublicEnvelope struct {
	ProtocolVersion     int
	ConsentVersion      int64
	EventID             uuid.UUID
	PlatformID          uuid.UUID
	DefinitionID        uuid.UUID
	VersionID           uuid.UUID
	ReleaseID           uuid.UUID
	ReleaseRevisionID   uuid.UUID
	DesktopVersion      string
	RuntimeVersion      string
	EventDay            string
	Kind                string
	Result              string
	LatencyBucket       string
	TotalTokenBucket    string
	CrashCode           string
	FeedbackRating      string
	FeedbackReasonCodes []string
	BindingProof        uuid.UUID
	DeviceSignature     []byte
}

type publicEnvelopeJSON struct {
	ProtocolVersion     int      `json:"protocol_version"`
	ConsentVersion      int64    `json:"consent_version"`
	EventID             string   `json:"event_id"`
	PlatformID          string   `json:"platform_id"`
	DefinitionID        string   `json:"definition_id"`
	VersionID           string   `json:"version_id"`
	ReleaseID           string   `json:"release_id"`
	ReleaseRevisionID   string   `json:"release_revision_id"`
	DesktopVersion      string   `json:"desktop_version"`
	RuntimeVersion      string   `json:"runtime_version"`
	EventDay            string   `json:"event_day"`
	Kind                string   `json:"kind"`
	Result              string   `json:"result"`
	LatencyBucket       string   `json:"latency_bucket"`
	TotalTokenBucket    string   `json:"total_token_bucket"`
	CrashCode           *string  `json:"crash_code"`
	FeedbackRating      *string  `json:"feedback_rating"`
	FeedbackReasonCodes []string `json:"feedback_reason_codes"`
	BindingProof        string   `json:"binding_proof"`
	DeviceSignature     string   `json:"device_signature"`
}

type eventSigningJSON struct {
	ProtocolVersion     int      `json:"protocol_version"`
	ConsentVersion      int64    `json:"consent_version"`
	EventID             string   `json:"event_id"`
	PlatformID          string   `json:"platform_id"`
	DefinitionID        string   `json:"definition_id"`
	VersionID           string   `json:"version_id"`
	ReleaseID           string   `json:"release_id"`
	ReleaseRevisionID   string   `json:"release_revision_id"`
	DesktopVersion      string   `json:"desktop_version"`
	RuntimeVersion      string   `json:"runtime_version"`
	EventDay            string   `json:"event_day"`
	Kind                string   `json:"kind"`
	Result              string   `json:"result"`
	LatencyBucket       string   `json:"latency_bucket"`
	TotalTokenBucket    string   `json:"total_token_bucket"`
	CrashCode           *string  `json:"crash_code"`
	FeedbackRating      *string  `json:"feedback_rating"`
	FeedbackReasonCodes []string `json:"feedback_reason_codes"`
	BindingProof        string   `json:"binding_proof"`
}

func DecodePublicEnvelope(raw []byte, now time.Time) (PublicEnvelope, error) {
	if len(raw) == 0 || !utf8.Valid(raw) || rejectDuplicateJSONKeys(raw) != nil {
		return PublicEnvelope{}, ErrInvalidRequest
	}
	var wire publicEnvelopeJSON
	if decodeStrictJSON(raw, &wire) != nil {
		return PublicEnvelope{}, ErrInvalidRequest
	}
	var present map[string]json.RawMessage
	if json.Unmarshal(raw, &present) != nil || len(present) != len(publicEnvelopeFields) {
		return PublicEnvelope{}, ErrInvalidRequest
	}
	for _, field := range publicEnvelopeFields {
		if _, ok := present[field]; !ok {
			return PublicEnvelope{}, ErrInvalidRequest
		}
	}
	value := PublicEnvelope{
		ProtocolVersion: wire.ProtocolVersion, ConsentVersion: wire.ConsentVersion,
		DesktopVersion: wire.DesktopVersion, RuntimeVersion: wire.RuntimeVersion,
		EventDay: wire.EventDay, Kind: wire.Kind, Result: wire.Result,
		LatencyBucket: wire.LatencyBucket, TotalTokenBucket: wire.TotalTokenBucket,
		FeedbackReasonCodes: slices.Clone(wire.FeedbackReasonCodes),
	}
	var ok bool
	if value.EventID, ok = canonicalUUID(wire.EventID); !ok || value.EventID.Version() != 7 || value.EventID.Variant() != uuid.RFC4122 {
		return PublicEnvelope{}, ErrInvalidRequest
	}
	identifiers := []struct {
		raw    string
		target *uuid.UUID
	}{
		{wire.PlatformID, &value.PlatformID}, {wire.DefinitionID, &value.DefinitionID},
		{wire.VersionID, &value.VersionID}, {wire.ReleaseID, &value.ReleaseID},
		{wire.ReleaseRevisionID, &value.ReleaseRevisionID}, {wire.BindingProof, &value.BindingProof},
	}
	for _, identifier := range identifiers {
		if *identifier.target, ok = canonicalUUID(identifier.raw); !ok {
			return PublicEnvelope{}, ErrInvalidRequest
		}
	}
	if wire.CrashCode != nil {
		value.CrashCode = *wire.CrashCode
	}
	if wire.FeedbackRating != nil {
		value.FeedbackRating = *wire.FeedbackRating
	}
	signature, err := base64.RawURLEncoding.DecodeString(wire.DeviceSignature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != wire.DeviceSignature || len(signature) != 64 {
		return PublicEnvelope{}, ErrInvalidRequest
	}
	value.DeviceSignature = signature
	if !value.valid(now) {
		return PublicEnvelope{}, ErrInvalidRequest
	}
	return value, nil
}

func (e PublicEnvelope) Purpose() string {
	if e.Kind == EventKindExplicitFeedback {
		return PurposeExplicitFeedback
	}
	return PurposeMetrics
}

func (e PublicEnvelope) SigningBytes() ([]byte, error) {
	if e.EventID == uuid.Nil || e.PlatformID == uuid.Nil || e.DefinitionID == uuid.Nil ||
		e.VersionID == uuid.Nil || e.ReleaseID == uuid.Nil || e.ReleaseRevisionID == uuid.Nil ||
		e.BindingProof == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	var crashCode *string
	if e.CrashCode != "" {
		value := e.CrashCode
		crashCode = &value
	}
	var rating *string
	if e.FeedbackRating != "" {
		value := e.FeedbackRating
		rating = &value
	}
	reasons := slices.Clone(e.FeedbackReasonCodes)
	if reasons == nil {
		reasons = []string{}
	}
	encoded, err := json.Marshal(eventSigningJSON{
		ProtocolVersion: e.ProtocolVersion, ConsentVersion: e.ConsentVersion,
		EventID: e.EventID.String(), PlatformID: e.PlatformID.String(),
		DefinitionID: e.DefinitionID.String(), VersionID: e.VersionID.String(),
		ReleaseID: e.ReleaseID.String(), ReleaseRevisionID: e.ReleaseRevisionID.String(),
		DesktopVersion: e.DesktopVersion, RuntimeVersion: e.RuntimeVersion,
		EventDay: e.EventDay, Kind: e.Kind, Result: e.Result,
		LatencyBucket: e.LatencyBucket, TotalTokenBucket: e.TotalTokenBucket,
		CrashCode: crashCode, FeedbackRating: rating, FeedbackReasonCodes: reasons,
		BindingProof: e.BindingProof.String(),
	})
	if err != nil {
		return nil, ErrInvalidRequest
	}
	return append([]byte(eventSignatureDomain+"\x00"), encoded...), nil
}

func (e PublicEnvelope) Day() time.Time {
	day, _ := time.Parse("2006-01-02", e.EventDay)
	return day
}

func (e PublicEnvelope) valid(now time.Time) bool {
	if e.ProtocolVersion != ProtocolVersion || e.ConsentVersion <= 0 || now.IsZero() ||
		!validBoundedToken(e.DesktopVersion, maximumVersionLength) ||
		!validBoundedToken(e.RuntimeVersion, maximumVersionLength) ||
		!contains(allowedResults, e.Result) || !contains(allowedLatencyBuckets, e.LatencyBucket) ||
		!contains(allowedTokenBuckets, e.TotalTokenBucket) {
		return false
	}
	day, err := time.Parse("2006-01-02", e.EventDay)
	if err != nil || day.Format("2006-01-02") != e.EventDay {
		return false
	}
	today := now.UTC().Truncate(24 * time.Hour)
	if day.After(today) || day.Before(today.AddDate(0, 0, -maximumEventAgeInDays)) {
		return false
	}
	if e.Result == ResultRuntimeCrash {
		if !contains(allowedCrashCodes, e.CrashCode) {
			return false
		}
	} else if e.CrashCode != "" {
		return false
	}
	switch e.Kind {
	case EventKindMetric:
		return e.FeedbackRating == "" && len(e.FeedbackReasonCodes) == 0
	case EventKindExplicitFeedback:
		if !contains(allowedRatings, e.FeedbackRating) || len(e.FeedbackReasonCodes) > len(allowedReasonCodes) {
			return false
		}
		seen := make(map[string]struct{}, len(e.FeedbackReasonCodes))
		for _, reason := range e.FeedbackReasonCodes {
			if !contains(allowedReasonCodes, reason) {
				return false
			}
			if _, duplicate := seen[reason]; duplicate {
				return false
			}
			seen[reason] = struct{}{}
		}
		return true
	default:
		return false
	}
}

func validBoundedToken(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) &&
		utf8.RuneCountInString(value) <= maximum && strings.IndexFunc(value, unicode.IsControl) < 0
}

func contains(values []string, target string) bool {
	return slices.Contains(values, target)
}

func canonicalUUID(raw string) (uuid.UUID, bool) {
	identifier, err := uuid.Parse(raw)
	return identifier, err == nil && identifier != uuid.Nil && identifier.String() == raw
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil || closing != matchingDelimiter(delimiter) {
		return errors.New("JSON container is not closed")
	}
	return nil
}

func matchingDelimiter(open json.Delim) json.Delim {
	if open == '{' {
		return '}'
	}
	return ']'
}
