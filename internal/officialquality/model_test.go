package officialquality

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPublicEnvelopeSigningBytesExcludeSignatureAndAreDeterministic(t *testing.T) {
	eventID := mustUUIDV7(t)
	signature := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 64))
	envelope, err := DecodePublicEnvelope(
		[]byte(validPublicEnvelopeJSON(eventID, signature)),
		time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("DecodePublicEnvelope() error = %v", err)
	}
	first, err := envelope.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes() error = %v", err)
	}
	second, err := envelope.SigningBytes()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("SigningBytes() is not deterministic: %v", err)
	}
	if bytes.Contains(first, envelope.DeviceSignature) || bytes.Contains(first, []byte("device_signature")) {
		t.Fatal("SigningBytes() contains the device signature")
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	proof := ed25519.Sign(private, first)
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), second, proof) {
		t.Fatal("deterministic signing bytes did not verify")
	}
}

func TestDecodePublicEnvelopeAcceptsOnlyCanonicalMinimizedContract(t *testing.T) {
	eventID := mustUUIDV7(t)
	signature := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 64))
	raw := validPublicEnvelopeJSON(eventID, signature)

	envelope, err := DecodePublicEnvelope([]byte(raw), time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("DecodePublicEnvelope() error = %v", err)
	}
	if envelope.ProtocolVersion != 1 || envelope.ConsentVersion != 3 || envelope.EventID != eventID {
		t.Fatalf("decoded envelope identity = %+v", envelope)
	}
	if envelope.EventDay != "2026-07-23" || envelope.Kind != EventKindMetric || envelope.Result != ResultSuccess {
		t.Fatalf("decoded envelope dimensions = %+v", envelope)
	}
	if len(envelope.DeviceSignature) != 64 || envelope.BindingProof == uuid.Nil {
		t.Fatalf("decoded proof/signature = %s/%d", envelope.BindingProof, len(envelope.DeviceSignature))
	}
	if len(envelope.FeedbackReasonCodes) != 0 || envelope.FeedbackRating != "" || envelope.CrashCode != "" {
		t.Fatalf("metric optional fields = %+v", envelope)
	}
}

func TestDecodePublicEnvelopeRejectsUnknownForbiddenAndOversizeFields(t *testing.T) {
	eventID := mustUUIDV7(t)
	signature := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5b}, 64))
	base := validPublicEnvelopeJSON(eventID, signature)

	for _, field := range []string{
		"prompt", "response", "error", "user_id", "device_id", "installation_id",
		"profile_id", "session_id", "conversation_id", "runtime_binding_id", "ip_address",
		"user_agent", "request_body", "unknown_field",
	} {
		t.Run(field, func(t *testing.T) {
			raw := strings.TrimSuffix(base, "}") + fmt.Sprintf(",%q:%q}", field, "private-canary")
			if _, err := DecodePublicEnvelope([]byte(raw), time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)); err == nil {
				t.Fatalf("DecodePublicEnvelope() accepted forbidden field %q", field)
			}
		})
	}

	duplicate := strings.Replace(base, `"protocol_version":1`, `"protocol_version":1,"protocol_version":1`, 1)
	if _, err := DecodePublicEnvelope([]byte(duplicate), time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("DecodePublicEnvelope() accepted duplicate field")
	}

	oversize := strings.Replace(base, `"desktop_version":"1.2.3"`, `"desktop_version":"`+strings.Repeat("x", 129)+`"`, 1)
	if _, err := DecodePublicEnvelope([]byte(oversize), time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("DecodePublicEnvelope() accepted oversized version")
	}
}

func TestDecodePublicEnvelopeRejectsEveryMissingContractField(t *testing.T) {
	base := validPublicEnvelopeJSON(mustUUIDV7(t), base64Signature(0x5d))
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &fields); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	for missing := range fields {
		t.Run(missing, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(fields)-1)
			for key, value := range fields {
				if key != missing {
					copy[key] = value
				}
			}
			raw, err := json.Marshal(copy)
			if err != nil {
				t.Fatalf("encode fixture: %v", err)
			}
			if _, err := DecodePublicEnvelope(raw, now); err == nil {
				t.Fatalf("DecodePublicEnvelope() accepted missing field %q", missing)
			}
		})
	}
}

func TestDecodePublicEnvelopePinsEnumsVariantsAndAcceptedDayWindow(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	eventID := mustUUIDV7(t)
	signature := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5c}, 64))
	base := validPublicEnvelopeJSON(eventID, signature)

	mutations := map[string]string{
		"uuid v4":          strings.Replace(base, eventID.String(), uuid.New().String(), 1),
		"future day":       strings.Replace(base, "2026-07-23", "2026-07-24", 1),
		"expired day":      strings.Replace(base, "2026-07-23", "2026-06-22", 1),
		"unknown result":   strings.Replace(base, `"result":"success"`, `"result":"maybe"`, 1),
		"unknown latency":  strings.Replace(base, `"latency_bucket":"lt_1s"`, `"latency_bucket":"fast"`, 1),
		"unknown tokens":   strings.Replace(base, `"total_token_bucket":"0"`, `"total_token_bucket":"many"`, 1),
		"metric rating":    strings.Replace(base, `"feedback_rating":null`, `"feedback_rating":"helpful"`, 1),
		"metric reason":    strings.Replace(base, `"feedback_reason_codes":[]`, `"feedback_reason_codes":["incorrect"]`, 1),
		"success crash":    strings.Replace(base, `"crash_code":null`, `"crash_code":"runtime_process_exit"`, 1),
		"unknown reason":   strings.Replace(base, `"feedback_reason_codes":[]`, `"feedback_reason_codes":["write_a_note"]`, 1),
		"padded signature": strings.Replace(base, signature, signature+"=", 1),
	}
	for name, raw := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePublicEnvelope([]byte(raw), now); err == nil {
				t.Fatalf("DecodePublicEnvelope() accepted invalid %s", name)
			}
		})
	}

	explicit := strings.NewReplacer(
		`"kind":"metric"`, `"kind":"explicit_feedback"`,
		`"feedback_rating":null`, `"feedback_rating":"not_helpful"`,
		`"feedback_reason_codes":[]`, `"feedback_reason_codes":["incorrect","too_slow"]`,
	).Replace(base)
	if _, err := DecodePublicEnvelope([]byte(explicit), now); err != nil {
		t.Fatalf("DecodePublicEnvelope() rejected explicit feedback: %v", err)
	}

	runtimeCrash := strings.NewReplacer(
		`"result":"success"`, `"result":"runtime_crash"`,
		`"crash_code":null`, `"crash_code":"unclassified_runtime_failure"`,
	).Replace(base)
	if _, err := DecodePublicEnvelope([]byte(runtimeCrash), now); err != nil {
		t.Fatalf("DecodePublicEnvelope() rejected runtime crash: %v", err)
	}
}

func validPublicEnvelopeJSON(eventID uuid.UUID, signature string) string {
	return fmt.Sprintf(`{
		"protocol_version":1,
		"consent_version":3,
		"event_id":%q,
		"platform_id":"11111111-1111-4111-8111-111111111111",
		"definition_id":"22222222-2222-4222-8222-222222222222",
		"version_id":"33333333-3333-4333-8333-333333333333",
		"release_id":"44444444-4444-4444-8444-444444444444",
		"release_revision_id":"55555555-5555-4555-8555-555555555555",
		"desktop_version":"1.2.3",
		"runtime_version":"2.3.4",
		"event_day":"2026-07-23",
		"kind":"metric",
		"result":"success",
		"latency_bucket":"lt_1s",
		"total_token_bucket":"0",
		"crash_code":null,
		"feedback_rating":null,
		"feedback_reason_codes":[],
		"binding_proof":"66666666-6666-4666-8666-666666666666",
		"device_signature":%q
	}`, eventID.String(), signature)
}

func mustUUIDV7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return value
}
