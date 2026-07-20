package agentcontrol

import (
	"crypto/sha256"
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"
)

const (
	ExperienceCandidateSchemaVersion = 1
	ExperienceCandidateDLPVersion    = "experience-candidate-dlp-v1"
	MaxExperienceCandidateFiles      = 32
	MaxExperienceCandidateFileBytes  = 256 * 1024
	MaxExperienceCandidateBytes      = 1024 * 1024
	maxExperienceCandidatePathBytes  = 512
)

var (
	ErrInvalidExperienceCandidate = errors.New("ExperienceCandidate content is invalid")
	experienceSkillNamePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,98}[a-z0-9])?$`)
)

type ExperienceCandidateAssetV1 struct {
	Path      string    `json:"path"`
	MediaType MediaType `json:"media_type"`
	Content   string    `json:"content"`
}

type ExperienceCandidateBundleV1 struct {
	SchemaVersion int                          `json:"schema_version"`
	SkillName     string                       `json:"skill_name"`
	Assets        []ExperienceCandidateAssetV1 `json:"assets"`
}

type CanonicalExperienceCandidate struct {
	Bundle        ExperienceCandidateBundleV1
	CanonicalJSON []byte
	ContentDigest [sha256.Size]byte
}

type ExperienceCandidateFinding struct {
	Code string `json:"code"`
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
}

type ExperienceCandidateDecision string

const (
	ExperienceCandidateApproved ExperienceCandidateDecision = "APPROVED"
	ExperienceCandidateRejected ExperienceCandidateDecision = "REJECTED"
)

type ExperienceCandidateReview struct {
	ID               uuid.UUID
	ReviewedByUserID *uuid.UUID
	Decision         ExperienceCandidateDecision
	ReasonCode       string
	SafeNote         string
	ReviewedAt       time.Time
}

type ExperienceCandidate struct {
	ID                    uuid.UUID
	WorkspaceID           uuid.UUID
	AgentDefinitionID     uuid.UUID
	SourceAgentVersionID  uuid.UUID
	SubmittedByUserID     *uuid.UUID
	SubmittedFromDeviceID *uuid.UUID
	SkillName             string
	DLPContractVersion    string
	ContentDigest         [sha256.Size]byte
	Bundle                ExperienceCandidateBundleV1
	CreatedAt             time.Time
	Review                *ExperienceCandidateReview
}

func CanonicalizeExperienceCandidate(input ExperienceCandidateBundleV1) (CanonicalExperienceCandidate, error) {
	if input.SchemaVersion != ExperienceCandidateSchemaVersion || !validExperienceSkillName(input.SkillName) {
		return CanonicalExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	assets, total, err := normalizeExperienceCandidateAssets(input.SkillName, input.Assets)
	if err != nil || total > MaxExperienceCandidateBytes {
		return CanonicalExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	bundle := ExperienceCandidateBundleV1{
		SchemaVersion: ExperienceCandidateSchemaVersion,
		SkillName:     input.SkillName,
		Assets:        assets,
	}
	raw, err := marshalCanonical(bundle)
	if err != nil {
		return CanonicalExperienceCandidate{}, ErrInvalidExperienceCandidate
	}
	return CanonicalExperienceCandidate{
		Bundle: bundle, CanonicalJSON: raw, ContentDigest: sha256.Sum256(raw),
	}, nil
}

func validExperienceSkillName(value string) bool {
	return utf8.ValidString(value) && experienceSkillNamePattern.MatchString(value)
}

func normalizeExperienceCandidateAssets(
	skillName string,
	input []ExperienceCandidateAssetV1,
) ([]ExperienceCandidateAssetV1, int, error) {
	if len(input) == 0 || len(input) > MaxExperienceCandidateFiles {
		return nil, 0, ErrInvalidExperienceCandidate
	}
	prefix := "skills/" + skillName + "/"
	requiredSkillPath := prefix + "SKILL.md"
	assets := make([]ExperienceCandidateAssetV1, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	total := 0
	hasSkill := false
	for _, asset := range input {
		normalizedPath, err := normalizeExperienceCandidatePath(asset.Path)
		if err != nil || !strings.HasPrefix(normalizedPath, prefix) || normalizedPath == prefix {
			return nil, 0, ErrInvalidExperienceCandidate
		}
		if _, duplicate := seen[normalizedPath]; duplicate {
			return nil, 0, ErrInvalidExperienceCandidate
		}
		if !validExperienceCandidateMediaType(normalizedPath, asset.MediaType) ||
			!utf8.ValidString(asset.Content) || strings.ContainsRune(asset.Content, '\x00') {
			return nil, 0, ErrInvalidExperienceCandidate
		}
		contentBytes := len([]byte(asset.Content))
		if contentBytes > MaxExperienceCandidateFileBytes {
			return nil, 0, ErrInvalidExperienceCandidate
		}
		total += contentBytes
		if total > MaxExperienceCandidateBytes {
			return nil, 0, ErrInvalidExperienceCandidate
		}
		seen[normalizedPath] = struct{}{}
		hasSkill = hasSkill || normalizedPath == requiredSkillPath
		assets = append(assets, ExperienceCandidateAssetV1{
			Path: normalizedPath, MediaType: asset.MediaType, Content: asset.Content,
		})
	}
	if !hasSkill {
		return nil, 0, ErrInvalidExperienceCandidate
	}
	sort.Slice(assets, func(left, right int) bool { return assets[left].Path < assets[right].Path })
	return assets, total, nil
}

func normalizeExperienceCandidatePath(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) ||
		strings.ContainsRune(value, '\x00') || strings.Contains(value, `\`) ||
		strings.Contains(value, "://") || strings.HasPrefix(value, "/") ||
		(len(value) >= 2 && value[1] == ':') {
		return "", ErrInvalidExperienceCandidate
	}
	normalized := norm.NFC.String(value)
	if len([]byte(normalized)) > maxExperienceCandidatePathBytes || path.Clean(normalized) != normalized || normalized == "." {
		return "", ErrInvalidExperienceCandidate
	}
	segments := strings.Split(normalized, "/")
	for _, segment := range segments {
		lower := strings.ToLower(segment)
		if segment == "" || segment == "." || segment == ".." || strings.HasPrefix(segment, ".") ||
			forbiddenExperienceCandidateSegment(lower) || forbiddenExperienceCandidateExtension(lower) {
			return "", ErrInvalidExperienceCandidate
		}
	}
	return normalized, nil
}

func forbiddenExperienceCandidateSegment(value string) bool {
	switch value {
	case "node_modules", "vendor", "__pycache__", "__pypackages__", "venv", "virtualenv", "site-packages",
		"target", "dist", "build", "coverage", "auth.json", "memory.md", "user.md", "credentials",
		"credential-store", "sessions", "conversation", "conversations", "curator", "archives":
		return true
	default:
		return false
	}
}

func forbiddenExperienceCandidateExtension(value string) bool {
	switch path.Ext(value) {
	case ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".dmg", ".pkg",
		".exe", ".dll", ".so", ".dylib", ".bin", ".wasm", ".class", ".jar", ".pyc",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".mp3", ".mp4", ".mov":
		return true
	default:
		return false
	}
}

func validExperienceCandidateMediaType(candidatePath string, mediaType MediaType) bool {
	if strings.EqualFold(path.Ext(candidatePath), ".md") {
		return mediaType == MediaTypeTextMarkdown
	}
	return mediaType == MediaTypeTextPlain
}
