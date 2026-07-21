package agentcontrol

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const AgentPublicationDLPVersion = "agent-publication-dlp-v1"

type PublicationTextAsset struct {
	Path    string
	Content string
}

type publicationDLPRule struct {
	code    string
	pattern *regexp.Regexp
}

var publicationDLPRules = []publicationDLPRule{
	{code: "credential_private_key", pattern: regexp.MustCompile(`(?i)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)},
	{code: "credential_bearer_token", pattern: regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]{20,}`)},
	{code: "credential_jwt", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b`)},
	{code: "credential_url", pattern: regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@[^/\s]+`)},
	{code: "credential_api_key", pattern: regexp.MustCompile(`(?i)\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16})\b`)},
	{code: "credential_environment_secret", pattern: regexp.MustCompile(`(?i)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_PASS|_CREDENTIALS?)[ \t]*=[ \t]*["']?[^"'\s#]{8,}`)},
	{code: "private_absolute_path", pattern: regexp.MustCompile(`(?:^|[\s"'(])/(?:Users|home|var/folders|private/var/folders)/[^\s"'<>]+`)},
	{code: "private_absolute_path", pattern: regexp.MustCompile(`(?i)\b[A-Z]:\\(?:Users|Documents and Settings|ProgramData)\\[^\r\n"'<>]+`)},
	{code: "private_absolute_path", pattern: regexp.MustCompile(`(?i)(?:HERMES_HOME|userData|\.hermes[/\\]profiles)[ \t]*[:=][ \t]*\S+`)},
	{code: "private_memory_payload", pattern: regexp.MustCompile(`(?i)^[ \t]*#{1,6}[ \t]+MEMORY(?:\.md)?[ \t]*$`)},
	{code: "private_user_payload", pattern: regexp.MustCompile(`(?i)^[ \t]*#{1,6}[ \t]+USER(?:\.md)?[ \t]*$`)},
	{code: "private_session_payload", pattern: regexp.MustCompile(`(?i)"session_id"[ \t]*:.*"messages"[ \t]*:`)},
	{code: "private_conversation_payload", pattern: regexp.MustCompile(`(?i)"conversation_id"[ \t]*:.*"messages"[ \t]*:`)},
	{code: "private_credential_store_payload", pattern: regexp.MustCompile(`(?i)"credential_store"[ \t]*:`)},
	{code: "private_curator_payload", pattern: regexp.MustCompile(`(?i)"curator_state"[ \t]*:`)},
}

func ScanAgentPublication(assets []PublicationTextAsset) []ExperienceCandidateFinding {
	return scanTextAssets(AgentPublicationDLPVersion, assets)
}

func scanTextAssets(_ string, assets []PublicationTextAsset) []ExperienceCandidateFinding {
	findings := make([]ExperienceCandidateFinding, 0)
	seen := make(map[string]struct{})
	for _, asset := range assets {
		for index, rawLine := range strings.Split(asset.Content, "\n") {
			line := strings.TrimSuffix(rawLine, "\r")
			for _, rule := range publicationDLPRules {
				if !rule.pattern.MatchString(line) {
					continue
				}
				finding := ExperienceCandidateFinding{Code: rule.code, Path: asset.Path, Line: index + 1}
				key := finding.Code + "\x00" + finding.Path + "\x00" + strconv.Itoa(finding.Line)
				if _, duplicate := seen[key]; duplicate {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, finding)
			}
		}
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Code != findings[right].Code {
			return findings[left].Code < findings[right].Code
		}
		if findings[left].Path != findings[right].Path {
			return findings[left].Path < findings[right].Path
		}
		return findings[left].Line < findings[right].Line
	})
	return findings
}
