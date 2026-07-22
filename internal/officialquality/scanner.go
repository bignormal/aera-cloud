package officialquality

import "regexp"

var officialQualityDLPRules = []*regexp.Regexp{
	regexp.MustCompile(`(?i)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]{20,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b`),
	regexp.MustCompile(`(?i)\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16})\b`),
	regexp.MustCompile(`(?:^|[\s"'(])/(?:Users|home|var/folders|private/var/folders)/[^\s"'<>]+`),
	regexp.MustCompile(`(?i)\b[A-Z]:\\(?:Users|Documents and Settings|ProgramData)\\[^\r\n"'<>]+`),
	regexp.MustCompile(`(?i)"(?:prompt|response|error|message|messages|user_id|account_id|device_id|installation_id|profile_id|session_id|conversation_id|runtime_binding_id|ip_address|user_agent|request_body|memory|skill|curator|attachment|file_path)"[ \t]*:`),
	regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>]+`),
	regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`),
}

type MinimizedScanner struct{}

func (MinimizedScanner) Scan(raw []byte) error {
	if len(raw) == 0 || len(raw) > maximumEventRequestBytes {
		return ErrDLPRejected
	}
	for _, rule := range officialQualityDLPRules {
		if rule.Match(raw) {
			return ErrDLPRejected
		}
	}
	return nil
}
