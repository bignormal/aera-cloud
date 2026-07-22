package admin

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/secure"
)

var maskedEmailDomainPattern = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

func MaskIdentity(kind secure.IdentityKind, normalized string) (string, error) {
	canonical, err := secure.NormalizeIdentity(kind, normalized)
	if err != nil || canonical != normalized {
		return "", ErrUnavailable
	}

	switch kind {
	case secure.IdentityEmail:
		local, domain, ok := strings.Cut(normalized, "@")
		if !ok || local == "" || !maskedEmailDomainPattern.MatchString(domain) {
			return "", ErrUnavailable
		}
		first, _ := utf8.DecodeRuneInString(local)
		if first == utf8.RuneError || first == '*' || first == '@' {
			return "", ErrUnavailable
		}
		return string(first) + "***@" + domain, nil
	case secure.IdentityPhone:
		if len(normalized) != 14 || !strings.HasPrefix(normalized, "+86") {
			return "", ErrUnavailable
		}
		local := normalized[3:]
		for _, character := range local {
			if character < '0' || character > '9' {
				return "", ErrUnavailable
			}
		}
		return local[:3] + "****" + local[7:], nil
	default:
		return "", ErrUnavailable
	}
}
