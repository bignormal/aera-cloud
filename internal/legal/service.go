package legal

import (
	"errors"
	"regexp"
)

var (
	versionPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	ErrOutdatedAcceptance = errors.New("current legal documents must be accepted")
)

type CurrentDocuments struct {
	TermsVersion   string `json:"terms_version"`
	PrivacyVersion string `json:"privacy_version"`
}

type Service struct {
	current CurrentDocuments
}

func NewService(termsVersion, privacyVersion string) (*Service, error) {
	if !versionPattern.MatchString(termsVersion) || !versionPattern.MatchString(privacyVersion) {
		return nil, errors.New("legal document versions are invalid")
	}
	return &Service{current: CurrentDocuments{TermsVersion: termsVersion, PrivacyVersion: privacyVersion}}, nil
}

func (s *Service) Current() CurrentDocuments {
	return s.current
}

func (s *Service) Validate(termsVersion, privacyVersion string) error {
	if termsVersion != s.current.TermsVersion || privacyVersion != s.current.PrivacyVersion {
		return ErrOutdatedAcceptance
	}
	return nil
}
