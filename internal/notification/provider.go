package notification

import (
	"context"
	"errors"
	"strings"

	"github.com/bignormal/aera-cloud/internal/verification"
)

type Provider interface {
	SendVerification(ctx context.Context, destination, code string, purpose verification.Purpose) error
}

type Router struct {
	email Provider
	sms   Provider
}

func NewRouter(email, sms Provider) (*Router, error) {
	if email == nil && sms == nil {
		return nil, errors.New("notification providers are unavailable")
	}
	return &Router{email: email, sms: sms}, nil
}

func (r *Router) SendVerification(ctx context.Context, destination, code string, purpose verification.Purpose) error {
	switch {
	case strings.Contains(destination, "@"):
		if r == nil || r.email == nil {
			return errors.New("email verification delivery is unavailable")
		}
		return r.email.SendVerification(ctx, destination, code, purpose)
	case strings.HasPrefix(destination, "+86"):
		if r == nil || r.sms == nil {
			return errors.New("SMS verification delivery is unavailable")
		}
		return r.sms.SendVerification(ctx, destination, code, purpose)
	default:
		return errors.New("notification destination is unsupported")
	}
}

func validVerificationCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validPurpose(purpose verification.Purpose) bool {
	switch purpose {
	case verification.PurposeRegistration,
		verification.PurposeLogin,
		verification.PurposePasswordReset,
		verification.PurposeBindIdentity,
		verification.PurposeAccountDeletion,
		verification.PurposeDeletionRecovery:
		return true
	default:
		return false
	}
}
