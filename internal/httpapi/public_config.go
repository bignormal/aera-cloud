package httpapi

import (
	"encoding/json"
	"net/http"
)

type PublicConfig struct {
	Environment                   string   `json:"environment"`
	PublicRegistrationEnabled     bool     `json:"public_registration_enabled"`
	RegistrationMode              string   `json:"registration_mode"`
	RegistrationIdentityKinds     []string `json:"registration_identity_kinds"`
	IdentityVerificationAvailable bool     `json:"identity_verification_available"`
}

func NewPublicConfigHandler(config PublicConfig) http.Handler {
	config.RegistrationIdentityKinds = append([]string(nil), config.RegistrationIdentityKinds...)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(response).Encode(config)
	})
}
