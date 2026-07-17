package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/verification"
)

const smsResponseLimit = 64 * 1024

type HTTPSMSConfig struct {
	Endpoint                  string
	APIKey                    string
	SenderID                  string
	Client                    *http.Client
	AllowInsecureLoopbackHTTP bool
}

type HTTPSMS struct {
	endpoint string
	apiKey   string
	senderID string
	client   *http.Client
}

func NewHTTPSMS(config HTTPSMSConfig) (*HTTPSMS, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, errors.New("SMS provider endpoint is invalid")
	}
	if endpoint.Scheme != "https" {
		if endpoint.Scheme != "http" || !config.AllowInsecureLoopbackHTTP || !notificationLoopback(endpoint.Hostname()) {
			return nil, errors.New("SMS provider endpoint must use HTTPS")
		}
	}
	if strings.TrimSpace(config.APIKey) == "" || strings.TrimSpace(config.SenderID) == "" || strings.ContainsAny(config.SenderID, "\r\n") {
		return nil, errors.New("SMS provider configuration is incomplete")
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	clientWithoutRedirects := *client
	clientWithoutRedirects.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HTTPSMS{endpoint: endpoint.String(), apiKey: config.APIKey, senderID: config.SenderID, client: &clientWithoutRedirects}, nil
}

func (s *HTTPSMS) SendVerification(
	ctx context.Context,
	destination string,
	code string,
	purpose verification.Purpose,
) error {
	if !validMainlandDestination(destination) || !validVerificationCode(code) || !validPurpose(purpose) {
		return errors.New("SMS verification delivery request is invalid")
	}
	body, err := json.Marshal(map[string]string{
		"to":        destination,
		"code":      code,
		"purpose":   string(purpose),
		"sender_id": s.senderID,
	})
	if err != nil {
		return errors.New("SMS verification request could not be prepared")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("SMS verification request could not be prepared")
	}
	request.Header.Set("Authorization", "Bearer "+s.apiKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return errors.New("SMS verification provider is unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, smsResponseLimit))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return errors.New("SMS verification provider is unavailable")
	}
	return nil
}

func validMainlandDestination(destination string) bool {
	if len(destination) != 14 || !strings.HasPrefix(destination, "+86") {
		return false
	}
	for _, character := range destination[3:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return destination[3] == '1'
}

func notificationLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
