package abuse

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const captchaResponseLimit = 64 * 1024

type HTTPChallengeConfig struct {
	Endpoint                  string
	Secret                    string
	Client                    *http.Client
	AllowInsecureLoopbackHTTP bool
}

type HTTPChallengeVerifier struct {
	endpoint string
	secret   string
	client   *http.Client
}

func NewHTTPChallengeVerifier(config HTTPChallengeConfig) (*HTTPChallengeVerifier, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, errors.New("CAPTCHA endpoint is invalid")
	}
	if endpoint.Scheme != "https" {
		if endpoint.Scheme != "http" || !config.AllowInsecureLoopbackHTTP || !isLoopback(endpoint.Hostname()) {
			return nil, errors.New("CAPTCHA endpoint must use HTTPS")
		}
	}
	if strings.TrimSpace(config.Secret) == "" {
		return nil, errors.New("CAPTCHA provider secret is required")
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	clientWithoutRedirects := *client
	clientWithoutRedirects.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HTTPChallengeVerifier{endpoint: endpoint.String(), secret: config.Secret, client: &clientWithoutRedirects}, nil
}

func (v *HTTPChallengeVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if v == nil || strings.TrimSpace(token) == "" || len(token) > 4096 || len(remoteIP) > 128 {
		return false, errors.New("CAPTCHA proof is invalid")
	}
	form := url.Values{
		"secret":   []string{v.secret},
		"response": []string{token},
	}
	if strings.TrimSpace(remoteIP) != "" {
		form.Set("remoteip", remoteIP)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, errors.New("CAPTCHA request could not be prepared")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := v.client.Do(request)
	if err != nil {
		return false, errors.New("CAPTCHA provider is unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, captchaResponseLimit))
		return false, errors.New("CAPTCHA provider is unavailable")
	}
	var result struct {
		Success bool `json:"success"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, captchaResponseLimit))
	if err := decoder.Decode(&result); err != nil {
		return false, errors.New("CAPTCHA provider returned an invalid response")
	}
	return result.Success, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
