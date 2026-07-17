package notification

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/verification"
)

type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	FromName    string
}

type SMTPEnvelope struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	To          string
	Message     []byte
}

type SMTPTransport interface {
	Deliver(ctx context.Context, envelope SMTPEnvelope) error
}

type SMTPEmail struct {
	config    SMTPConfig
	transport SMTPTransport
}

func NewSMTPEmail(config SMTPConfig, transport SMTPTransport) (*SMTPEmail, error) {
	if strings.TrimSpace(config.Host) == "" || strings.ContainsAny(config.Host, "\r\n") ||
		config.Port <= 0 || config.Port > 65535 || strings.TrimSpace(config.Username) == "" || config.Password == "" ||
		strings.ContainsAny(config.FromName, "\r\n") {
		return nil, errors.New("SMTP configuration is incomplete")
	}
	from, err := mail.ParseAddress(config.FromAddress)
	if err != nil || from.Address != config.FromAddress || strings.ContainsAny(config.FromAddress, "\r\n") {
		return nil, errors.New("SMTP sender address is invalid")
	}
	if transport == nil {
		transport = networkSMTPTransport{}
	}
	return &SMTPEmail{config: config, transport: transport}, nil
}

func (s *SMTPEmail) SendVerification(
	ctx context.Context,
	destination string,
	code string,
	purpose verification.Purpose,
) error {
	if strings.ContainsAny(destination, "\r\n") || !validVerificationCode(code) || !validPurpose(purpose) {
		return errors.New("email verification delivery request is invalid")
	}
	recipient, err := mail.ParseAddress(destination)
	if err != nil || recipient.Address != destination {
		return errors.New("email verification destination is invalid")
	}
	from := (&mail.Address{Name: s.config.FromName, Address: s.config.FromAddress}).String()
	message := []byte(strings.Join([]string{
		"From: " + from,
		"To: " + recipient.Address,
		"Subject: AgentEra verification code",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		"Your AgentEra verification code is " + code + ".",
		"It expires in 5 minutes. Do not share this code with anyone.",
		"",
	}, "\r\n"))
	if err := s.transport.Deliver(ctx, SMTPEnvelope{
		Host:        s.config.Host,
		Port:        s.config.Port,
		Username:    s.config.Username,
		Password:    s.config.Password,
		FromAddress: s.config.FromAddress,
		To:          recipient.Address,
		Message:     message,
	}); err != nil {
		return errors.New("email verification provider is unavailable")
	}
	return nil
}

type networkSMTPTransport struct{}

func (networkSMTPTransport) Deliver(ctx context.Context, envelope SMTPEnvelope) error {
	address := net.JoinHostPort(envelope.Host, strconv.Itoa(envelope.Port))
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("SMTP connection failed")
	}
	defer func() { _ = connection.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("SMTP deadline could not be configured")
	}
	client, err := smtp.NewClient(connection, envelope.Host)
	if err != nil {
		return errors.New("SMTP session failed")
	}
	defer func() { _ = client.Close() }()
	if supported, _ := client.Extension("STARTTLS"); !supported {
		return errors.New("SMTP server does not support TLS")
	}
	if err := client.StartTLS(&tls.Config{ServerName: envelope.Host, MinVersion: tls.VersionTLS12}); err != nil {
		return errors.New("SMTP TLS negotiation failed")
	}
	if err := client.Auth(smtp.PlainAuth("", envelope.Username, envelope.Password, envelope.Host)); err != nil {
		return errors.New("SMTP authentication failed")
	}
	if err := client.Mail(envelope.FromAddress); err != nil {
		return errors.New("SMTP sender was rejected")
	}
	if err := client.Rcpt(envelope.To); err != nil {
		return errors.New("SMTP recipient was rejected")
	}
	writer, err := client.Data()
	if err != nil {
		return errors.New("SMTP message could not start")
	}
	if _, err := writer.Write(envelope.Message); err != nil {
		_ = writer.Close()
		return errors.New("SMTP message could not be written")
	}
	if err := writer.Close(); err != nil {
		return errors.New("SMTP message could not be completed")
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP delivery did not complete")
	}
	return nil
}
