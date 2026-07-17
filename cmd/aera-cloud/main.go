package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bignormal/aera-cloud/internal/abuse"
	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/httpapi"
	"github.com/bignormal/aera-cloud/internal/notification"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	startupTimeout  = 10 * time.Second
	shutdownTimeout = 10 * time.Second
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.LookupEnv); err != nil {
		slog.Error("AgentEra cloud stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, lookup config.LookupEnv) error {
	cfg, err := config.Load(lookup)
	if err != nil {
		return err
	}

	startupCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	postgres, err := store.OpenPostgres(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(startupCtx, postgres); err != nil {
		return err
	}
	redisStore, err := store.OpenRedis(startupCtx, store.RedisOptions{
		Addr:     cfg.RedisAddr,
		Username: cfg.RedisUsername,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := redisStore.Close(); err != nil {
			slog.Warn("Redis close failed")
		}
	}()
	verificationHandler, err := buildVerificationHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return errors.New("HTTP listener could not be opened")
	}
	slog.Info("AgentEra cloud started", "address", cfg.ListenAddr, "environment", cfg.Environment)
	return serve(ctx, listener, httpapi.New(httpapi.Dependencies{
		PostgreSQL:   postgres,
		Redis:        redisStore,
		Verification: verificationHandler,
	}))
}

func buildVerificationHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (http.Handler, error) {
	identityCodec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: cfg.IdentityEncryptionKeyRing.ActiveKeyID,
		EncryptionKeys:        cfg.IdentityEncryptionKeyRing.Keys,
		ActiveLookupKeyID:     cfg.IdentityLookupKeyRing.ActiveKeyID,
		LookupKeys:            cfg.IdentityLookupKeyRing.Keys,
	})
	if err != nil {
		return nil, err
	}
	email, err := notification.NewSMTPEmail(notification.SMTPConfig{
		Host:        cfg.SMTPHost,
		Port:        cfg.SMTPPort,
		Username:    cfg.SMTPUsername,
		Password:    cfg.SMTPPassword,
		FromAddress: cfg.SMTPFromAddress,
		FromName:    cfg.SMTPFromName,
	}, nil)
	if err != nil {
		return nil, err
	}
	allowInsecureLoopback := cfg.Environment != "production"
	sms, err := notification.NewHTTPSMS(notification.HTTPSMSConfig{
		Endpoint:                  cfg.SMSEndpoint,
		APIKey:                    cfg.SMSAPIKey,
		SenderID:                  cfg.SMSSenderID,
		AllowInsecureLoopbackHTTP: allowInsecureLoopback,
	})
	if err != nil {
		return nil, err
	}
	sender, err := notification.NewRouter(email, sms)
	if err != nil {
		return nil, err
	}
	captcha, err := abuse.NewHTTPChallengeVerifier(abuse.HTTPChallengeConfig{
		Endpoint:                  cfg.CaptchaEndpoint,
		Secret:                    cfg.CaptchaSecret,
		AllowInsecureLoopbackHTTP: allowInsecureLoopback,
	})
	if err != nil {
		return nil, err
	}
	service, err := verification.NewService(verification.ServiceConfig{
		Sender:          sender,
		Repository:      verification.NewPostgresRepository(postgres),
		Limiter:         verification.NewRedisLimiter(redisClient),
		Captcha:         captcha,
		DeliveryGuard:   verification.NewRedisDeliveryGuard(redisClient),
		TargetIndexer:   identityCodec,
		ActiveCodeKeyID: cfg.VerificationCodeKeyRing.ActiveKeyID,
		CodeKeys:        cfg.VerificationCodeKeyRing.Keys,
		RequestHMACKey:  cfg.VerificationRequestHMACKey,
		Logger:          slog.Default(),
	})
	if err != nil {
		return nil, err
	}
	return verification.NewHandler(service), nil
}

func serve(ctx context.Context, listener net.Listener, handler http.Handler) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return errors.New("HTTP server shutdown timed out")
		}
		err := <-serveResult
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
