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

	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/httpapi"
	"github.com/bignormal/aera-cloud/internal/store"
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

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return errors.New("HTTP listener could not be opened")
	}
	slog.Info("AgentEra cloud started", "address", cfg.ListenAddr, "environment", cfg.Environment)
	return serve(ctx, listener, httpapi.New(httpapi.Dependencies{
		PostgreSQL: postgres,
		Redis:      redisStore,
	}))
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
