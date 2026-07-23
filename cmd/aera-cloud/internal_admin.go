package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/adminapi"
	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/officialquality"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

type listenerOpener func(network, address string) (net.Listener, error)

type httpServerBinding struct {
	listener net.Listener
	handler  http.Handler
}

func buildInternalAdmin(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisStore *store.RedisStore,
	platformServices ...agentcontrol.PlatformService,
) (http.Handler, *tls.Config, error) {
	if !cfg.InternalAdmin.Enabled {
		return nil, nil, errors.New("internal admin is disabled")
	}
	if postgres == nil || redisStore == nil {
		return nil, nil, errors.New("internal admin stores are required")
	}

	identities, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: cfg.IdentityEncryptionKeyRing.ActiveKeyID,
		EncryptionKeys:        cfg.IdentityEncryptionKeyRing.Keys,
		ActiveLookupKeyID:     cfg.IdentityLookupKeyRing.ActiveKeyID,
		LookupKeys:            cfg.IdentityLookupKeyRing.Keys,
	})
	if err != nil {
		return nil, nil, err
	}
	protector, err := admin.NewProtector(cfg.InternalAdmin.HMACKeys.ActiveKeyID, cfg.InternalAdmin.HMACKeys.Keys)
	if err != nil {
		return nil, nil, err
	}
	repository, err := admin.NewControlRepository(postgres, identities, protector, time.Now)
	if err != nil {
		return nil, nil, err
	}
	service, err := admin.NewControlService(admin.ControlServiceConfig{
		Queries: repository, Commands: repository, OfficialAudit: repository,
		Protector: protector, Clock: time.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := adminapi.LoadEd25519PublicKey(cfg.InternalAdmin.JWTPublicKeyFile)
	if err != nil {
		return nil, nil, err
	}
	authenticator, err := adminapi.NewAuthenticator(adminapi.AuthenticatorConfig{
		PublicKey: publicKey, Issuer: cfg.InternalAdmin.JWTIssuer,
		Subject: cfg.InternalAdmin.JWTSubject, Clock: time.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	var platform agentcontrol.PlatformService
	if len(platformServices) > 1 {
		return nil, nil, errors.New("one official platform service is allowed")
	}
	if len(platformServices) == 1 {
		platform = platformServices[0]
	}
	if cfg.OfficialAgent.Enabled && platform == nil {
		return nil, nil, errors.New("official platform service is unavailable")
	}
	if cfg.OfficialQuality.Enabled && platform == nil {
		return nil, nil, errors.New("official quality platform service is unavailable")
	}
	handlerConfig := adminapi.HandlerConfig{
		Service: service, Auth: authenticator, PostgreSQL: postgres, Redis: redisStore, Clock: time.Now,
	}
	if platform != nil {
		handlerConfig.OfficialAgents = platform
		handlerConfig.OfficialAudit = service
		handlerConfig.OperationProtector = protector
	}
	if cfg.OfficialQuality.Enabled {
		qualityRepository := officialquality.NewPostgresRepository(postgres)
		draftCloner, err := officialquality.NewAgentControlDraftCloner(platform)
		if err != nil {
			return nil, nil, err
		}
		qualityService, err := officialquality.NewProposalService(officialquality.ProposalServiceConfig{
			Repository: qualityRepository, AggregateReader: qualityRepository,
			Scanner: officialquality.MinimizedScanner{}, DraftCloner: draftCloner,
			PlatformID:      cfg.OfficialAgent.PlatformID,
			MinimumSubjects: cfg.OfficialQuality.MinimumSubjects,
		})
		if err != nil {
			return nil, nil, err
		}
		handlerConfig.OfficialQuality = qualityService
	}
	handler, err := adminapi.NewHandler(handlerConfig)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := adminapi.LoadTLSConfig(
		cfg.InternalAdmin.ServerCertFile,
		cfg.InternalAdmin.ServerKeyFile,
		cfg.InternalAdmin.ClientCAFile,
	)
	if err != nil {
		return nil, nil, err
	}
	return handler, tlsConfig, nil
}

func runHTTPServers(
	ctx context.Context,
	cfg config.Config,
	publicHandler http.Handler,
	internalHandler http.Handler,
	internalTLS *tls.Config,
	open listenerOpener,
) error {
	return runHTTPServersWithReady(ctx, cfg, publicHandler, internalHandler, internalTLS, open, nil)
}

func runHTTPServersWithReady(
	ctx context.Context,
	cfg config.Config,
	publicHandler http.Handler,
	internalHandler http.Handler,
	internalTLS *tls.Config,
	open listenerOpener,
	ready func(),
) error {
	if ctx == nil || publicHandler == nil || open == nil || cfg.ListenAddr == "" {
		return errors.New("HTTP server configuration is invalid")
	}
	if cfg.InternalAdmin.Enabled &&
		(internalHandler == nil || internalTLS == nil || cfg.InternalAdmin.ListenAddr == "") {
		return errors.New("internal admin server configuration is invalid")
	}
	if ctx.Err() != nil {
		return nil
	}

	publicListener, err := open("tcp", cfg.ListenAddr)
	if err != nil || publicListener == nil {
		return errors.New("HTTP listener could not be opened")
	}
	defer func() { _ = publicListener.Close() }()
	bindings := []httpServerBinding{{listener: publicListener, handler: publicHandler}}

	if cfg.InternalAdmin.Enabled {
		internalListener, err := open("tcp", cfg.InternalAdmin.ListenAddr)
		if err != nil || internalListener == nil {
			return errors.New("internal admin listener could not be opened")
		}
		defer func() { _ = internalListener.Close() }()
		bindings = append(bindings, httpServerBinding{
			listener: tls.NewListener(internalListener, internalTLS.Clone()),
			handler:  internalHandler,
		})
	}
	if ready != nil {
		ready()
	}
	return serveHTTPBindings(ctx, bindings)
}

func serveHTTPBindings(ctx context.Context, bindings []httpServerBinding) error {
	if len(bindings) == 0 {
		return errors.New("at least one HTTP server binding is required")
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(bindings))
	for _, binding := range bindings {
		binding := binding
		go func() {
			results <- serve(serveCtx, binding.listener, binding.handler)
		}()
	}

	first := <-results
	parentCanceled := ctx.Err() != nil
	cancel()
	for remaining := 1; remaining < len(bindings); remaining++ {
		if err := <-results; first == nil && err != nil {
			first = err
		}
	}
	if parentCanceled && first == nil {
		return nil
	}
	if first != nil || !parentCanceled {
		return errors.New("HTTP server stopped unexpectedly")
	}
	return nil
}
