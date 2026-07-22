package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bignormal/aera-cloud/internal/abuse"
	"github.com/bignormal/aera-cloud/internal/account"
	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/bignormal/aera-cloud/internal/browser"
	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/device"
	"github.com/bignormal/aera-cloud/internal/entitlement"
	"github.com/bignormal/aera-cloud/internal/httpapi"
	"github.com/bignormal/aera-cloud/internal/jobs"
	"github.com/bignormal/aera-cloud/internal/legal"
	"github.com/bignormal/aera-cloud/internal/notification"
	"github.com/bignormal/aera-cloud/internal/oauth"
	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/bignormal/aera-cloud/internal/webui"
	"github.com/bignormal/aera-cloud/internal/workspace"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	startupTimeout      = 10 * time.Second
	shutdownTimeout     = 10 * time.Second
	maintenanceInterval = time.Minute
	maintenanceLeaseTTL = 10 * time.Minute
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
	accountHandler, err := buildAccountHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		return err
	}
	oauthHandler, err := buildOAuthHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		return err
	}
	deviceHandler, err := buildDeviceHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		return err
	}
	agentRepository := agentcontrol.NewPostgresRepository(postgres)
	agentControlHandler, err := buildAgentControlHandler(cfg, postgres, redisStore.Client(), agentRepository)
	if err != nil {
		return err
	}
	workspaceHandler, err := buildWorkspaceHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		return err
	}
	organizationHandler, err := buildOrganizationHandler(
		cfg, postgres, redisStore.Client(), agentcontrol.NewOrganizationAssetGuard(agentRepository),
	)
	if err != nil {
		return err
	}
	maintenanceRunner, err := buildMaintenanceRunner(cfg, postgres, redisStore.Client())
	if err != nil {
		return err
	}

	publicHandler := httpapi.New(httpapi.Dependencies{
		PostgreSQL:   postgres,
		Redis:        redisStore,
		Verification: verificationHandler,
		Accounts:     accountHandler,
		OAuth:        oauthHandler,
		Devices:      deviceHandler,
		AgentControl: agentControlHandler,
		Workspace:    workspaceHandler,
		Organization: organizationHandler,
		Web:          webui.New(),
	})
	var internalHandler http.Handler
	var internalTLS *tls.Config
	if cfg.InternalAdmin.Enabled {
		internalHandler, internalTLS, err = buildInternalAdmin(cfg, postgres, redisStore)
		if err != nil {
			return err
		}
	}
	maintenanceCtx, stopMaintenance := context.WithCancel(ctx)
	defer stopMaintenance()
	return runHTTPServersWithReady(ctx, cfg, publicHandler, internalHandler, internalTLS, net.Listen, func() {
		slog.Info("AgentEra cloud started", "address", cfg.ListenAddr, "environment", cfg.Environment,
			"internal_admin_enabled", cfg.InternalAdmin.Enabled)
		go maintenanceRunner.Run(maintenanceCtx)
	})
}

func buildMaintenanceRunner(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (*jobs.Runner, error) {
	identityCodec, _, err := buildIdentityCodecs(cfg)
	if err != nil {
		return nil, err
	}
	maintenance, err := jobs.NewPostgresMaintenance(
		postgres, account.NewPostgresRepository(postgres, identityCodec),
	)
	if err != nil {
		return nil, err
	}
	owner, err := secure.RandomUUID()
	if err != nil {
		return nil, err
	}
	return jobs.NewRunner(jobs.RunnerConfig{
		Lease: jobs.NewRedisLease(redisClient), Maintenance: maintenance, Owner: owner.String(),
		LeaseTTL: maintenanceLeaseTTL, Interval: maintenanceInterval, Logger: slog.Default(),
	})
}

func buildVerificationHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (http.Handler, error) {
	identityCodec, receiptCodec, err := buildIdentityCodecs(cfg)
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
		Receipts:        receiptCodec,
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

func buildAccountHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (http.Handler, error) {
	identityCodec, receiptCodec, err := buildIdentityCodecs(cfg)
	if err != nil {
		return nil, err
	}
	passwords, err := secure.DefaultPasswordHasher()
	if err != nil {
		return nil, err
	}
	legalService, err := legal.NewService(cfg.TermsVersion, cfg.PrivacyVersion)
	if err != nil {
		return nil, err
	}
	loginLimiter, err := account.NewRedisLoginLimiter(redisClient, cfg.LoginRateHMACKey, account.LoginRatePolicy{
		IdentityLimit: cfg.LoginIdentityLimit,
		IPLimit:       cfg.LoginIPLimit,
		Window:        time.Duration(cfg.LoginWindowSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	auditor, err := audit.NewPostgresRecorder(postgres)
	if err != nil {
		return nil, err
	}
	accountService, err := account.NewService(account.ServiceConfig{
		Repository:    account.NewPostgresRepository(postgres, identityCodec),
		IdentityCodec: identityCodec,
		Receipts:      receiptCodec,
		Passwords:     passwords,
		Legal:         legalService,
		LoginLimiter:  loginLimiter,
		Auditor:       auditor,
	})
	if err != nil {
		return nil, err
	}
	browserSessions, err := buildBrowserSessionManager(cfg, redisClient)
	if err != nil {
		return nil, err
	}
	accessAuthenticator, err := buildAccessAuthenticator(cfg, postgres, redisClient)
	if err != nil {
		return nil, err
	}
	return account.NewHandler(account.HTTPConfig{
		Accounts: accountService, BrowserSessions: browserSessions, Legal: legalService,
		AccessTokens: accessAuthenticator,
	}), nil
}

func buildOAuthHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (http.Handler, error) {
	accessSigner, err := session.NewAccessSigner(session.AccessSignerConfig{
		Issuer: cfg.PublicURL, Audience: oauth.DesktopClientID,
		ActiveKeyID: cfg.AccessSigningKeyRing.ActiveKeyID,
		SigningKeys: privateSigningKeys(cfg.AccessSigningKeyRing),
	})
	if err != nil {
		return nil, err
	}
	offlineEntitlements, err := entitlement.NewService(entitlement.ServiceConfig{
		Repository: entitlement.NewPostgresRepository(postgres),
		Issuer:     cfg.PublicURL, Audience: oauth.DesktopClientID,
		ActiveKeyID:   cfg.OfflineSigningKeyRing.ActiveKeyID,
		SigningKeys:   privateSigningKeys(cfg.OfflineSigningKeyRing),
		PolicyVersion: cfg.OfflinePolicyVersion,
	})
	if err != nil {
		return nil, err
	}
	agentControlSigner, err := agentcontrol.NewSigner(agentcontrol.SigningConfig{
		Issuer: cfg.PublicURL, ActiveKeyID: cfg.AgentControlSigningKeyRing.ActiveKeyID,
		SigningKeys: privateSigningKeys(cfg.AgentControlSigningKeyRing),
	})
	if err != nil {
		return nil, err
	}
	organizationSigner, err := organization.NewSigner(organization.SigningConfig{
		Issuer: cfg.PublicURL, ActiveKeyID: cfg.AgentControlSigningKeyRing.ActiveKeyID,
		SigningKeys: privateSigningKeys(cfg.AgentControlSigningKeyRing),
	})
	if err != nil {
		return nil, err
	}
	sessions, err := session.NewService(session.ServiceConfig{
		Repository: session.NewPostgresRepository(postgres), AccessTokens: accessSigner,
		OfflineEntitlements: offlineEntitlements, RefreshHMACKey: cfg.RefreshTokenHMACKey,
	})
	if err != nil {
		return nil, err
	}
	devices, err := device.NewService(device.ServiceConfig{
		Repository: device.NewPostgresRepository(postgres), ActiveLimit: cfg.ActiveDeviceLimit,
	})
	if err != nil {
		return nil, err
	}
	oauthService, err := oauth.NewService(oauth.ServiceConfig{
		Repository: oauth.NewPostgresRepository(postgres), Devices: devices, Sessions: sessions,
		ActiveStateKeyID:    cfg.OAuthStateEncryptionKeyRing.ActiveKeyID,
		StateEncryptionKeys: cfg.OAuthStateEncryptionKeyRing.Keys,
		StateHMACKey:        cfg.OAuthStateHMACKey,
	})
	if err != nil {
		return nil, err
	}
	browserSessions, err := buildBrowserSessionManager(cfg, redisClient)
	if err != nil {
		return nil, err
	}
	return oauth.NewHandler(oauth.HTTPConfig{
		OAuth: oauthService, Sessions: sessions, BrowserSessions: browserSessions,
		SigningKeys: func() []oauth.PublishedKey {
			published := make(
				[]oauth.PublishedKey,
				0,
				len(accessSigner.PublicKeys())+len(offlineEntitlements.PublicKeys())+2*len(agentControlSigner.PublicKeys())+len(organizationSigner.PublicKeys()),
			)
			for _, key := range accessSigner.PublicKeys() {
				published = append(published, oauth.PublishedKey{
					KeyID: key.KeyID, KeyType: key.KeyType, Curve: key.Curve,
					Algorithm: key.Algorithm, Use: key.Use, Purpose: "access", X: key.X,
				})
			}
			for _, key := range offlineEntitlements.PublicKeys() {
				published = append(published, oauth.PublishedKey{
					KeyID: key.KeyID, KeyType: key.KeyType, Curve: key.Curve,
					Algorithm: key.Algorithm, Use: key.Use, Purpose: "offline_entitlement", X: key.X,
				})
			}
			for _, key := range agentControlSigner.PublicKeys() {
				published = append(published, oauth.PublishedKey{
					KeyID: key.KeyID, KeyType: key.KeyType, Curve: key.Curve,
					Algorithm: key.Algorithm, Use: key.Use, Purpose: string(agentcontrol.PurposeAgentVersion), X: key.X,
				})
				published = append(published, oauth.PublishedKey{
					KeyID: key.KeyID, KeyType: key.KeyType, Curve: key.Curve,
					Algorithm: key.Algorithm, Use: key.Use, Purpose: string(agentcontrol.PurposeAgentPolicy), X: key.X,
				})
			}
			for _, key := range organizationSigner.PublicKeys() {
				published = append(published, oauth.PublishedKey{
					KeyID: key.KeyID, KeyType: key.KeyType, Curve: key.Curve,
					Algorithm: key.Algorithm, Use: key.Use, Purpose: string(organization.PurposeOrganizationPolicy), X: key.X,
				})
			}
			return published
		},
	}), nil
}

func buildDeviceHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (http.Handler, error) {
	accessAuthenticator, err := buildAccessAuthenticator(cfg, postgres, redisClient)
	if err != nil {
		return nil, err
	}
	devices, err := device.NewService(device.ServiceConfig{
		Repository: device.NewPostgresRepository(postgres), ActiveLimit: cfg.ActiveDeviceLimit,
	})
	if err != nil {
		return nil, err
	}
	browserSessions, err := buildBrowserSessionManager(cfg, redisClient)
	if err != nil {
		return nil, err
	}
	return device.NewHandler(device.HTTPConfig{
		Devices: devices, AccessTokens: accessAuthenticator, BrowserSessions: browserSessions,
	}), nil
}

func buildAgentControlHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
	repository *agentcontrol.PostgresRepository,
) (http.Handler, error) {
	if repository == nil {
		return nil, errors.New("Agent control repository is unavailable")
	}
	accessAuthenticator, err := buildAccessAuthenticator(cfg, postgres, redisClient)
	if err != nil {
		return nil, err
	}
	signer, err := agentcontrol.NewSigner(agentcontrol.SigningConfig{
		Issuer: cfg.PublicURL, ActiveKeyID: cfg.AgentControlSigningKeyRing.ActiveKeyID,
		SigningKeys: privateSigningKeys(cfg.AgentControlSigningKeyRing),
	})
	if err != nil {
		return nil, err
	}
	service, err := agentcontrol.NewService(agentcontrol.ServiceConfig{
		Repository: repository, Signer: signer,
	})
	if err != nil {
		return nil, err
	}
	return agentcontrol.NewHandler(agentcontrol.HTTPConfig{
		Service: service, AccessTokens: accessAuthenticator,
	}), nil
}

func buildWorkspaceHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (http.Handler, error) {
	accessAuthenticator, err := buildAccessAuthenticator(cfg, postgres, redisClient)
	if err != nil {
		return nil, err
	}
	limiter, err := workspace.NewRedisWorkspaceLimiter(redisClient, workspace.LimitPolicies{
		WorkspaceCreate: workspace.LimitPolicy{
			Limit: cfg.WorkspaceCreateRateLimit, Window: cfg.WorkspaceCreateRateWindow,
		},
		InvitationCreate: workspace.LimitPolicy{
			Limit: cfg.WorkspaceInviteRateLimit, Window: cfg.WorkspaceInviteRateWindow,
		},
		InvitationAccept: workspace.LimitPolicy{
			Limit: cfg.WorkspaceAcceptRateLimit, Window: cfg.WorkspaceAcceptRateWindow,
		},
	})
	if err != nil {
		return nil, err
	}
	auditor, err := audit.NewPostgresRecorder(postgres)
	if err != nil {
		return nil, err
	}
	service, err := workspace.NewService(workspace.ServiceConfig{
		Repository: workspace.NewPostgresRepository(postgres), Limiter: limiter, Auditor: auditor,
		Random: workspace.DefaultServiceRandom(), Quotas: workspace.Quotas{
			ActiveOwned: cfg.WorkspaceActiveOwnedLimit, Members: cfg.WorkspaceMemberLimit,
			PendingInvitations: cfg.WorkspacePendingInviteLimit,
		},
	})
	if err != nil {
		return nil, err
	}
	return workspace.NewHandler(workspace.HTTPConfig{Service: service, AccessTokens: accessAuthenticator}), nil
}

func buildOrganizationHandler(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
	assetGuard organization.AssetGuard,
) (http.Handler, error) {
	if postgres == nil || redisClient == nil || assetGuard == nil {
		return nil, errors.New("organization dependencies are unavailable")
	}
	accessAuthenticator, err := buildAccessAuthenticator(cfg, postgres, redisClient)
	if err != nil {
		return nil, err
	}
	limiter, err := organization.NewRedisOrganizationLimiter(redisClient, organization.LimitPolicies{
		OrganizationCreate: organization.LimitPolicy{
			Limit: cfg.OrganizationCreateRateLimit, Window: cfg.OrganizationCreateRateWindow,
		},
		InvitationCreate: organization.LimitPolicy{
			Limit: cfg.OrganizationInviteRateLimit, Window: cfg.OrganizationInviteRateWindow,
		},
		InvitationAccept: organization.LimitPolicy{
			Limit: cfg.OrganizationAcceptRateLimit, Window: cfg.OrganizationAcceptRateWindow,
		},
		Mutation: organization.LimitPolicy{
			Limit: cfg.OrganizationMutationRateLimit, Window: cfg.OrganizationMutationRateWindow,
		},
		HighRisk: organization.LimitPolicy{
			Limit: cfg.OrganizationHighRiskRateLimit, Window: cfg.OrganizationHighRiskRateWindow,
		},
	})
	if err != nil {
		return nil, err
	}
	signer, err := organization.NewSigner(organization.SigningConfig{
		Issuer: cfg.PublicURL, ActiveKeyID: cfg.AgentControlSigningKeyRing.ActiveKeyID,
		SigningKeys: privateSigningKeys(cfg.AgentControlSigningKeyRing),
	})
	if err != nil {
		return nil, err
	}
	repository := organization.NewPostgresRepository(postgres, signer, assetGuard)
	service, err := organization.NewService(organization.ServiceConfig{
		Repository: repository, Limiter: limiter,
		OwnedLimit: cfg.OrganizationOwnedLimit, MemberLimit: cfg.OrganizationMemberLimit,
		DepartmentLimit: cfg.OrganizationDepartmentLimit, PendingInvitationLimit: cfg.OrganizationPendingInviteLimit,
	})
	if err != nil {
		return nil, err
	}
	return organization.NewHandler(organization.HTTPConfig{Service: service, AccessTokens: accessAuthenticator}), nil
}

func buildAccessAuthenticator(
	cfg config.Config,
	postgres *pgxpool.Pool,
	redisClient redis.UniversalClient,
) (*session.AccessAuthenticator, error) {
	accessSigner, err := session.NewAccessSigner(session.AccessSignerConfig{
		Issuer: cfg.PublicURL, Audience: oauth.DesktopClientID,
		ActiveKeyID: cfg.AccessSigningKeyRing.ActiveKeyID,
		SigningKeys: privateSigningKeys(cfg.AccessSigningKeyRing),
	})
	if err != nil {
		return nil, err
	}
	return session.NewAccessAuthenticator(session.AccessAuthenticatorConfig{
		Tokens: accessSigner, Repository: session.NewPostgresRepository(postgres),
		Cache: session.NewRedisAccessStatusCache(redisClient),
	})
}

func buildBrowserSessionManager(cfg config.Config, redisClient redis.UniversalClient) (*browser.Manager, error) {
	return browser.NewManager(browser.ManagerConfig{
		Redis:         redisClient,
		HMACKey:       cfg.BrowserSessionHMACKey,
		TTL:           time.Duration(cfg.BrowserSessionTTLSeconds) * time.Second,
		CookieName:    cfg.BrowserCookieName,
		SecureCookies: cfg.Environment == "production" || strings.HasPrefix(cfg.PublicURL, "https://"),
	})
}

func privateSigningKeys(keyRing config.KeyRing) map[string]ed25519.PrivateKey {
	keys := make(map[string]ed25519.PrivateKey, len(keyRing.Keys))
	for keyID, material := range keyRing.Keys {
		keys[keyID] = append(ed25519.PrivateKey(nil), material...)
	}
	return keys
}

func buildIdentityCodecs(cfg config.Config) (*secure.IdentityCodec, *verification.ReceiptCodec, error) {
	identityCodec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: cfg.IdentityEncryptionKeyRing.ActiveKeyID,
		EncryptionKeys:        cfg.IdentityEncryptionKeyRing.Keys,
		ActiveLookupKeyID:     cfg.IdentityLookupKeyRing.ActiveKeyID,
		LookupKeys:            cfg.IdentityLookupKeyRing.Keys,
	})
	if err != nil {
		return nil, nil, err
	}
	receiptCodec, err := verification.NewReceiptCodec(verification.ReceiptCodecConfig{
		IdentityCodec:      identityCodec,
		ActiveSigningKeyID: cfg.VerificationReceiptKeyRing.ActiveKeyID,
		SigningKeys:        cfg.VerificationReceiptKeyRing.Keys,
	})
	if err != nil {
		return nil, nil, err
	}
	return identityCodec, receiptCodec, nil
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
