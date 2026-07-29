# AgentEra Cloud

Private cloud backend and browser account center for AgentEra Studio.

This repository owns AgentEra APP identity, personal-space metadata, device sessions, and product authorization. It does not share accounts, cookies, tokens, user IDs, balances, or API keys with `bignormal/agentera-claw-api`, and it never stores Hermes Memory, USER, sessions, files, skills, Curator state, or self-learning data.

## Local development

Requirements: Go 1.26+, Docker, and Docker Compose.

```bash
docker compose up -d postgres redis
set -a
source .env.example
set +a
go run ./cmd/aera-cloud
```

The local HTTP service listens on `127.0.0.1:8086`. PostgreSQL and Redis are published on loopback-only development ports and use credentials that are intentionally limited to this disposable development stack.

```bash
curl --fail http://127.0.0.1:8086/health/live
curl --fail http://127.0.0.1:8086/health/ready
```

The versioned verification API is mounted at:

```text
POST /api/v1/verification/challenges
POST /api/v1/verification/challenges/verify
```

Challenge creation requires `Idempotency-Key` and `X-AgentEra-Installation-ID` headers. The provider values in `.env.example` deliberately use the reserved `.invalid` domain, so local requests exercise failure handling without sending email or SMS. Verified deployments may explicitly enable `email`, `phone`, or both identity kinds. Phone delivery supports either the existing HTTPS gateway contract or direct Alibaba Cloud Dysmsapi; credentials are injected only through the deployment secret environment. Registration and login share one atomic 60-second cooldown per normalized phone number, including across service instances and purpose changes. Aliyun failures retain only a validated provider code and masked request ID in structured logs; provider messages, credentials, phone numbers, and verification codes are discarded. An internal-beta deployment without CAPTCHA fails closed when a rate-limit decision requires CAPTCHA instead of bypassing the check.

## Internal Admin API

The Internal Admin API is disabled by default. When explicitly enabled, the same Cloud process starts a separate TLS 1.3 Internal Admin listener; none of its `/internal/admin/v1` routes are registered on the public HTTP listener. The listener must remain on a private network or loopback interface and requires both mTLS and a short-lived Ed25519 service JWT on every request.

The API provides masked exact-identity lookup plus bounded user, device, session, account, and operation controls for the separate `aera-admin` service. Full email or phone input is accepted only in the lookup POST body and is never returned, logged, audited, cached, or stored by this interface. PostgreSQL commits each successful mutation, administrative revision, operation record, and Cloud audit event atomically; Redis cannot make a revoked principal active again.

Do not add certificate paths, key material, or service identities to `.env.example`. Supply all enabled-listener settings through the deployment secret manager and follow the [private staging runbook](docs/runbooks/private-staging.md) for configuration, deployment order, rollback, and verification.

## Official managed Agent development

Official managed Agents are disabled by default. Development or test processes expose no official catalog, PLATFORM publication workflow, or managed update path unless `AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=true` and the complete platform identity plus rollout-key configuration is present. Partial configuration fails startup. Keep the rollout HMAC ring independent from every signing, identity, session, and rate-limit key; `.env.example` intentionally contains no enabled rollout secret.

The public API exposes only eligible published catalog entries and USER-owned managed Installations. Drafts, submissions, reviews, release controls, and official audit history exist only on the separately authenticated Internal Admin listener. Official Agent mutations persist their domain change, idempotency record, operation result, and audit evidence atomically. Version selection is derived by Cloud from the current immutable release revision; clients cannot submit PLATFORM ownership or an arbitrary managed version.

Cloud stores no physical Hermes Profile path and receives no Memory, conversation, session, credential, private Skill, Curator, or local-learning data. Each official Installation remains USER-owned, while `runtime_binding_records` contain only opaque profile identity and sanitized release provenance. Publishing, pausing, rollout changes, and rollback do not mutate an existing local RuntimeBinding or private adaptive state.

After starting the disposable Compose PostgreSQL and Redis services, run the complete development gate with the checked-in non-production configuration:

```bash
set -a
source ./.env.example
set +a
go test ./... -count=1
go vet ./...
AERA_INTEGRATION_TESTS=1 go test -p 1 ./... -count=1
```

The integration gate includes deterministic rollout, immutable publication, atomic failure rollback, actor-bound Internal Admin operations, strict public/internal OpenAPI separation, and private-state boundary checks. These commands verify local development behavior only; they do not authorize production keys, deployment, publication, or release.

Run unit tests without services:

```bash
go test ./...
```

Run service integration tests after starting Compose and sourcing `.env.example`:

```bash
AERA_INTEGRATION_TESTS=1 go test -p 1 ./... -v
```

Run the destructive auth smoke flow only against its automatically created, isolated Compose project:

```bash
./scripts/smoke-auth.sh
```

The script proves health, verified phone registration with PostgreSQL account rows, one-time SMS-code browser login, password login, desktop PKCE exchange, refresh rotation, revoke, post-revoke rejection, and recovery-key identity decryption, then destroys the isolated database and Redis volumes.

The browser account center lives in `web/`. Its production build is embedded into the Go binary by `Dockerfile`; credentials and verification codes never enter the desktop renderer.

## Delivery boundary

`deploy/compose.production.yaml` defines one bounded AgentEra application container plus dedicated PostgreSQL and Redis resources. The app is loopback-published for a trusted HTTPS reverse proxy and does not share the recharge website's accounts, cookies, database, Redis namespace, or network.

Before any public launch, follow:

- [private staging](docs/runbooks/private-staging.md)
- [production](docs/runbooks/production.md)
- [key rotation](docs/runbooks/key-rotation.md)
- [account and disaster recovery](docs/runbooks/account-recovery.md)

Production remains gated on a filed domain, trusted HTTPS, a real provider for every enabled identity kind, real CAPTCHA, published legal documents, independent secrets, encrypted backup, and a verified disposable restore. The existence of deployment files does not authorize a push, deployment, DNS change, or public registration.
