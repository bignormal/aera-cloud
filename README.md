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

Run unit tests without services:

```bash
go test ./...
```

Run service integration tests after starting Compose and sourcing `.env.example`:

```bash
AERA_INTEGRATION_TESTS=1 go test ./internal/store -v
```

Production deployment is intentionally unavailable at this stage. A filed domain, trusted HTTPS, real email/SMS providers, independent production secrets, and verified backup/restore are later release gates.
