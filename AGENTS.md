# Cloud Development Rules

These repository-scoped rules are mandatory for every AI agent and contributor working anywhere in `aera-cloud`.

## Required relational-integrity analysis

- Before changing identity, ownership, authorization, revocation, reassignment, or a composite key, enumerate every inbound PostgreSQL foreign key and application-owned reference to the affected entity. Inspect current migrations and the live repository queries; do not infer the relationship graph from one package alone.
- Define and test same-owner reauthorization, cross-owner transfer, and owner-bound protected-data behavior separately.
- Preserve same-owner operational state unless the approved feature contract explicitly replaces it. During an allowed cross-owner transfer, remove only disposable old-owner state.
- Never silently delete or reassign encrypted backups, backup authority, audit evidence, or other protected user data to make an ownership transition succeed. Return an explicit domain conflict instead.
- Execute the complete ownership transition in one PostgreSQL transaction and prove rollback after a failure that occurs after intermediate mutations.

## Required error semantics

- Only invalid, expired, replayed, or cryptographically rejected authorization material may map to an authorization-specific client error such as `authorization_expired`.
- Database, foreign-key, dependency, and availability failures must remain retryable availability failures unless deliberately classified as a stable domain conflict.
- Preserve domain errors through repository, service, and HTTP layers, and add a mapping test at every changed boundary. Do not convert an internal failure into expired credentials.

## Required verification

- Use real migrations and PostgreSQL for relational-state regression tests; schema mocks do not prove foreign-key behavior.
- Cover the unchanged-state result for every rejected transition and the committed-state result for every accepted transition.
- Run packages sharing the integration database serially with `AERA_INTEGRATION_TESTS=1 go test -count=1 -p 1 ...`.
- Validate only affected Cloud boundaries unless another repository or platform changed. Passing Cloud tests does not prove a Desktop release, deployment, or physical-client acceptance.
