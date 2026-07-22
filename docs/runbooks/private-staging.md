# Private staging runbook

Private staging is for functional verification before the AgentEra account domain has completed filing and trusted HTTPS is available. It is not a public launch mode.

## Network rule

The server IP may be used only through one of these controls:

1. a VPN reachable only by approved developers;
2. an SSH tunnel to a loopback-bound service; or
3. trusted HTTPS plus a strict developer IP allowlist at both the firewall and reverse proxy.

Never bind the account service, PostgreSQL, or Redis directly to `0.0.0.0` for raw-IP testing. Public registration stays disabled throughout private staging.

## Internal Admin listener

The Internal Admin listener is independent from the public account listener. Keep it on a loopback address, a private service network, or an authenticated tunnel reachable only from the approved Aera Admin workload. Do not publish it through the public reverse proxy, reuse its certificate as the public web certificate, or route `/internal/admin` from the public listener.

Internal Admin is disabled by default. Enabling it requires every variable below; inject paths and secret values from the staging secret manager rather than committing examples:

- `AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED`: explicit feature gate; use `true` only after the remaining values and database migration are ready.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR`: private address different from `AGENTERA_CLOUD_LISTEN_ADDR`.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE`: absolute path to the listener certificate with the deployed DNS name or IP in its SAN.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE`: absolute path to the matching private key.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE`: absolute path to the dedicated CA bundle that validates the Admin client certificate.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE`: absolute path to the Ed25519 public key used only to verify Admin service tokens.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_ISSUER`: exact approved service-token issuer.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_SUBJECT`: exact approved Admin workload identity.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_ACTIVE_KEY_ID`: active identifier for operation idempotency and cursor protection.
- `AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_KEYS`: JSON key ring containing independent 32-byte HMAC keys supplied by the secret manager.

Every call must pass both a client certificate rooted in the dedicated CA and a short-lived Ed25519 service JWT with the exact issuer, subject, audience, and route scope. Grant only the required values from `users:read`, `devices:write`, `sessions:write`, `accounts:write`, and `operations:read`; duplicate, unknown, or wildcard scopes are invalid.

PostgreSQL remains authoritative for user, device, session, entitlement, administrative revision, operation, and audit state. Redis is only an acceleration layer: clearing or restoring Redis does not restore access after PostgreSQL records a revocation or account disable. A database restore can intentionally rewind security state, so recovery requires a security review and reconciliation against the immutable audit export before either listener is reopened.

### Deployment and rollback order

1. Back up PostgreSQL and complete a disposable restore verification.
2. Apply migration `000015_internal_admin_api.sql` before enabling the Internal Admin listener. Do not enable the listener against an older schema.
3. Mount the server certificate/key, dedicated client CA, Ed25519 verification key, and HMAC key ring with least-privilege file permissions.
4. Start Cloud with Internal Admin enabled, verify TLS 1.3 mutual authentication from the approved Admin workload, and confirm requests without either credential fail closed.
5. Enable the Admin Cloud client only after the private listener is healthy; run a masked lookup and a non-destructive operation query before allowing mutations.

For rollback, disable the Admin Cloud client and stop the Internal Admin listener before rolling back the Cloud application. Keep migration `000015_internal_admin_api.sql` and its data in place while any old or new process might read it; do not drop operation, revision, or audit facts as part of application rollback. Re-enable the listener only after the deployed binary and schema are compatible and the dual-authentication probe passes.

Passing these checks proves only local or private-staging verification. A Git commit, a branch push, a deployment, and a production release are separate states and must be recorded independently.

## SSH-tunnel workflow

1. Create a separate staging secret file outside Git with mode `0600`. Use `AGENTERA_CLOUD_ENVIRONMENT=development`, `AGENTERA_CLOUD_LISTEN_ADDR=127.0.0.1:18086`, and `AGENTERA_CLOUD_PUBLIC_URL=http://127.0.0.1:18086`.
2. Use the dedicated `aera_cloud` PostgreSQL database/role and Redis user/database 9. Do not reuse recharge-site cookies, keys, users, or networks.
3. Run the image on the Linux host with loopback networking and bounded resources:

   ```bash
   docker run --rm --name agentera-cloud-staging \
     --network host --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
     --cpus 0.75 --memory 384m --pids-limit 128 \
     --env-file /srv/agentera-cloud/secrets/staging.env \
     agentera-cloud:staging
   ```

4. From the approved developer machine, create the tunnel:

   ```bash
   ssh -N -L 18086:127.0.0.1:18086 deploy@SERVER_IP
   ```

5. Open `http://127.0.0.1:18086/login` locally. Confirm `/health/ready`, registration delivery through a staging provider, browser login, PKCE authorization, refresh rotation, device revoke, and account recovery.

## Exit criteria

- Run `./scripts/smoke-auth.sh` against its automatically isolated stack.
- Run encrypted backup and `restore-verify.sh`; retain only the encrypted archive.
- Confirm no service is exposed publicly with `ss -lntp` and the host firewall.
- Destroy staging browser sessions and test accounts before changing origins.

Changing the control-plane origin changes the token issuer. Raw-IP/loopback staging sessions and offline entitlements are disposable; users must authenticate again after the filed HTTPS domain becomes the production origin.
