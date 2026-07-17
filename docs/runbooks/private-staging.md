# Private staging runbook

Private staging is for functional verification before the AgentEra account domain has completed filing and trusted HTTPS is available. It is not a public launch mode.

## Network rule

The server IP may be used only through one of these controls:

1. a VPN reachable only by approved developers;
2. an SSH tunnel to a loopback-bound service; or
3. trusted HTTPS plus a strict developer IP allowlist at both the firewall and reverse proxy.

Never bind the account service, PostgreSQL, or Redis directly to `0.0.0.0` for raw-IP testing. Public registration stays disabled throughout private staging.

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
