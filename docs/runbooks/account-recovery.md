# Account and disaster-recovery runbook

## User account recovery

- Password reset requires a fresh email or mainland-phone verification receipt and revokes prior product sessions.
- An account pending deletion can be recovered during the seven-day cooling-off period through `/delete-account?mode=recover` with a bound identity, verification code, and password.
- After recovery, old devices remain revoked and must authenticate again.
- A finalized account cannot be restored from the live service; use legally approved backup recovery only when policy permits.

Cloud account deletion, disablement, recovery, or session revocation never deletes local Hermes sessions, Memory, USER, files, skills, Curator state, Profile data, or self-learning results.

## Restricted operator commands

Run the admin binary only from a controlled host with an explicit operator identity:

```bash
aera-cloud-admin --operator incident-123 disable-account --user-id USER_UUID
aera-cloud-admin --operator incident-123 enable-account --user-id USER_UUID
aera-cloud-admin --operator incident-123 revoke-session --session-id SESSION_UUID
aera-cloud-admin --operator incident-123 audit --user-id USER_UUID --limit 50
```

The audit command returns redacted events and never returns identity plaintext, request secrets, tokens, or device keys.

## Disaster recovery

1. Select the newest encrypted archive whose checksum is present in independent storage.
2. Provision a disposable PostgreSQL server; never restore over production.
3. Provide the offline `age` identity, database-admin URL, and the full identity encryption recovery key ring.
4. Run:

   ```bash
   export AGENTERA_RESTORE_BACKUP=/secure/path/agentera-cloud.dump.age
   export AGENTERA_RESTORE_AGE_IDENTITY=/secure/offline/age-identity.txt
   export AGENTERA_RESTORE_ADMIN_URL='REDACTED_DISPOSABLE_ADMIN_URL'
   export AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS='REDACTED_RECOVERY_KEY_RING'
   ./deploy/restore-verify.sh
   ```

5. Require a passing migration ledger, relational-integrity queries, and authenticated decryption of every stored identity. The command reports only a count and never prints plaintext identities.
6. Destroy the disposable database. Promote restored data only through a separately reviewed incident plan, then rotate credentials and revoke sessions.
