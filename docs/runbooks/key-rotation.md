# Key-rotation runbook

Key IDs are durable data references. Rotation always adds a key first, changes the active key later, and removes an old key only after every dependent record has expired or been migrated.

## Symmetric encryption, lookup, HMAC, and receipt keys

1. Generate new independent material and a new `kid` in the secret manager.
2. Deploy the expanded key ring while leaving the old key active.
3. Confirm every instance can read data written under both IDs.
4. Switch the active ID in a second release.
5. Re-encrypt or re-index through a reviewed maintenance operation where required.
6. Prove backups restore with the complete recovery set before retiring an old key.

Never change key bytes under an existing ID. Never remove identity encryption keys from the recovery set while any backup or row references them.

## Offline-entitlement signing keys

Offline rotation is an overlap protocol and cannot be a cloud-only key switch:

1. Generate the next Ed25519 key pair and assign a new offline public `kid`.
2. Ship a desktop release that trusts the next public `kid` while still trusting the current one.
3. Confirm sufficient desktop adoption and retain evidence of the bundled public-key set.
4. Add the new private key to the cloud key ring, then begin signing new entitlements with it.
5. Keep the previous public and private verification material available through the final seven-day entitlement expiry, plus operational clock tolerance.
6. Only after that window may the previous signing key be retired from new cloud releases; older supported desktop builds must still have a valid trusted key path.

Switching only the cloud signer would make updated entitlements unverifiable on existing desktops and is prohibited.

## Emergency response

If a private signing key may be compromised, disable new entitlement issuance, revoke affected devices/sessions online, preserve audit evidence, and ship an emergency desktop trust update. Do not silently shorten local Hermes data retention or alter Hermes self-learning state as a substitute for authorization revocation.
