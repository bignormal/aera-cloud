ALTER TABLE identities
    ADD CONSTRAINT identities_user_id_kind_key UNIQUE (user_id, kind);

CREATE INDEX users_pending_deletion_idx
    ON users (deletion_requested_at)
    WHERE status = 'pending_deletion';

CREATE TABLE device_self_revocation_nonces (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    nonce_hash BYTEA NOT NULL,
    used_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_id, nonce_hash),
    CONSTRAINT device_self_revocation_nonces_hash_length_check CHECK (octet_length(nonce_hash) = 32)
);

CREATE INDEX device_self_revocation_nonces_used_at_idx
    ON device_self_revocation_nonces (used_at);
