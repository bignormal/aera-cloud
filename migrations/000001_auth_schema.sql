CREATE TABLE users (
    id UUID PRIMARY KEY,
    nickname TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    password_security_version INTEGER NOT NULL DEFAULT 1,
    deletion_requested_at TIMESTAMPTZ,
    deletion_finalized_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'pending_deletion', 'disabled')),
    CONSTRAINT users_password_security_version_check CHECK (password_security_version > 0),
    CONSTRAINT users_deletion_state_check CHECK (status <> 'pending_deletion' OR deletion_requested_at IS NOT NULL)
);

CREATE TABLE identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    encryption_key_id TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    lookup_key_id TEXT NOT NULL,
    lookup_hmac BYTEA NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT identities_kind_check CHECK (kind IN ('email', 'phone')),
    CONSTRAINT identities_nonce_length_check CHECK (octet_length(nonce) = 12),
    CONSTRAINT identities_ciphertext_length_check CHECK (octet_length(ciphertext) > 16),
    CONSTRAINT identities_lookup_hmac_length_check CHECK (octet_length(lookup_hmac) = 32),
    CONSTRAINT identities_kind_lookup_hmac_key UNIQUE (kind, lookup_hmac)
);

CREATE INDEX identities_user_id_idx ON identities(user_id);
CREATE INDEX identities_lookup_key_id_idx ON identities(lookup_key_id);

CREATE TABLE password_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    params_version INTEGER NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT password_credentials_params_version_check CHECK (params_version > 0)
);

CREATE TABLE personal_spaces (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT personal_spaces_owner_user_id_key UNIQUE (owner_user_id),
    CONSTRAINT personal_spaces_status_check CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    installation_id UUID NOT NULL,
    public_key BYTEA NOT NULL,
    display_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    app_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT devices_installation_id_key UNIQUE (installation_id),
    CONSTRAINT devices_public_key_key UNIQUE (public_key),
    CONSTRAINT devices_public_key_length_check CHECK (octet_length(public_key) = 32),
    CONSTRAINT devices_status_check CHECK (status IN ('active', 'inactive', 'revoked')),
    CONSTRAINT devices_revocation_state_check CHECK (status <> 'revoked' OR revoked_at IS NOT NULL)
);

CREATE INDEX devices_user_status_idx ON devices(user_id, status);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    refresh_token_hash BYTEA NOT NULL,
    rotated_from_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    replaced_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    replay_detected_at TIMESTAMPTZ,
    CONSTRAINT sessions_refresh_token_hash_key UNIQUE (refresh_token_hash),
    CONSTRAINT sessions_refresh_token_hash_length_check CHECK (octet_length(refresh_token_hash) = 32),
    CONSTRAINT sessions_expiry_check CHECK (expires_at > issued_at)
);

CREATE INDEX sessions_family_id_idx ON sessions(family_id);
CREATE INDEX sessions_device_active_idx ON sessions(device_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE verification_challenges (
    id UUID PRIMARY KEY,
    purpose TEXT NOT NULL,
    identity_kind TEXT NOT NULL,
    target_lookup_key_id TEXT NOT NULL,
    target_lookup_hmac BYTEA NOT NULL,
    code_key_id TEXT NOT NULL,
    code_hmac BYTEA NOT NULL,
    idempotency_key_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    resend_after TIMESTAMPTZ NOT NULL,
    failed_attempts SMALLINT NOT NULL DEFAULT 0,
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT verification_challenges_identity_kind_check CHECK (identity_kind IN ('email', 'phone')),
    CONSTRAINT verification_challenges_target_hmac_length_check CHECK (octet_length(target_lookup_hmac) = 32),
    CONSTRAINT verification_challenges_code_hmac_length_check CHECK (octet_length(code_hmac) = 32),
    CONSTRAINT verification_challenges_idempotency_hash_key UNIQUE (idempotency_key_hash),
    CONSTRAINT verification_challenges_idempotency_hash_length_check CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT verification_challenges_failed_attempts_check CHECK (failed_attempts BETWEEN 0 AND 5),
    CONSTRAINT verification_challenges_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX verification_challenges_target_idx ON verification_challenges(identity_kind, target_lookup_hmac, purpose, created_at DESC);
CREATE INDEX verification_challenges_expiry_idx ON verification_challenges(expires_at) WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE oauth_requests (
    id UUID PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    pkce_method TEXT NOT NULL,
    state_hash BYTEA NOT NULL,
    state_ciphertext BYTEA NOT NULL,
    installation_id UUID NOT NULL,
    device_public_key BYTEA NOT NULL,
    device_key_digest BYTEA NOT NULL,
    approved_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_requests_pkce_method_check CHECK (pkce_method = 'S256'),
    CONSTRAINT oauth_requests_state_hash_length_check CHECK (octet_length(state_hash) = 32),
    CONSTRAINT oauth_requests_device_public_key_length_check CHECK (octet_length(device_public_key) = 32),
    CONSTRAINT oauth_requests_device_key_digest_length_check CHECK (octet_length(device_key_digest) = 32),
    CONSTRAINT oauth_requests_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX oauth_requests_expiry_idx ON oauth_requests(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY,
    oauth_request_id UUID NOT NULL REFERENCES oauth_requests(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT authorization_codes_oauth_request_id_key UNIQUE (oauth_request_id),
    CONSTRAINT authorization_codes_code_hash_key UNIQUE (code_hash),
    CONSTRAINT authorization_codes_code_hash_length_check CHECK (octet_length(code_hash) = 32),
    CONSTRAINT authorization_codes_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE offline_entitlement_issuances (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    personal_space_id UUID NOT NULL REFERENCES personal_spaces(id) ON DELETE CASCADE,
    installation_id UUID NOT NULL,
    signing_key_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT offline_entitlement_issuances_policy_version_check CHECK (policy_version > 0),
    CONSTRAINT offline_entitlement_issuances_expiry_check CHECK (expires_at > issued_at)
);

CREATE INDEX offline_entitlement_issuances_device_idx ON offline_entitlement_issuances(device_id, expires_at DESC);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    object_type TEXT,
    object_id UUID,
    outcome TEXT NOT NULL,
    reason_code TEXT,
    request_id TEXT,
    ip_hmac BYTEA,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_events_outcome_check CHECK (outcome IN ('success', 'failure', 'denied')),
    CONSTRAINT audit_events_ip_hmac_length_check CHECK (ip_hmac IS NULL OR octet_length(ip_hmac) = 32)
);

CREATE INDEX audit_events_actor_time_idx ON audit_events(actor_user_id, created_at DESC);
CREATE INDEX audit_events_type_time_idx ON audit_events(event_type, created_at DESC);

CREATE TABLE legal_acceptances (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_type TEXT NOT NULL,
    document_version TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT legal_acceptances_document_type_check CHECK (document_type IN ('terms', 'privacy')),
    CONSTRAINT legal_acceptances_user_document_version_key UNIQUE (user_id, document_type, document_version)
);
