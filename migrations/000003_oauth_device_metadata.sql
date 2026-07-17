ALTER TABLE oauth_requests
    ADD COLUMN state_encryption_key_id TEXT NOT NULL DEFAULT 'legacy-unavailable',
    ADD COLUMN state_nonce BYTEA NOT NULL DEFAULT decode('000000000000000000000000', 'hex'),
    ADD COLUMN device_display_name TEXT NOT NULL DEFAULT 'Unknown device',
    ADD COLUMN device_platform TEXT NOT NULL DEFAULT 'darwin',
    ADD COLUMN app_version TEXT NOT NULL DEFAULT '0.0.0';

ALTER TABLE oauth_requests
    ALTER COLUMN state_encryption_key_id DROP DEFAULT,
    ALTER COLUMN state_nonce DROP DEFAULT,
    ALTER COLUMN device_display_name DROP DEFAULT,
    ALTER COLUMN device_platform DROP DEFAULT,
    ALTER COLUMN app_version DROP DEFAULT,
    ADD CONSTRAINT oauth_requests_state_nonce_length_check CHECK (octet_length(state_nonce) = 12),
    ADD CONSTRAINT oauth_requests_device_platform_check CHECK (device_platform IN ('darwin', 'windows', 'linux')),
    ADD CONSTRAINT oauth_requests_device_display_name_check CHECK (char_length(device_display_name) BETWEEN 1 AND 100),
    ADD CONSTRAINT oauth_requests_app_version_check CHECK (char_length(app_version) BETWEEN 1 AND 64);
