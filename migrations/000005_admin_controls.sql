ALTER TABLE users
    ADD COLUMN administratively_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT users_administrative_disable_state_check CHECK (
        NOT administratively_disabled OR status = 'disabled'
    );
