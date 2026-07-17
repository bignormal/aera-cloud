ALTER TABLE verification_challenges
    ADD COLUMN receipt_consumed_at TIMESTAMPTZ,
    ADD CONSTRAINT verification_challenges_receipt_consumption_check CHECK (
        receipt_consumed_at IS NULL
        OR (consumed_at IS NOT NULL AND receipt_consumed_at >= consumed_at)
    );

CREATE INDEX verification_challenges_receipt_available_idx
    ON verification_challenges (id, purpose)
    WHERE consumed_at IS NOT NULL AND receipt_consumed_at IS NULL;
