-- Transactional outbox (ADR-0010). Usage events and, later, audit records are
-- appended here; in-process workers consume them at least once, keyed by
-- event_id. seq reflects insertion order, not commit order: consumers must not
-- assume that a lower seq is already visible.
CREATE TABLE outbox (
    seq         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id    text        NOT NULL UNIQUE,
    kind        text        NOT NULL,
    occurred_at timestamptz NOT NULL,
    payload     jsonb       NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbox_kind_occurred_idx ON outbox (kind, occurred_at);

-- Every revision the gateway has ever run, so that an event's config_revision
-- can always be resolved to the exact configuration. The YAML holds API key
-- hashes and environment variable names, never secrets.
CREATE TABLE config_revisions (
    revision        text PRIMARY KEY,
    profile         text        NOT NULL,
    config_yaml     text        NOT NULL,
    tavian_version  text        NOT NULL,
    first_loaded_at timestamptz NOT NULL DEFAULT now()
);
