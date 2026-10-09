-- Every call of the administration API that changes something (or tries to),
-- with who made it, from where, and what came of it. The same record goes to
-- the outbox in the same transaction (kind admin_change), where the audit
-- chain picks it up: this table answers "what did the administrators do?",
-- the chain proves the answer was not edited. detail never holds secrets or
-- request content.
CREATE TABLE admin_changes (
    seq         bigserial PRIMARY KEY,
    event_id    text        NOT NULL UNIQUE,
    occurred_at timestamptz NOT NULL,
    actor       text        NOT NULL,
    action      text        NOT NULL,
    target      text        NOT NULL DEFAULT '',
    outcome     text        NOT NULL,
    request_id  text        NOT NULL DEFAULT '',
    remote_addr text        NOT NULL DEFAULT '',
    detail      jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX admin_changes_occurred_idx ON admin_changes (occurred_at);
