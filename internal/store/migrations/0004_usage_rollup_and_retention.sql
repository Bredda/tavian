-- Hourly usage rollups and outbox retention.
--
-- usage_hourly sums the usage events of an hour by who, what and where, so that
-- totals survive the removal of the raw events. A consumer adds to it in the
-- transaction that moves its cursor, so every event is counted once.
-- cost_micro_eur stays NULL until prices are configured.
CREATE TABLE usage_hourly (
    hour             timestamptz NOT NULL,
    team             text        NOT NULL,
    application      text        NOT NULL,
    principal        text        NOT NULL, -- the API key id or the user
    model            text        NOT NULL,
    backend          text        NOT NULL,
    outcome          text        NOT NULL,
    requests         bigint      NOT NULL DEFAULT 0,
    usage_unknown    bigint      NOT NULL DEFAULT 0, -- requests whose backend reported no token counts
    input_tokens     bigint      NOT NULL DEFAULT 0,
    output_tokens    bigint      NOT NULL DEFAULT 0,
    cached_tokens    bigint      NOT NULL DEFAULT 0,
    reasoning_tokens bigint      NOT NULL DEFAULT 0,
    cost_micro_eur   bigint,
    PRIMARY KEY (hour, team, application, principal, model, backend, outcome)
);

-- What retention removed from the outbox, written in the transaction that
-- removed it, so that `tavian verify-audit` can tell the records retention
-- accounts for from records that went missing otherwise. Never pruned.
CREATE TABLE outbox_prunes (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pruned_at        timestamptz NOT NULL DEFAULT now(),
    kind             text        NOT NULL,
    rows             bigint      NOT NULL,
    through_position bigint -- decision records: the highest chain position removed
);
