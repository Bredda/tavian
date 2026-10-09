-- Outbox consumers and the audit hash chain (ADR-0010, docs/SECURITY.md#audit).
--
-- outbox.seq is assigned when a row is inserted, not when its transaction
-- commits, so a consumer reading "everything after the last seq it saw" can
-- skip a row that commits late. xid records the inserting transaction (xid8:
-- 64 bits, no wraparound). A consumer only reads rows whose xid is below the
-- oldest transaction still running (pg_snapshot_xmin): every transaction
-- older than that has finished, so no row can appear behind its cursor.
-- Rows that exist before this migration all get the migration's own xid.
ALTER TABLE outbox ADD COLUMN xid xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE INDEX outbox_xid_seq_idx ON outbox (xid, seq);

-- Where each consumer is: everything up to (last_xid, last_seq) has been
-- handled. The cursor moves in the same transaction as the handler's effects.
CREATE TABLE outbox_consumers (
    name       text PRIMARY KEY,
    last_xid   bigint      NOT NULL DEFAULT 0,
    last_seq   bigint      NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The hash chain over decision records. position has no gaps; each entry
-- commits to the one before it, so changing, removing or reordering a record
-- breaks every entry after it.
CREATE TABLE audit_chain (
    position     bigint PRIMARY KEY,
    event_id     text        NOT NULL UNIQUE,
    occurred_at  timestamptz NOT NULL,
    content_hash bytea       NOT NULL,
    prev_hash    bytea       NOT NULL,
    entry_hash   bytea       NOT NULL,
    chained_at   timestamptz NOT NULL DEFAULT now()
);

-- Signed statements about a stretch of the chain. A seal is what an auditor
-- keeps outside the database: with it, rewriting the chain is detectable even
-- by someone who can recompute every hash. id has no gaps.
CREATE TABLE audit_seals (
    id              bigint PRIMARY KEY,
    first_position  bigint      NOT NULL,
    last_position   bigint      NOT NULL,
    last_entry_hash bytea       NOT NULL,
    sealed_at       timestamptz NOT NULL,
    key_id          text        NOT NULL,
    signature       bytea       NOT NULL
);
