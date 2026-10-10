# Audit chain

_Status: built (M2 steps 2.6 and 2.6b)._

Every authenticated chat request leaves a **decision record** ([SECURITY.md](SECURITY.md#audit)), and every change made through the administration API or by `SIGHUP` leaves an **admin change record** ([ADMIN_API.md](ADMIN_API.md)); both go in the chain. This page is about making those records *tamper-evident*: showing, later, that none was changed, removed or slipped in. It is written for whoever runs the gateway and for the auditor who checks it.

## What it guarantees, and what it does not

| Someone with access to the database... | Detected? |
|---|---|
| edits a record's content, time or outcome | yes: the record no longer matches its hash |
| deletes a record, or a stretch of the chain | yes: a gap, or a seal that no longer matches |
| reorders or swaps records | yes: entries no longer link |
| inserts a record that was never chained | yes, once the sealer has passed it |
| **recomputes the whole chain** after editing a record | yes **if the chain is sealed**: the seals are signed with a key that is not in the database. Without a signing key this is *not* detected |
| deletes the newest entries **and** the newest seals | only against a copy of the seals kept elsewhere (`-anchors`) |
| steals the signing key | no: they can forge seals from then on. Keep the key away from the people who can edit the database |

It does not prove that the gateway recorded what really happened (a compromised gateway can write false records), nor does it hide anything: records hold no prompt content, but they are not encrypted either (M4).

## How it works

1. The gateway writes each decision record to the outbox table; the administration API writes each change record there too (kind `admin_change`), in the same transaction as its `admin_changes` row and before the change takes effect.
2. A background consumer (the *sealer*) reads new decision and admin change records in transaction order and appends them to `audit_chain`. Each entry holds `content_hash` (SHA-256 of a canonical form of the record: keys sorted, no insignificant whitespace), `prev_hash` and `entry_hash`, which commits to the position, the previous entry, the event id, the time and the content hash. The first entry links to a fixed genesis hash.
3. When a signing key is configured, the sealer writes a **seal** every `audit.seal_every_events` entries (default 1000) or when the oldest unsealed entry is `audit.seal_every` old (default 5 minutes): "entries *a* to *b* end with this hash", signed with Ed25519. Seals are numbered without gaps.
4. `tavian verify-audit` recomputes everything from what is in the database.

The chain is built after the fact, not on the request path: a slow or stopped sealer delays sealing, never requests. Watch `tavian_audit_unsealed_entries`, `tavian_audit_seconds_since_last_seal` and `tavian_outbox_consumer_pending{consumer="audit-chain"}`.

Records are read in the order of the transactions that wrote them, once every older transaction has finished, so a record whose transaction commits late is never skipped (details in [ADR-0010](adr/0010-transactional-outbox-no-broker.md)). A long transaction anywhere in the PostgreSQL cluster delays the chain for as long as it runs.

## Setting it up

```bash
tavian audit-keygen -out /etc/tavian/audit.key        # prints the public key
```

```yaml
audit:
  signing_key_file: /etc/tavian/audit.key   # relative paths are relative to this file
  seal_every_events: 1000
  seal_every: 5m
```

Run `tavian migrate` first (migration 0003 adds the chain tables and a column to `outbox`; it needs PostgreSQL 13 or later and rewrites the table). The key file must not be readable by others (mode 0600). Without `signing_key_file` the chain is still built, but the gateway warns at startup that nothing anchors it. Changing the audit or workers settings needs a restart.

Give the public key (`ed25519:...`) to your auditors. After a key change, keep the old public key: seals say which key signed them, and `-public-key` takes several.

## Verifying

```bash
tavian verify-audit -config tavian.yaml -public-key ed25519:...           # exit 0: nothing wrong, 1: problems
tavian verify-audit -config tavian.yaml -public-key ed25519:... -export-seals seals.jsonl
tavian verify-audit -config tavian.yaml -public-key ed25519:... -anchors seals.jsonl
```

It only reads, so a read-only database role is enough ([For the auditor](#for-the-auditor) below). It checks that

- entries are numbered without gaps, link to each other and hash to what they claim;
- every record still in the outbox matches its hash (and time), and no decision record that the sealer has passed is missing from the chain;
- seals are numbered without gaps, their signatures verify, and each matches the entry it names;
- with `-anchors`, every seal exported earlier is still in the database, unchanged. **Export the seals regularly to somewhere the database administrators cannot write** (offline media, a separate system): that is what exposes a truncated end of the chain.

`-from-seal N` starts after a signed seal instead of the first entry, for long chains. Records that the chain still covers but the outbox no longer holds are a problem unless `-allow-pruned` is given and a signed seal covers them *and* the retention log accounts for them (see below).

The report also says how many entries come after the last seal (not covered by a signature yet) and how many records are waiting to be chained (normal for a few seconds). Decision and admin change records are chained; usage events are accounting. Retention never removes admin change records.

## For the auditor

An auditor needs three things, none of which lets them change anything: a database role that can only read, a configuration file that says where the database is, and the public key of the seals.

**1. A role that can only read.** `tavian audit-role` prints the SQL that creates it; it runs nothing, and the script is run by a database administrator (`tavian audit-role -name tavian_auditor -database tavian | psql`), who then sets the password or the certificate of the role.

```bash
tavian audit-role -name tavian_auditor -database tavian -schema public > auditor-role.sql
```

The role can log in and has no right to create anything or to bypass anything. It gets `SELECT` on the tables the checks and the export read (`audit_chain`, `audit_seals`, `outbox`, `outbox_consumers`, `outbox_prunes`, the history of administrators' changes and of configuration revisions) and nothing else: not `usage_hourly`, not `admin_token_use`, no write, no `TRUNCATE`, no `CREATE`. Its sessions also start read-only (`default_transaction_read_only`), a second lock that the grants make unnecessary. A test creates the role from this very script and tries to write, delete, truncate, drop, alter and grant: all refused, and `verify-audit` works with it. On PostgreSQL 14 and older, also run `REVOKE CREATE ON SCHEMA public FROM PUBLIC` (version 15 and later already do).

What the auditor can read: all of the outbox, which also holds the usage events (who used which model, how many tokens, at what cost; never the content of a request). Restricting that would need the audit records in a schema of their own; it is not done.

**2. A configuration file.** The auditor does not need the gateway's. This is enough (the profile decides which database addresses are accepted):

```yaml
profile: air-gapped          # the profile of the gateway
database:
  url_env: TAVIAN_DATABASE_URL
```

with `TAVIAN_DATABASE_URL` set to the connection URL of the auditor's role.

**3. The public key** of the seals (`tavian audit-keygen` printed it) and, ideally, the seals exported earlier and kept elsewhere (`-anchors`).

Then the auditor:

```bash
tavian verify-audit -config auditor.yaml -public-key ed25519:... -anchors seals.jsonl
tavian audit-export -config auditor.yaml -o audit.jsonl                  # all entries
tavian audit-export -config auditor.yaml -kind admin_change -since 2026-09-01 -until 2026-10-01
```

`audit-export` writes the chain as JSON lines, one entry per line, in the order of the chain, with the record it covers:

```json
{"position":412,"event_id":"…","kind":"admin_change","occurred_at":"2026-10-10T12:00:00Z",
 "content_hash":"…","prev_hash":"…","entry_hash":"…","record":{"actor":"ops-alice","action":"config.apply",…}}
```

`kind` is `decision` or `admin_change`; `record` is the record as the outbox holds it, or `null` with `"pruned":true` when retention has removed it (the entry stays). Filters: `-kind` (comma-separated), `-since` and `-until` (RFC 3339 or a date, UTC; `-since` is included, `-until` is not), `-from-position`. `-o FILE` writes the file with mode 0600 and never over an existing one without `-force`; without it the entries go to the standard output.

The export is enough to check the chain with a tool of one's own. With `‖` for concatenation and `be64` for a signed 64-bit big-endian integer:

- `content_hash` = SHA-256 of the **canonical form** of `record`: the JSON with its object keys sorted, no whitespace outside strings, numbers as they are written, strings as JSON strings with no escaping of `<`, `>` and `&`;
- `entry_hash` = SHA-256 of `"tavian-audit-entry-v1" ‖ 0x00 ‖ be64(position) ‖ prev_hash ‖ be64(length of event_id) ‖ event_id ‖ be64(occurred_at in microseconds since 1970) ‖ content_hash` (the hashes as their 32 raw bytes, not their hexadecimal text);
- `prev_hash` of an entry is the `entry_hash` of the one before; the first one is SHA-256 of `"tavian-audit-genesis-v1"`.

`tavian verify-audit` does all of this and more (the seals and their signatures, the records still in the outbox, the retention log); the export is for archiving, for reading, and for cross-checking with something else. When the export starts after the first entry (`-from-position`), the first `prev_hash` is the one of an entry you do not have: trust it, or start from the beginning.

## Retention

The outbox would grow for ever, so old events are removed (`internal/outbox`, a pass every `outbox.prune_every`, default 1 hour, in batches of 1000):

```yaml
outbox:
  retention:
    usage_days: 90      # default 90; 0 keeps them for ever
    decision_days: 0    # default 0 = never; needs audit.signing_key_file
  prune_every: 1h
```

A row is removed only when **all** of these hold:

- it is older than the retention of its kind (counted from when it was recorded);
- every registered consumer has handled it. A consumer that is new, stopped or removed from the code but still registered holds pruning back: safe, but watch `tavian_outbox_consumer_pending` and the size of the outbox;
- for a decision record, its chain entry is covered by a **signed seal**. Without a signing key nothing is ever removed, which is why `decision_days` requires one.

Usage events go after their hourly sums are made ([QUOTAS_AND_METERING.md](QUOTAS_AND_METERING.md#reporting)). The chain, the seals, the hourly sums and the configuration revisions are never removed (the chain costs about 150 bytes per record).

Each batch is written to `outbox_prunes` (kind, number of rows, highest chain position) in the transaction that removed it. `tavian verify-audit -allow-pruned` accepts the records missing under a signed seal only as far as that log accounts for them: a record that went missing otherwise is a problem. Someone who can edit the database can also edit this log, so it catches mistakes and crude deletions, not a determined attacker; only seals exported elsewhere (`-anchors`) anchor history. Metrics: `tavian_outbox_pruned_total{kind}`, `tavian_outbox_prune_errors_total`.

Deleting rows leaves dead space that PostgreSQL's autovacuum reuses. Partitioning the outbox by time, to drop whole partitions, is not done: it needs a data migration and is only worth it at volumes this version is not aimed at.
