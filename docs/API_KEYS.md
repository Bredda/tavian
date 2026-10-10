# API keys

Tavian API keys are for applications and service accounts. People sign in with
an OIDC access token instead ([ADR-0002](adr/0002-generic-oidc.md)); both can
be used on the same gateway.

## What a key is

`tavian keygen` prints a key (`tav_` followed by 256 random bits) and the value
to put in the configuration. The key is shown **once**: Tavian never stores it,
only its SHA-256, so it cannot be recovered. A salt would add nothing here: the
key is as random as a salt would be, so there is nothing to brute-force and the
hash is only a lookup handle.

```yaml
api_keys:
  - id: research-app                 # shows up in usage events and logs, never the key
    hash: sha256:4b7e…               # from `tavian keygen`
    team: research
    application: notebook
    allowed_models: ["llama-*"]      # '*' wildcard; an empty list is invalid
    expires_at: 2027-03-01           # optional, see below
    max_classification: internal     # optional, see below
```

## Expiry

`expires_at` is an RFC 3339 timestamp (`2027-03-01T10:00:00+01:00`) or a plain
date, which means 00:00 UTC (a plain date is written without quotes: in quotes
it must be a full timestamp). The key stops working **at** that instant and is
refused with the usual `401`; the log line says the key has expired and names
its `id`. Without `expires_at` a key never expires.

Tavian does not refuse to start with an expired key in the file (a restart
must not take the gateway down because someone forgot to tidy the
configuration). Instead:

- the log names expired keys, and keys expiring within 14 days, at startup and
  on every reload;
- `tavian_api_keys_expired` counts expired keys and
  `tavian_api_keys_next_expiry_seconds` gives the time to the nearest expiry.
  Alert on the latter (for example below 14 days) so that nobody is surprised.

## Rotating a key without downtime

Several keys may be valid at the same time, so rotation is an overlap:

1. Generate a new key: `tavian keygen`. Give it a new `id` (for example
   `research-app-2027`), the same team, application and models.
2. Add it to `api_keys` next to the old one and reload: `kill -HUP <pid>`
   (or restart the container). From the next request on, both work.
3. Give the new key to the application and let it switch over.
4. When usage events no longer show the old `key_id`, remove the old entry (or
   let its `expires_at` pass) and reload.

To make the old key stop earlier or later than planned, change its
`expires_at` and reload.

## Revoking a key

Remove its entry and reload. It is refused from the next request on: the
configuration is read from memory, not from a cache that has to expire. A key
that must be cut off while the file cannot be edited can be given an
`expires_at` in the past, which has the same effect.

An invalid reload (for example a typo) is rejected and the previous
configuration stays active, so check the log after a revocation.

## Clearance: `max_classification`

Every application has a **clearance**: the most sensitive label of data it may
send (`public` < `internal` < `confidential` < `restricted`). It defaults to
`internal`. A compromised key can therefore never push data above its
clearance through the gateway.

The gateway **enforces** it: every request gets a classification label (see
[SECURITY.md](SECURITY.md#data-classification)), and a request whose label is
above the caller's clearance is refused with 403 `classification_exceeds_clearance`
(reason `CLEARANCE_EXCEEDED` in the decision record). With the default
clearance, a request that contains an IBAN, a payment card number, a French
social security number (`confidential`) or a secret (`restricted`) is
therefore refused: an application that is meant to handle such data must
declare it, for example `max_classification: confidential` for a finance
application. Ordinary prompts, including ones with e-mail addresses, phone
numbers or IP addresses, are `internal` and unaffected. An identity without
any clearance is refused every request. For OIDC users the
clearance comes from the group mappings: `max_classification` on each mapping
in `oidc.mappings`, and a person gets the highest of their groups, just as
their allowed models add up.

## What is not there (yet)

- Last-use tracking and a revocation list need the database and the admin API:
  they come with M3, together with database-backed keys.
- OIDC access tokens cannot be revoked before they expire. Keep their lifetime
  short at the identity provider.
