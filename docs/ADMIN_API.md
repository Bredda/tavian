# Administration API

_What the administration API does today, how to turn it on, and what it records. The reference of every call, with a "Test Request" button, is embedded in the gateway at `/admin/docs` on the admin listener, and works offline._

The API lives on the **admin listener** (`listen.admin`, `127.0.0.1:9090` by default) under `/admin/v1`, next to `/healthz`, `/readyz` and `/metrics`, which stay as they are and need no credential. Keep the listener on a private interface: the API is as sensitive as the configuration file.

It is separate from the data plane in three ways: a different port, different credentials, and a record of every change.

## Turning it on

The API is **not served at all** (every route answers 404) until at least one token is configured.

```bash
tavian keygen -admin
# token: tavadm_...   <- give it to the administrator; shown once, never stored
# hash:  sha256:4b7e... <- goes in the configuration
```

```yaml
admin:
  tokens:
    - id: ops-alice          # names the author of every change this token makes
    - ...
```

Each entry is `id` and `hash`. Reload (`SIGHUP`, or `POST /admin/v1/config/reload` with another token). The API also needs the database (`database.url_env`): a change that cannot be recorded must not be made, so the configuration is refused without it.

Tokens are 256-bit random values and, like API keys, only their SHA-256 is stored ([API_KEYS.md](API_KEYS.md)). The `tavadm_` prefix keeps them apart from data-plane keys (`tav_`): neither kind is accepted where the other is expected. Give each person or tool its own token, with an `id` that says who it is: the id is what the change history shows. To revoke a token, remove its entry and reload. Expiry and rotation help are not built yet; OIDC sign-in for administrators is not built either, so today anyone who holds a token is an administrator.

Failed authentications are logged (reason, request id and address, never the credential) and counted in `tavian_admin_requests_total{outcome="unauthenticated"}`. They are not throttled.

## Calls

Send `Authorization: Bearer tavadm_...`. Errors are `{"error": {"code": "...", "message": "..."}}` and every answer has an `X-Request-Id` (send your own to follow a call through the logs and the records).

| Call | What it does |
|---|---|
| `GET /admin/v1/whoami` | The id of the token you used |
| `GET /admin/v1/config` | The running revision: its id, profile, and how many models, backends, keys, tokens and policy files it holds, and the warnings. No secret and no file content |
| `POST /admin/v1/config/reload` | Reads the configuration file and the policy directory again, as `SIGHUP` does. Invalid, or needing a restart (profile, database, audit, workers, outbox, OIDC connection settings): `422 invalid_configuration` or `409 restart_required`, and the running revision stays |
| `GET /admin/v1/changes` | What the administrators changed, newest first, `limit` and `before` to page |

## Every change is recorded first

A call that changes something (today: a reload, by the API or by `SIGHUP`, which is recorded as actor `sighup`) is recorded **before** it takes effect, in one transaction:

- a row of `admin_changes`: when, who (the token id), which action, which revision it leads to, the outcome (`applied`, or `rejected` for an attempt that was refused), the request id and the caller's address, and a few facts (`previous` revision);
- an `admin_change` event in the outbox, with the same content, which the audit chain takes in like a decision record ([AUDIT.md](AUDIT.md)).

If the record cannot be written the call answers `503 audit_unavailable` and nothing changes. A refused attempt is recorded too, so that an administrator probing the limits leaves a trace. Reading calls are not recorded.

The record never holds a secret, a token, or any request content. The chain makes the history tamper-evident: `tavian verify-audit` finds an edited or removed record, and with anchored seals even a rewritten chain. The retention pruner never removes these events.

## Metrics

`tavian_admin_requests_total{action, outcome}` counts calls that change something (`applied`, `rejected`, `audit_unavailable`, `failed`) and refused credentials (`unauthenticated`). The administrator's identity is never a label.
