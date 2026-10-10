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
| `GET /admin/v1/config/revisions` | The revisions the gateway has run, newest first, with the active one marked |
| `GET /admin/v1/config/revisions/{id}` | One revision with its configuration YAML and policy files (`active` stands for the active one) |
| `GET /admin/v1/config/diff?from=&to=` | A unified diff per file between two revisions (`to` defaults to the active one) |
| `POST /admin/v1/config/validate` | Checks a configuration (`{config, policies}`) like `tavian validate` does, and says whether it could replace the running one. Changes and records nothing |
| `POST /admin/v1/config/apply` | Makes a configuration (`{config, policies, base}`) the active one |
| `POST /admin/v1/config/rollback` | Makes an earlier revision (`{revision, base}`) the active one again |
| `POST /admin/v1/config/reload` | Reads the configuration file and the policy directory again, as `SIGHUP` does |
| `GET /admin/v1/changes` | What the administrators changed, newest first, `limit` and `before` to page |

## Revisions

A **revision** is a configuration as the gateway ran it: the YAML and the policy files, identified by a 12-character hash of both. Each one is kept, and every usage event and decision record names the revision it was made under. One revision is **active**: the database says which.

`apply` takes a `config` and its `policies` (the files `policy.dir` points to; the directory itself is not read) and a `base`, the revision you believe is active. The change is made only if the database still says so, otherwise the call answers `409 conflict` and nothing happens: two administrators cannot overwrite each other, and a change made from a stale view is refused. The same holds for `rollback`.

What a change is refused for, with nothing changed and the attempt recorded:

- the configuration does not compile (`422 invalid_configuration`, with what is wrong);
- it changes a setting that cannot change while the gateway runs (`409 restart_required`): the profile, `database`, `audit`, `workers`, `outbox` and the OIDC connection (its mappings can change). Edit the configuration file and restart for those;
- it lists no admin token (`422 no_admin_token`): nobody could use the API afterwards;
- `rollback` only: the revision holds an API key or admin token that the running configuration does not (`409 credentials_would_return`). It may have been revoked since, and a rollback must not bring it back. Apply a configuration that lists exactly the credentials you want instead.

**At start** the gateway follows the configuration file if it changed since the last start (the operator edited it, which is also how to get in again after losing every token), and otherwise the active revision, so that what the API applied survives a restart. Either way the choice is recorded (`config.bootstrap`, actor `startup`). If the active revision cannot run with the file the gateway started with, it refuses to start and says why.

`SIGHUP` and `POST /config/reload` read the file again and make the result the active revision.

**Limits.** With several gateways on one database, a change is made on the gateway that received it; the others pick the active revision up when they restart. Making them follow is planned. The file on disk is not rewritten by the API: after an `apply`, the file and the active revision differ until the file is edited or `reload` reads it again.

## The command line

`tavian config` is the same API from a terminal. It reads the token from `TAVIAN_ADMIN_TOKEN` (never from a flag, which would show in the process list) and the server from `-server` or `TAVIAN_ADMIN_URL` (default `http://127.0.0.1:9090`). It warns when the token would cross a network without TLS, and it never follows a redirect, since the token would go with it. `-json` prints the answer of the API as it is.

```bash
export TAVIAN_ADMIN_TOKEN=tavadm_...
tavian config list                              # revisions, newest first; the active one is marked
tavian config show [REVISION]                   # the active one by default
tavian config export -o ./conf                  # conf/tavian.yaml and conf/policies/*.yaml
# edit them, then:
tavian config diff -config conf/tavian.yaml -policies conf/policies      # against the active revision
tavian config validate -config conf/tavian.yaml -policies conf/policies  # same checks as `tavian validate`, and can the gateway take it?
tavian config apply -config conf/tavian.yaml -policies conf/policies -dry-run
tavian config apply -config conf/tavian.yaml -policies conf/policies
tavian config rollback -revision 4b7e1c0a9d32
tavian config reload                            # read the gateway's own file again
tavian config history                           # who changed what
```

`apply` asks the gateway which revision is active and sends it as `base`, so a change made by someone else in between is refused, not overwritten; `-base` pins it. Without `-policies` the policy files are those of `policy.dir` of the configuration file, read relative to it, as the gateway reads them. `validate` and `apply -dry-run` exit with 1 when the configuration is invalid or cannot be applied; a refusal of `apply` or `rollback` prints its code and reason and exits with 1. An exported revision applied as it is changes nothing: the revision is a hash of the bytes. `export` does not write into a directory that has files in it without `-force`, and never writes a policy file whose name could leave the directory.

## Every change is recorded first

A call that changes something (`apply`, `rollback`, `reload`, and the choice made at start) is recorded **before** it takes effect, in one transaction:

- a row of `admin_changes`: when, who (the token id), which action, which revision it leads to, the outcome (`applied`, or `rejected` for an attempt that was refused), the request id and the caller's address, and a few facts (`previous` revision);
- an `admin_change` event in the outbox, with the same content, which the audit chain takes in like a decision record ([AUDIT.md](AUDIT.md)).

If the record cannot be written the call answers `503 audit_unavailable` and nothing changes. A refused attempt is recorded too, so that an administrator probing the limits leaves a trace. Reading calls are not recorded.

`SIGHUP` is recorded as actor `sighup`. The record never holds a secret, a token, or any request content. The chain makes the history tamper-evident: `tavian verify-audit` finds an edited or removed record, and with anchored seals even a rewritten chain. The retention pruner never removes these events.

## Metrics

`tavian_admin_requests_total{action, outcome}` counts calls that change something (`applied`, `rejected`, `audit_unavailable`, `failed`) and refused credentials (`unauthenticated`). The administrator's identity is never a label.
