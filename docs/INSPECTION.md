# Content inspection

_What the gateway looks for in a request today, how it decides, and how to tune it. For the design and the threat model see [SECURITY.md](SECURITY.md#content-inspection)._

Inspection is **on by default** and **observe-only**: findings are recorded in the usage event and counted in metrics, but no finding changes what happens to a request yet. Actions on findings (block, redact, restrict destinations) and classification come with the policy engine ([roadmap](ROADMAP.md)). What is enforced today is the fail-closed behaviour described below.

## What is inspected

**Every string value in the request body**, wherever it is: message contents, `name`, tool-call arguments, `prediction`, tool definitions, `metadata`, and any extra parameter a backend such as vLLM accepts (`documents`, `chat_template_kwargs`, …). Anything the gateway forwards is content that leaves it, so nothing is skipped because a field is unknown. JSON escapes are decoded first, and all duplicate keys are seen, whichever one a backend would keep.

Not inspected: object **keys**, and the **response** (response inspection is M4).

Before detectors run, text is normalized: invisible format characters (zero-width spaces, soft hyphens, bidi controls) are dropped, exotic spaces become plain spaces, full-width look-alikes become ASCII, and invalid UTF-8 is replaced. Offsets in findings refer to the normalized text.

## Fail closed

A request is **refused**, never served uninspected, when:

| Situation | Response | Code |
|---|---|---|
| A detector errors, panics, returns an impossible finding, or the whole inspection exceeds `inspection.budget` | 503 | `inspection_failed` |
| The request has a non-text content part: image, audio, file, or any type the gateway does not know | 400 | `multimodal_not_inspectable` |
| The request has more than 20 000 strings or is nested deeper than 64 levels | 400 | `request_too_complex` |

A refused request leaves a decision record carrying the reason code (`MULTIMODAL_NOT_INSPECTABLE`, `REQUEST_TOO_COMPLEX`, `INSPECTION_FAILED`), and the error body names its `decision_id`. Turning inspection off (`inspection.enabled: false`) is an explicit choice: requests are then served without being inspected, usage events and decision records say `skipped`, and the gateway logs a warning at startup.

## Built-in detectors

| Detector | Subtype | Recognises | Not covered |
|---|---|---|---|
| `pii.email` | `email` | `local@domain.tld` | Addresses with quoted local parts or IP-literal domains |
| `pii.iban` | `iban` | IBANs of 78 countries: length per country, groups of four separated by a space or hyphen, mod-97 checksum | Other separators |
| `pii.card` | `payment_card` | 13–19 digits (single space or hyphen between groups) with a Visa / Mastercard / Amex / Discover / UnionPay / JCB / Diners prefix and a valid Luhn checksum | Schemes outside that list |
| `pii.nir` | `nir` | French social security number (15 characters, Corsica 2A/2B, key checked), single spaces or dots tolerated | Other countries' national IDs |
| `pii.phone` | `phone` | International (`+` and 8–15 digits) and French national (`0X` + 8 digits) numbers | National formats of other countries |
| `pii.ip` | `ipv4` | Dotted-quad IPv4 addresses that are not part of a longer dotted number | IPv6, host names |
| `secret.token` | `aws_access_key`, `github_token`, `gitlab_token`, `slack_token`, `stripe_key`, `google_api_key`, `private_key`, `jwt` | Credentials with a well-known prefix; PEM private key headers | Providers not listed; generic high-entropy strings |
| `secret.credential` | `credential` | The value in `password = …`, `"api_key": "…"`, `client_secret: …` (keywords: password, passwd, pwd, secret, token, api_key, apikey, access_key, private_key, client_secret, credential). Values must be 8+ characters mixing letters and digits or symbols | Values written in prose |

Checksums and prefixes keep false positives down, but detection stays **best-effort**: a value split across messages, written in words, or encoded is not found.

Severity: IBAN, card and NIR `high`; secrets `critical` (`high` for Google keys, JWT and credential assignments); e-mail and phone `medium`; IP `low`.

## Your own detectors (L1)

Everything is in the configuration (so that the revision identifies exactly what ran). No external files.

```yaml
inspection:
  disable: [pii.ip]                    # built-in detectors that are too noisy for your data
  dictionaries:
    - name: codenames                  # becomes the finding subtype; custom.<name> is the detector
      severity: high                   # low | medium (default) | high | critical
      terms: ["Projet Aurore", "Falcon"]
    - name: markings
      terms: ["CONFIDENTIEL", "DIFFUSION RESTREINTE"]
  patterns:
    - name: contract-ref
      regex: 'CTR-\d{6}'               # RE2 syntax, linear time
```

- Dictionary matching ignores case using simple Unicode lower-casing (`société générale` matches `SOCIÉTÉ GÉNÉRALE`; special cases such as `ß` vs `SS` are not folded) unless `case_sensitive: true`, and by default only matches whole words (`whole_word: false` to match inside words). Overlapping terms report the longest (`Projet Aurore` hides `Aurore`). Terms need at least 2 characters.
- Limits: 50 dictionaries of up to 10 000 terms (128 bytes each), 100 patterns of up to 1 000 bytes. A regex that can match the empty string is refused.
- A detector's version changes whenever its terms or settings do, and usage events record the versions that ran.
- Terms and patterns are applied to every string of every request; large dictionaries and patterns cost time, which counts against `inspection.budget`.

## Findings and what is kept

A finding carries: detector, type, subtype, severity, confidence, and a location (message index, field name from a fixed vocabulary, part index, byte offsets). It also carries a **fingerprint**: `HMAC-SHA256(key, subtype ‖ value)` truncated to 128 bits, so the same value can be correlated across requests without being recoverable. **The matched text is never stored**, logged, or put in a metric label or an error message; a canary test checks the logs, metrics, events and error bodies on every path.

The usage event and the decision record both hold a **summary**: status, finding count, count per `type.subtype`, detector versions, duration. The decision record also holds the **findings themselves** (detector, type, subtype, severity, confidence, location, fingerprint), capped at 200 per request with `findings_truncated` set when there are more; the summary counts stay complete.

Set `inspection.fingerprint_key_env` to the name of an environment variable holding a secret (16+ bytes) to make fingerprints stable across restarts and replicas. Without it a random key is generated at startup and the gateway logs a warning: fingerprints then only correlate within one run. Changing the key changes every fingerprint.

## Time budget and performance

The whole inspection of a request must finish within `inspection.budget` (default 50 ms), otherwise the request is refused. Measured on a development machine (12 threads), full built-in set, ordinary prose, 8 detectors:

| Prompt size | Time |
|---|---|
| 1 KB | ~25 µs |
| 10 KB | ~0.15 ms |
| 100 KB | ~1.4 ms |

That is about 70 MB/s, so a prompt of a few MB can exceed the default budget; raise `budget` (up to 10 s) if your users send very large contexts. Run `make bench` to measure on your hardware. The budget bounds latency, not CPU: a detector cannot be interrupted mid-scan, so after a timeout it finishes in the background (all built-in detectors run in time linear in the input, and `limits.max_inflight` bounds how many requests exist).

## Metrics

`tavian_inspections_total{status}` (`ok`, `skipped`, `failed`), `tavian_inspection_findings_total{type,subtype}`, `tavian_inspection_duration_seconds`. Labels come from a fixed set and from the names you give your own detectors, never from content.
