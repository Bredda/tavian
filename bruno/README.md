# Bruno collection

Open this folder with [Bruno](https://www.usebruno.com/) (File → Open Collection), pick an environment, and send the requests.

| Folder | What it is |
| --- | --- |
| `demo-0.2.0/` | The scenario of [`scripts/demo-e2e.sh`](../scripts/demo-e2e.sh) one request at a time, with assertions: ordinary data, an IBAN that stays on-prem, refusals, masking, a blocked secret, a shadow policy. |
| `api/admin/` | The admin listener: health, readiness, metrics. |
| `api/data-plane/` | The OpenAI-compatible API: models, chat completions (also streaming, and with a declared classification). |

| Environment | For |
| --- | --- |
| `demo-0.2.0` | The demo stack (`make demo`, or `KEEP=1 scripts/demo-e2e.sh`). Holds the public demo keys (`demoKey`, `financeKey`, `apiKey`) and the model `demo-chat`. |
| `local` | A gateway you run yourself (ports 8080 and 9090, model `llama-70b` of `configs/tavian.example.yaml`). `apiKey` is a secret: Bruno asks for it, it is never written to the file. |

With the CLI (`npm i -g @usebruno/cli`), from this folder:

```bash
bru run -r --env demo-0.2.0                                   # everything
bru run demo-0.2.0 -r --env demo-0.2.0                        # the scenario only
bru run api -r --env local --env-var apiKey=tav_...           # the API against your gateway
```

The demo keys are public and for the demo only. The checks that need the database (the decision records) or the `verify-audit` command are given as commands in the docs of the requests concerned.
