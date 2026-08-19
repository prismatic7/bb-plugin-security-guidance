# bb-plugin-security-guidance

Pattern-matched security warnings for code the agent writes. Port of the
Hermes `security-guidance` plugin to BB's plugin model.

BB has no `transform_tool_result` hook (the Hermes plugin's delivery
mechanism), so this port exposes the same 25-rule pattern engine as a native
agent tool instead:

- **`security_scan`** — scan content (and an optional path) for known
  dangerous code patterns. Returns a warning block for every match. The
  agent calls this on content it is about to write, reads the warnings, and
  either fixes the code or briefly documents why the construct is safe.

Same warn-by-default philosophy as the Hermes original: the scan is
advisory, not blocking. Pattern matching has a non-trivial false-positive
rate, so the tool returns warnings rather than refusing anything.

## Coverage (25 rules)

The pattern set is forked verbatim from Anthropic's `claude-plugins-official`
under Apache-2.0. Categories:

| Category | Rules |
|---|---|
| Unsafe deserialization | `pickle.load`, `cPickle/cloudpickle/dill.load`, `marshal.loads`, `shelve.open`, `yaml.load`, `yaml.unsafe_load`, `torch.load` (without `weights_only=True`), `joblib.load`, `pandas.read_pickle`, `numpy.load(allow_pickle=True)` |
| Command injection | `os.system`, `subprocess(..., shell=True)`, JS `child_process.exec`, Go `exec.Command("sh"...)` |
| Code injection | `eval(`, JS `new Function(...)` |
| XSS sinks | `.innerHTML =`, `.outerHTML =`, `.insertAdjacentHTML(`, `document.write`, React `dangerouslySetInnerHTML` |
| Crypto footguns | AES ECB mode, Node `crypto.createCipher` (no IV), TLS verification disabled (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, ...) |
| XXE | `xml.etree`, `minidom`, `xml.sax` without `defusedxml` |
| Supply chain | `<script src="https://..."` without `integrity=` SRI hash |
| CI/CD injection | GitHub Actions workflow files using `${{ github.event.* }}` in `run:` |

Each rule carries a per-extension `pathFilter` — Python-only rules skip
`.js`, JS rules skip `.py`, all rules skip `.md/.txt/.rst/.json/.yaml`.
Lookbehind assertions exclude method calls (so `model.eval()` and
`redis.eval()` don't trip the `eval(` rule). False-positive rate is
mediocre but tolerable; the tool is warn-by-default precisely because of
that.

## Tool

### `security_scan`

```
security_scan(content: string, path?: string)
```

Scans content for known-dangerous patterns. Returns a warning block for
every match, or a clean message if none match. Call this on content you are
about to write to a file.

## Settings

| Setting | Default | Description |
|---|---|---|
| `mode` | `warn` | `warn`: returns warnings for the agent to act on. `block`: returns a refusal message when patterns match. |

## Attribution and licensing

- `patterns.ts` is a faithful port of the pattern data from
  [`anthropics/claude-plugins-official`](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance/hooks)
  (commit `0bde168`, 2026-05-26), licensed under the
  [Apache License 2.0](./LICENSE). See [NOTICE](./NOTICE) for the full
  attribution.
- `server.ts`, `package.json`, and `README.md` are original work by
  prismatic7, MIT-licensed.
