# bb-plugin-security-guidance

Pattern-matched security warnings for code the agent writes, behind an
episteme-shaped verdict. Port of the Hermes `security-guidance` plugin to BB's
plugin model.

BB has no `transform_tool_result` hook (the Hermes plugin's delivery
mechanism), so this port exposes the same 25-rule pattern engine as native
agent tools instead:

- **`gate_check`** — judge content before it is written. Returns **STOP**,
  **REVISE**, **PROCEED** or **PROCEED_DOCUMENTED**, with a certainty, the
  evidence, and the counterfactual: what would change the verdict. High-tier
  findings (arbitrary code execution, shell injection) stop; exploitable sinks
  (XSS, TLS, crypto mode) ask for a revision; advisory findings pass with a
  note. A `justification` turns a STOP into PROCEED_DOCUMENTED without hiding
  the finding.
- **`security_scan`** — the raw scan. Returns a warning block for every match.
  The agent calls this on content it is about to write, reads the warnings,
  and either fixes the code or briefly documents why the construct is safe.

## The verdict model

Each of the 25 rules carries a tier and a fix in `gate.ts`; an unranked rule
fails closed, and a test proves every rule is ranked. Certainty is per-rule:
a literal match (`pickle.load`, `shell=True`) is high, while a rule that has
to read a call's arguments (`yaml.load`, `torch.load`, `numpy.load`, `eval`)
reports medium, because its danger depends on those arguments.

A gate that cannot refuse has to be honest about it: BB gives plugins no
pre-tool-call hook, so `gate_check` is a decision the agent is asked to
obtain and honour, not enforcement. Every verdict says so.

Same warn-by-default philosophy as the Hermes original: pattern matching has
a non-trivial false-positive rate, so the tools inform rather than refuse.

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

## Development

```sh
npm install
npm run build      # tsc typecheck (noEmit)
npm test           # behaviour tests for the pattern set
npm run bundle     # bb plugin build → dist/
```

## Attribution and licensing

- `patterns.ts` is a faithful port of the pattern data from
  [`anthropics/claude-plugins-official`](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance/hooks)
  (commit `fce198c`, 2026-11-23), licensed under the
  [Apache License 2.0](./LICENSE). See [NOTICE](./NOTICE) for the full
  attribution. The port includes upstream's argument-aware matching: a call's
  own arguments are read across lines and nested brackets, so a `SafeLoader`
  or `weights_only=True` anywhere inside the call suppresses the warning.
- `server.ts`, `package.json`, and `README.md` are original work by
  prismatic7, MIT-licensed.
