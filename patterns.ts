// security-guidance patterns — ported from Anthropic's claude-plugins-official
// (plugins/security-guidance/hooks/patterns.py, commit fce198c, 2026-11-23),
// Apache-2.0. See LICENSE and NOTICE.
//
// Each rule matches content (and optionally a path) and carries a reminder.
// Ported faithfully from the Python original; regexes are JS-compatible
// equivalents of the Python patterns. Where the original reads a call's own
// arguments (rather than one line), the rule carries a `test` that walks the
// call the same way — see callArgs().

export interface SecurityRule {
  ruleName: string;
  reminder: string;
  /** Path filter: rule only fires when this returns true. */
  pathFilter?: (path: string) => boolean;
  /** Path check: rule fires purely on path match (no content scan). */
  pathCheck?: (path: string) => boolean;
  /** Literal substrings (fast path). */
  substrings?: string[];
  /** Regex (slow path). */
  regex?: RegExp;
  /** Argument-aware matcher; used instead of substrings/regex when present. */
  test?: (content: string) => boolean;
}

const JS_EXTS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"];
const PY_EXTS = [".py", ".pyi", ".ipynb"];
const DOC_EXTS = [".md", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml"];

const endsWithAny = (p: string, exts: string[]) => exts.some((e) => p.endsWith(e));

// ─── Call-argument reader ─────────────────────────────────────────────
//
// Port of upstream's _call_args(): read a call's arguments from just after its
// "(", stepping over strings, comments and nested brackets as units, across
// lines. Text that follows the call is not read as an argument of it, and text
// inside a nested call is not mistaken for this one's. Every scan is bounded.

const MAX_ARGS = 4000;

/** Arguments of the call whose "(" sits at `open`, or "" if it never closes. */
export function callArgs(content: string, open: number): string {
  let depth = 1;
  let i = open + 1;
  const limit = Math.min(content.length, open + MAX_ARGS);
  while (i < limit) {
    const ch = content[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      i++;
      while (i < limit) {
        if (content[i] === "\\") {
          i += 2;
          continue;
        }
        if (content[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (ch === "#") {
      while (i < limit && content[i] !== "\n") i++;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return content.slice(open + 1, i);
    }
    i++;
  }
  return "";
}

/** True when the `eval(` at `evalIndex` is Playwright/Puppeteer page.$eval:
 *  a selector string, then a function. Nothing is evaluated from a string, so
 *  upstream leaves it out. Mirrors _page_function_call(). */
export function isPageFunctionEval(content: string, evalIndex: number): boolean {
  if (evalIndex === 0 || content[evalIndex - 1] !== "$") return false;
  const args = callArgs(content, evalIndex + 4).trimStart();
  const selector = /^(?:"[^"\\\n]{0,300}"|'[^'\\\n]{0,300}'|`[^`$\\]{0,300}`)\s*,\s*/;
  const m = selector.exec(args);
  if (!m) return false;
  const rest = args.slice(m[0].length);
  return /^(?:async\s+)?(?:function\b|(?:[\w$]{1,60}|\([^()]{0,200}\))\s{0,20}(?::[^=\n]{0,60})?=>)/.test(
    rest
  );
}

/** Every match of `re` in `content`, as {index, text} pairs. */
function findAll(content: string, re: RegExp): Array<{ index: number; text: string }> {
  const out: Array<{ index: number; text: string }> = [];
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m: RegExpExecArray | null;
  while ((m = g.exec(content)) !== null) {
    out.push({ index: m.index, text: m[0] });
    if (m.index === g.lastIndex) g.lastIndex++;
  }
  return out;
}

const UNSAFE_DESERIALIZATION_REMINDER =
  "⚠️ Security Warning: Loading pickle data (or equivalents: cPickle, cloudpickle, dill, the standard library's .pyc serializer and its load()/loads(), shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.\n\n" +
  "For simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.\n\n" +
  "If this is safe or is explicitly needed, briefly document that in a comment before continuing.";

const UNSAFE_YAML_LOAD_REMINDER =
  "⚠️ Security Warning: yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.\n\n" +
  "Use yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types.";

const UNSAFE_TORCH_LOAD_REMINDER =
  "⚠️ Security Warning: torch.load() defaults to weights_only=False, which unpickles arbitrary Python objects and allows arbitrary code execution.\n\n" +
  "If the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1).";

export const SECURITY_PATTERNS: SecurityRule[] = [
  {
    ruleName: "github_actions_workflow",
    pathCheck: (p) =>
      p.includes(".github/workflows/") && (p.endsWith(".yml") || p.endsWith(".yaml")),
    reminder:
      "⚠️ Security Warning: You are editing a GitHub Actions workflow file. Be aware of these security risks:\n\n" +
      "1. **Command Injection**: Never use untrusted input (like issue titles, PR descriptions, commit messages) directly in run: commands without proper escaping\n" +
      "2. **Use environment variables**: Instead of ${{ github.event.issue.title }}, use env: with proper quoting\n" +
      "3. **Review the guide**: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/\n\n" +
      "Example of UNSAFE pattern to avoid:\nrun: echo \"${{ github.event.issue.title }}\"\n\n" +
      "Example of SAFE pattern:\nenv:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo \"$TITLE\"\n\n" +
      "Other risky inputs to be careful with:\n" +
      "- github.event.issue.body\n- github.event.pull_request.title\n- github.event.pull_request.body\n- github.event.comment.body\n- github.event.review.body\n- github.event.review_comment.body\n- github.event.pages.*.page_name\n- github.event.commits.*.message\n- github.event.head_commit.message\n- github.event.head_commit.author.email\n- github.event.head_commit.author.name\n- github.event.commits.*.author.email\n- github.event.commits.*.author.name\n- github.event.pull_request.head.ref\n- github.event.pull_request.head.label\n- github.event.pull_request.head.repo.default_branch\n- github.event.client_payload.* (repository_dispatch events — attacker can set any field)\n\n" +
      "4. **Ref injection**: Never use untrusted input in `ref:` parameters of `actions/checkout`. For `client_payload.pr_number`, validate it matches `^[0-9]+$` before using in `ref: refs/pull/${{ ... }}/head`\n- github.head_ref",
  },
  {
    ruleName: "child_process_exec",
    pathFilter: (p) => endsWithAny(p, JS_EXTS),
    substrings: ["child_process.exec", "execSync("],
    regex: /(?<![a-zA-Z0-9_.])exec\(/,
    reminder:
      "⚠️ Security Warning: Using child_process.exec() can lead to command injection vulnerabilities.\n\n" +
      "exec() runs the command string through a shell, so any user input interpolated into it can inject arbitrary commands. Prefer child_process.execFile() (or spawn()) with an argument array instead of building a shell string.\n\n" +
      "Instead of:\n  exec(`command ${userInput}`)\n\nUse:\n  import { execFile } from 'node:child_process'\n  execFile('command', [userInput], callback)\n\n" +
      "Why execFile/spawn with an argument array is safer:\n- No shell is involved, so shell metacharacters in arguments are not interpreted\n- Arguments are passed directly to the program rather than interpolated into a command string\n\n" +
      "Only use exec() if you absolutely need shell features and the input is guaranteed to be safe.",
  },
  {
    ruleName: "new_function_injection",
    // JS-only construct: gate to JS/TS files so docs/.md and other prose
    // mentioning "new Function" don't trip the warning.
    pathFilter: (p) => endsWithAny(p, JS_EXTS),
    // The whole word: `new FunctionRegistry()` is another class. The two names
    // code gives to Function itself still count.
    regex: /new Function(?:Constructor|Ctor)?(?![\w$])/,
    reminder:
      "⚠️ Security Warning: Using new Function() with string interpolation is a CODE INJECTION vulnerability. If any variable is concatenated or interpolated into the function body string, an attacker controlling that variable can execute arbitrary code. Use safe alternatives: for property access use obj[key] or array.reduce((o, k) => o[k], root); for computation use a safe expression parser. NEVER interpolate untrusted strings into new Function() bodies.",
  },
  {
    ruleName: "eval_injection",
    // Lookbehind excludes `.` so method calls like PyTorch model.eval(),
    // redis.eval(), spec.eval() don't match. Playwright's page.$eval('selector',
    // function) is left out too. Skip doc/prose files.
    pathFilter: (p) => !endsWithAny(p, DOC_EXTS),
    test: (content) =>
      findAll(content, /(?<![a-zA-Z0-9_.])eval\(/).some(
        (m) => !isPageFunctionEval(content, m.index)
      ),
    reminder:
      "⚠️ Security Warning: eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data, ast.literal_eval() for Python literals, or a safe expression parser. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
  },
  {
    ruleName: "react_dangerously_set_html",
    // JS/TS-only (React); gate so .md docs / .py / .go files don't trip.
    pathFilter: (p) => endsWithAny(p, JS_EXTS),
    substrings: ["dangerouslySetInnerHTML"],
    reminder:
      "⚠️ Security Warning: dangerouslySetInnerHTML can lead to XSS vulnerabilities if used with untrusted content. Ensure all content is properly sanitized using an HTML sanitizer library like DOMPurify, or use safe alternatives.",
  },
  {
    ruleName: "document_write_xss",
    // Browser DOM API: only meaningful in JS/TS source.
    pathFilter: (p) => endsWithAny(p, JS_EXTS),
    substrings: ["document.write"],
    reminder:
      "⚠️ Security Warning: document.write() can be exploited for XSS attacks and has performance issues. Use DOM manipulation methods like createElement() and appendChild() instead.",
  },
  {
    ruleName: "innerHTML_xss",
    // Browser DOM API: only meaningful in JS/TS source. An assignment, not a
    // `==` or `===` comparison.
    pathFilter: (p) => endsWithAny(p, JS_EXTS),
    regex: /\.innerHTML ?=(?!=)/,
    reminder:
      "⚠️ Security Warning: Setting innerHTML with untrusted content can lead to XSS vulnerabilities. Use textContent for plain text or safe DOM methods for HTML content. If you need HTML support, consider using an HTML sanitizer library such as DOMPurify.",
  },
  {
    ruleName: "pickle_deserialization",
    pathFilter: (p) => endsWithAny(p, PY_EXTS),
    regex: /(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b|(?<![a-zA-Z0-9_])pkl_load\(/,
    reminder: UNSAFE_DESERIALIZATION_REMINDER,
  },
  {
    ruleName: "os_system_injection",
    pathFilter: (p) => endsWithAny(p, PY_EXTS),
    regex: /\bos\.system\s*\(/,
    substrings: ["from os import system"],
    reminder:
      "⚠️ Security Warning: os.system() runs a shell and is a command-injection sink. Use subprocess.run([...]) with a list of arguments instead. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
  },
  {
    ruleName: "python_subprocess_shell",
    regex: /subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True/,
    reminder:
      "⚠️ Security Warning: Using subprocess with shell=True enables command injection.\n\n" +
      "UNSAFE:\n  subprocess.run(f\"ls {user_input}\", shell=True)\n  subprocess.call(\"grep \" + pattern, shell=True)\n\n" +
      "SAFE - pass arguments as a list without shell:\n  subprocess.run([\"ls\", user_input])\n  subprocess.call([\"grep\", pattern])\n\n" +
      "When arguments are passed as a list without shell=True, special characters cannot be interpreted as shell metacharacters.",
  },
  {
    ruleName: "go_exec_shell_injection",
    regex: /exec\.Command\(\s*"(?:sh|bash|\/bin\/sh|\/bin\/bash)"/,
    reminder:
      "⚠️ Security Warning: Using exec.Command with a shell interpreter (sh/bash) enables command injection.\n\n" +
      "UNSAFE:\n  exec.Command(\"sh\", \"-c\", \"ping -c 1 \" + host)\n  exec.Command(\"bash\", \"-c\", fmt.Sprintf(\"df -h %s\", path))\n\n" +
      "SAFE - pass arguments directly without a shell:\n  exec.Command(\"ping\", \"-c\", \"1\", host)\n  exec.Command(\"df\", \"-h\", path)\n\n" +
      "When arguments are passed directly (not through a shell), special characters in user input cannot be interpreted as shell metacharacters. This prevents command injection entirely.\n\n" +
      "Additionally, validate user inputs:\n- For hostnames/IPs: use net.ParseIP() or a hostname regex\n- For file paths: use filepath.Clean() and verify the result is within an allowed directory\n- For numeric values: parse to int/float first",
  },
  {
    ruleName: "unsafe_yaml_load",
    // Suppressed by SafeLoader or CSafeLoader among the call's own arguments.
    test: (content) =>
      findAll(content, /\byaml\.load\s*\(/).some((m) => {
        const args = callArgs(content, m.index + m.text.length - 1);
        const firstLine = args.split("\n")[0] ?? "";
        return !(/\bC?Safe\b/.test(firstLine.slice(0, 80)) || /\bC?SafeLoader\b/.test(args));
      }),
    reminder: UNSAFE_YAML_LOAD_REMINDER,
  },
  {
    ruleName: "node_createcipher_no_iv",
    regex: /\bcrypto\.(createCipher|createDecipher)\b/,
    reminder:
      "⚠️ Security Warning: Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22 and derives the key insecurely (no IV, MD5-based KDF).",
  },
  {
    ruleName: "aes_ecb_mode",
    regex: /\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|["']aes-\d+-ecb["']/,
    reminder:
      "⚠️ Security Warning: Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure (identical blocks encrypt to identical ciphertext).",
  },
  {
    ruleName: "tls_verification_disabled",
    regex:
      /\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|ssl\._create_unverified_context|check_hostname\s*=\s*False/,
    reminder:
      "⚠️ Security Warning: Don't disable TLS verification. This allows MITM attacks. For self-signed dev certs, add the CA to your trust store or use a properly-issued cert.",
  },
  {
    ruleName: "marshal_loads",
    regex: /\bmarshal\.loads?\s*\(/,
    reminder: UNSAFE_DESERIALIZATION_REMINDER,
  },
  {
    ruleName: "shelve_open",
    regex: /\bshelve\.open\s*\(/,
    reminder: UNSAFE_DESERIALIZATION_REMINDER,
  },
  {
    ruleName: "xml_unsafe_parse",
    regex:
      /\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b/,
    reminder:
      "⚠️ Security Warning: Use defusedxml.ElementTree. Python's stdlib XML parsers are vulnerable to XXE (external entity) and billion-laughs attacks by default.",
  },
  {
    ruleName: "pickle_variants_load",
    regex: /\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\(/,
    reminder: UNSAFE_DESERIALIZATION_REMINDER,
  },
  {
    ruleName: "outerHTML_xss",
    // Browser DOM API: only meaningful in JS/TS source.
    pathFilter: (p) => endsWithAny(p, JS_EXTS),
    regex: /\.outerHTML ?=(?!=)/,
    reminder:
      "⚠️ Security Warning: Use textContent or sanitize with DOMPurify. outerHTML assignment is an XSS sink equivalent to innerHTML.",
  },
  {
    ruleName: "insertAdjacentHTML_xss",
    // Browser DOM API: only meaningful in JS/TS source.
    pathFilter: (p) => endsWithAny(p, JS_EXTS),
    substrings: [".insertAdjacentHTML("],
    reminder:
      "⚠️ Security Warning: Use insertAdjacentText() or sanitize with DOMPurify. insertAdjacentHTML is an XSS sink.",
  },
  {
    ruleName: "script_src_without_sri",
    regex:
      /<script\s+(?![^>]{0,400}integrity\s*=)[^>]{0,200}src\s*=\s*["'](?:https?:)?\/\/[^"']{1,300}["'][^>]{0,100}>/,
    reminder:
      '⚠️ Security Warning: Add integrity="sha384-..." crossorigin="anonymous" to external script tags. Loading scripts without Subresource Integrity exposes you to CDN compromise.',
  },
  {
    ruleName: "torch_unsafe_load",
    // Suppressed by weights_only=True among the call's own arguments.
    // weights_only=False still triggers.
    test: (content) =>
      findAll(content, /(?:\btorch\.load|\.torch_load)\s*\(/).some((m) => {
        const args = callArgs(content, m.index + m.text.length - 1);
        const firstLine = args.split("\n")[0] ?? "";
        return !(
          /weights_only\s*=\s*True/.test(firstLine.slice(0, 200)) ||
          /\bweights_only\s*=\s*True/.test(args)
        );
      }),
    reminder: UNSAFE_TORCH_LOAD_REMINDER,
  },
  {
    ruleName: "yaml_unsafe_load_variants",
    regex: /(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\(/,
    reminder: UNSAFE_YAML_LOAD_REMINDER,
  },
  {
    ruleName: "pickle_wrapper_load",
    // Library APIs that unpickle without saying "pickle". numpy.load only triggers
    // when allow_pickle=True is explicit (defaults to False since numpy 1.16.3).
    test: (content) =>
      /\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(/.test(content) ||
      findAll(content, /\b(?:np|numpy)\.load\s*\(/).some((m) => {
        const args = callArgs(content, m.index + m.text.length - 1);
        const firstLine = args.split("\n")[0] ?? "";
        return (
          /allow_pickle\s*=\s*True/.test(firstLine.slice(0, 200)) ||
          /\ballow_pickle\s*=\s*True/.test(args)
        );
      }),
    reminder: UNSAFE_DESERIALIZATION_REMINDER,
  },
];

// ─── Scanning ─────────────────────────────────────────────────────────

const MAX_SCAN_BYTES = 256 * 1024;

export interface Finding {
  ruleName: string;
  reminder: string;
}

/** Scan content (optionally with a path) for dangerous patterns. */
export function scanContent(path: string, content: string): Finding[] {
  if (!content || content.length > MAX_SCAN_BYTES) return [];
  const hits: Finding[] = [];
  for (const rule of SECURITY_PATTERNS) {
    // path_check: rule fires purely on path match.
    if (rule.pathCheck) {
      try {
        if (rule.pathCheck(path || "")) hits.push({ ruleName: rule.ruleName, reminder: rule.reminder });
      } catch {
        // ignore
      }
      continue;
    }
    // path_filter: skip when it returns false.
    if (rule.pathFilter) {
      try {
        if (!rule.pathFilter(path || "")) continue;
      } catch {
        continue;
      }
    }
    let matched = false;
    if (rule.test) {
      try {
        matched = rule.test(content);
      } catch {
        matched = false;
      }
    } else if (rule.substrings) {
      for (const sub of rule.substrings) {
        if (content.includes(sub)) {
          matched = true;
          break;
        }
      }
    }
    if (!matched && rule.regex) {
      if (rule.regex.test(content)) matched = true;
    }
    if (matched) hits.push({ ruleName: rule.ruleName, reminder: rule.reminder });
  }
  return hits;
}

/** Render findings into a Markdown warning block. */
export function formatWarningBlock(findings: Finding[]): string {
  const names = findings.map((f) => f.ruleName).join(", ");
  const lines = [
    "",
    "---",
    `⚠️ Security guidance — ${findings.length} pattern${findings.length !== 1 ? "s" : ""} matched (${names})`,
    "",
  ];
  for (const f of findings) {
    lines.push(f.reminder);
    lines.push("");
  }
  lines.push(
    "Pattern matches can be false positives. If the construct is safe in this context, briefly document why in a code comment and continue. Otherwise, fix the code before moving on."
  );
  return lines.join("\n");
}
