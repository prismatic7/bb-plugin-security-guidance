// gate.ts — an episteme-shaped decision layer over the pattern engine.
//
// Episteme's discipline, applied to a code gate: a verdict states its
// certainty, the evidence behind it, and what would change it. So a finding
// here is not "this looks dangerous" but "this is arbitrary code execution
// (high certainty, one line of evidence), and a Loader=SafeLoader in the call
// would clear it".
//
// What this layer can and cannot do in BB: it cannot refuse a write. BB gives
// a plugin no pre-tool-call hook, so the gate is a decision the agent is asked
// to obtain and honour — the same relationship the Hermes original has with
// its advisory warnings. Saying that plainly is the point: a gate that
// pretended to enforce would be lying.
//
// patterns.ts stays an unmodified port of upstream's pattern set. Ranking and
// verdicts live here, keyed by rule name, so the port can be re-synced from
// upstream without touching them.
import { scanContent, type Finding } from "./patterns.ts";

export type Tier = "high" | "medium" | "low";
export type Certainty = "high" | "medium" | "low";
export type Decision = "stop" | "revise" | "proceed" | "proceed_documented";

export interface RuleVerdict {
  tier: Tier;
  /** Why this tier: what the construct lets an attacker do. */
  why: string;
  /** The concrete change that clears the finding. */
  fix: string;
  /**
   * Rules that read a call's arguments (a SafeLoader deep in the args, a
   * comparison rather than an assignment) are context-sensitive: their match
   * is certain, their danger is not.
   */
  contextSensitive?: boolean;
}

/** Every rule in the pattern set, ranked. A missing entry is a test failure. */
export const RULE_VERDICTS: Record<string, RuleVerdict> = {
  pickle_deserialization: {
    tier: "high",
    why: "unpickling runs arbitrary code from the file",
    fix: "use JSON or msgspec for data, or a schema-validated deserializer for objects",
  },
  pickle_variants_load: {
    tier: "high",
    why: "cPickle/cloudpickle/dill.load run arbitrary code from the file",
    fix: "use JSON or msgspec; if objects are needed, parse into declared types",
  },
  pickle_wrapper_load: {
    tier: "high",
    why: "joblib/pandas/numpy load can unpickle arbitrary objects",
    fix: "drop allow_pickle=True, or load into declared types after a JSON/metadata pass",
    contextSensitive: true,
  },
  marshal_loads: {
    tier: "high",
    why: "marshal.loads executes arbitrary bytecode",
    fix: "use JSON for data; marshal is not a safe interchange format",
  },
  shelve_open: {
    tier: "high",
    why: "shelve unpickles on read",
    fix: "use sqlite3 or JSON files instead of shelve",
  },
  unsafe_yaml_load: {
    tier: "high",
    why: "yaml.load builds arbitrary Python objects via !!python/object tags",
    fix: "use yaml.safe_load, or pass Loader=yaml.SafeLoader",
    contextSensitive: true,
  },
  yaml_unsafe_load_variants: {
    tier: "high",
    why: "yaml.unsafe_load is yaml.load with the seatbelt removed",
    fix: "use yaml.safe_load",
  },
  torch_unsafe_load: {
    tier: "high",
    why: "torch.load defaults to weights_only=False, which unpickles arbitrary objects",
    fix: "pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1)",
    contextSensitive: true,
  },
  os_system_injection: {
    tier: "high",
    why: "os.system runs through a shell, so interpolated input is a command injection",
    fix: "use subprocess.run([...]) with an argument list and no shell",
  },
  python_subprocess_shell: {
    tier: "high",
    why: "shell=True makes every interpolated argument a shell token",
    fix: "pass an argument list and drop shell=True",
  },
  child_process_exec: {
    tier: "high",
    why: "child_process.exec runs a shell string, so input can inject commands",
    fix: "use execFile/spawn with an argument array",
  },
  go_exec_shell_injection: {
    tier: "high",
    why: "exec.Command(\"sh\", \"-c\", …) puts user input into a shell",
    fix: "call the program directly with separate arguments",
  },
  eval_injection: {
    tier: "high",
    why: "eval executes whatever string it is given",
    fix: "parse data with JSON.parse/ast.literal_eval, or use an expression parser",
    contextSensitive: true,
  },
  new_function_injection: {
    tier: "high",
    why: "new Function compiles a string into code",
    fix: "use obj[key] for property access, or a safe expression parser for computation",
  },
  react_dangerously_set_html: {
    tier: "medium",
    why: "HTML injection into the DOM: XSS if the content is ever untrusted",
    fix: "sanitise with DOMPurify, or render as text",
  },
  document_write_xss: {
    tier: "medium",
    why: "document.write parses its argument as HTML",
    fix: "build nodes with createElement/appendChild, or use textContent",
  },
  innerHTML_xss: {
    tier: "medium",
    why: "an HTML sink: XSS if the value is ever untrusted",
    fix: "use textContent, or sanitise with DOMPurify",
    contextSensitive: true,
  },
  outerHTML_xss: {
    tier: "medium",
    why: "an HTML sink equivalent to innerHTML",
    fix: "use textContent, or sanitise with DOMPurify",
    contextSensitive: true,
  },
  insertAdjacentHTML_xss: {
    tier: "medium",
    why: "insertAdjacentHTML parses its argument as HTML",
    fix: "use insertAdjacentText, or sanitise first",
  },
  tls_verification_disabled: {
    tier: "medium",
    why: "disabling verification accepts any certificate, so a MITM is invisible",
    fix: "trust the CA, or scope the exception to a local dev host",
  },
  node_createcipher_no_iv: {
    tier: "medium",
    why: "createCipher derives the key insecurely and takes no IV",
    fix: "use createCipheriv with a random IV",
  },
  aes_ecb_mode: {
    tier: "medium",
    why: "ECB leaks plaintext structure block by block",
    fix: "use AES-GCM (or CBC with a MAC)",
  },
  xml_unsafe_parse: {
    tier: "medium",
    why: "stdlib XML parsers expand external entities and entity bombs by default",
    fix: "use defusedxml",
  },
  github_actions_workflow: {
    tier: "low",
    why: "workflow files are an injection surface, but only via untrusted event fields",
    fix: "route untrusted values through env: and quote them",
  },
  script_src_without_sri: {
    tier: "low",
    why: "an external script without integrity can be swapped by its origin",
    fix: "add integrity= and crossorigin=anonymous to the tag",
  },
};

export interface GateFinding {
  rule: string;
  tier: Tier;
  why: string;
  fix: string;
  certainty: Certainty;
}

export interface GateVerdict {
  decision: Decision;
  certainty: Certainty;
  findings: GateFinding[];
  /** One line stating what the evidence is, and what it is not. */
  evidence: string;
  /** The counterfactual: what would move this verdict. */
  whatWouldChangeIt: string;
  /** Present only when the caller documented a reason to proceed. */
  justification?: string;
  /** False: BB gives this plugin no way to prevent the write. */
  enforced: false;
}

const RANK: Record<Certainty, number> = { high: 0, medium: 1, low: 2 };

function weakest(a: Certainty, b: Certainty): Certainty {
  return RANK[a] >= RANK[b] ? a : b;
}

function tierOf(f: Finding): RuleVerdict {
  const v = RULE_VERDICTS[f.ruleName];
  if (v) return v;
  // A rule added upstream without a ranking must not silently pass as safe.
  return {
    tier: "high",
    why: "unranked rule (the pattern set moved ahead of gate.ts)",
    fix: "rank it in RULE_VERDICTS before relying on this verdict",
  };
}

/**
 * Judge `content` as a write to `path`.
 *
 * `justification` is episteme's documented-exception path: a caller that names
 * why the construct is safe gets `proceed_documented`, with the reason carried
 * in the verdict for the transcript. It does not suppress the finding.
 */
export function gate(path: string, content: string, options: { justification?: string } = {}): GateVerdict {
  const findings = scanContent(path || "", content);
  const ranked: GateFinding[] = findings.map((f) => {
    const v = tierOf(f);
    return {
      rule: f.ruleName,
      tier: v.tier,
      why: v.why,
      fix: v.fix,
      certainty: v.contextSensitive ? "medium" : "high",
    };
  });

  const highs = ranked.filter((f) => f.tier === "high");
  const mediums = ranked.filter((f) => f.tier === "medium");
  const lows = ranked.filter((f) => f.tier === "low");

  let certainty: Certainty = "high";
  for (const f of ranked) certainty = weakest(certainty, f.certainty);

  const evidence =
    ranked.length === 0
      ? `no rule in the 25-rule pattern set matched ${path ? path : "this content"}`
      : `${highs.length} high, ${mediums.length} medium, ${lows.length} low finding(s) from the 25-rule pattern set`;

  const whatWouldChangeIt =
    ranked.length === 0
      ? "a construct the pattern set does not carry — the set covers deserialisation, shell injection, XSS sinks, crypto footguns, XXE and TLS; it is not a proof of safety"
      : highs.length
        ? `removing the high-tier construct (${highs.map((f) => f.rule).join(", ")}) — or a comment that names why this input cannot be attacker-controlled`
        : mediums.length
          ? `showing the value is never untrusted, or applying the fix (${mediums.map((f) => f.rule).join(", ")})`
          : "nothing: the remaining findings are advisory";

  let decision: Decision;
  if (options.justification) decision = "proceed_documented";
  else if (highs.length) decision = "stop";
  else if (mediums.length) decision = "revise";
  else decision = "proceed";

  const verdict: GateVerdict = {
    decision,
    certainty,
    findings: ranked,
    evidence,
    whatWouldChangeIt,
    enforced: false,
  };
  if (options.justification) verdict.justification = options.justification;
  return verdict;
}

/** Render a verdict as the block an agent reads. */
export function renderVerdict(v: GateVerdict): string {
  const head = `${v.decision.toUpperCase()}  (certainty: ${v.certainty})`;
  const lines = [head, `evidence: ${v.evidence}`];
  if (v.findings.length) {
    lines.push("");
    for (const f of v.findings) {
      lines.push(`[${f.tier}] ${f.rule} — ${f.why}`);
      lines.push(`  fix: ${f.fix}`);
    }
  }
  lines.push("");
  lines.push(`what would change this: ${v.whatWouldChangeIt}`);
  if (v.justification) lines.push(`documented justification: ${v.justification}`);
  lines.push(
    v.decision === "stop"
      ? "Do not write this as-is. Fix it, or call again with a justification you can defend."
      : v.decision === "revise"
        ? "Revise before writing, or document why the value is never untrusted."
        : v.decision === "proceed_documented"
          ? "Proceeding with the documented reason above; keep it in the code comment."
          : "No action needed.",
  );
  lines.push("(advisory: BB gives plugins no way to block a write)");
  return lines.join("\n");
}
