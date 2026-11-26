// Behaviour tests for the ported pattern set.
//
// Each case pins a refinement inherited from the upstream patterns.py at
// fce198c: the JS-only gating, the assignment-vs-comparison innerHTML rule, the
// Playwright/Puppeteer $eval exclusion, and argument-aware suppression for
// yaml / torch / numpy loads (a SafeLoader or weights_only=True several lines
// into the call still suppresses).
//
// Run: node --test test/patterns.test.ts
import assert from "node:assert/strict";
import { test } from "node:test";
import { scanContent } from "../patterns.ts";

const rules = (path: string, content: string) => scanContent(path, content).map((f) => f.ruleName);
const has = (path: string, content: string, rule: string) =>
  rules(path, content).includes(rule);

test("new Function is gated to JS and matched as a whole word", () => {
  assert.equal(has("a.ts", "const f = new Function('a', 'return a');", "new_function_injection"), true);
  assert.equal(has("a.ts", "const f = new FunctionConstructor('return 1');", "new_function_injection"), true);
  assert.equal(has("a.ts", "const r = new FunctionRegistry();", "new_function_injection"), false);
  assert.equal(has("notes.md", "Docs mention new Function() as a hazard.", "new_function_injection"), false);
});

test("innerHTML and outerHTML fire on assignment, not comparison", () => {
  assert.equal(has("a.ts", "el.innerHTML = html;", "innerHTML_xss"), true);
  assert.equal(has("a.ts", "el.innerHTML=html;", "innerHTML_xss"), true);
  assert.equal(has("a.ts", "if (el.innerHTML === expected) ok();", "innerHTML_xss"), false);
  assert.equal(has("a.ts", "el.outerHTML = html;", "outerHTML_xss"), true);
  assert.equal(has("a.ts", "if (el.outerHTML == expected) ok();", "outerHTML_xss"), false);
});

test("browser DOM rules stay out of non-JS files", () => {
  assert.deepEqual(rules("README.md", "Use dangerouslySetInnerHTML and document.write."), []);
  assert.deepEqual(rules("mod.py", "dangerouslySetInnerHTML = 1  # .insertAdjacentHTML("), []);
});

test("eval fires on bare eval but not on method calls or page.$eval", () => {
  assert.equal(has("a.js", "eval(userInput);", "eval_injection"), true);
  assert.equal(has("a.js", "model.eval();", "eval_injection"), false);
  assert.equal(has("a.js", "redis.eval('return 1', 0);", "eval_injection"), false);
  assert.equal(has("a.js", "const t = await page.$eval('#note', (el) => el.textContent);", "eval_injection"), false);
  assert.equal(
    has("a.js", "await page.$eval('#note', function (el) { return el.textContent; });", "eval_injection"),
    false
  );
  assert.equal(has("a.js", "const v = $eval(expr);", "eval_injection"), true);
});

test("yaml.load is suppressed by a SafeLoader anywhere in its arguments", () => {
  assert.equal(has("a.py", "yaml.load(open(path))", "unsafe_yaml_load"), true);
  assert.equal(has("a.py", "yaml.load(raw, Loader=yaml.SafeLoader)", "unsafe_yaml_load"), false);
  assert.equal(has("a.py", "yaml.load(raw, Loader=CSafeLoader)", "unsafe_yaml_load"), false);
  const multiline = ["cfg = yaml.load(", "    stream,", "    Loader=yaml.SafeLoader,", ")"].join("\n");
  assert.equal(has("a.py", multiline, "unsafe_yaml_load"), false);
  const nested = ["cfg = yaml.load(", "    open(resolve(path)),", "    Loader=yaml.CSafeLoader,", ")"].join("\n");
  assert.equal(has("a.py", nested, "unsafe_yaml_load"), false);
});

test("torch.load is suppressed only by weights_only=True in its arguments", () => {
  assert.equal(has("a.py", "torch.load(path)", "torch_unsafe_load"), true);
  assert.equal(has("a.py", "torch.load(path, weights_only=True)", "torch_unsafe_load"), false);
  const multiline = ["m = torch.load(", "    ckpt,", "    map_location='cpu',", "    weights_only=True,", ")"].join("\n");
  assert.equal(has("a.py", multiline, "torch_unsafe_load"), false);
  assert.equal(has("a.py", "torch.load(path, weights_only=False)", "torch_unsafe_load"), true);
});

test("numpy.load fires only with an explicit allow_pickle=True", () => {
  assert.equal(has("a.py", "arr = np.load(path)", "pickle_wrapper_load"), false);
  assert.equal(has("a.py", "arr = np.load(path, allow_pickle=True)", "pickle_wrapper_load"), true);
  const multiline = ["arr = np.load(", "    path,", "    allow_pickle=True,", ")"].join("\n");
  assert.equal(has("a.py", multiline, "pickle_wrapper_load"), true);
  assert.equal(has("a.py", "m = joblib.load(path)", "pickle_wrapper_load"), true);
});

test("the argument reader stops at the call's own closing bracket", () => {
  // A SafeLoader used by the *next* statement must not suppress this call.
  const content = ["yaml.load(raw)", "yaml.load(other, Loader=yaml.SafeLoader)"].join("\n");
  assert.equal(has("a.py", content, "unsafe_yaml_load"), true);
});
