// Where did the triggering signal appear? SARIF and code-scanning UIs want a file and
// a line. The checks in core.mjs run over the whole scanned surface, so most findings
// are about an absence (no gate, no receipt) and have no single line. We point at the
// first place the triggering pattern appears (for example the first external effect)
// and say so in the SARIF message. These patterns mirror core.mjs; a test fails if a
// core finding on a fixture cannot be located.
const TOOL_CALL = /(tool_call|toolcall|function_call|function\s+\w+\s*\(|tool\s*[:=]|execute\s*\(|invoke\s*\()/i;
const EXTERNAL_EFFECT = /(fetch\s*\(|axios|stripe\.|db\.(add|update|delete)|send\s*\(|publish\s*\(|approve\s*\(|deny\s*\(|transfer\s*\(|charge\s*\(|refund\s*\()/i;
const SECRET = /(sk_(?:live|test)_[A-Za-z0-9]{6,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|Bearer\s+(?=[A-Za-z0-9._~+\/=-]*\d)[A-Za-z0-9._~+\/=-]{16,})/i;
const INJECTION = /(ignore (all|any|the) previous|system prompt|jailbreak|disregard instructions|developer message)/i;

const TRIGGER = {
  "secret-exposure": SECRET,
  "untrusted-instruction": INJECTION,
  "authorization-gap": EXTERNAL_EFFECT,
  "unverifiable-effect": EXTERNAL_EFFECT,
  "replay-risk": EXTERNAL_EFFECT,
  "irreversible-action": EXTERNAL_EFFECT,
  "tool-governance": TOOL_CALL,
  "partial-assurance": TOOL_CALL,
};

export const MAX_LOCATIONS = 3;

export function locateFindings(findings, scanned) {
  const out = new Map();
  for (const f of findings) {
    const re = TRIGGER[f.id];
    const hits = [];
    if (re) {
      for (const file of scanned) {
        const m = re.exec(file.text);
        if (m) {
          hits.push({ rel: file.rel, line: file.text.slice(0, m.index).split("\n").length });
          if (hits.length >= MAX_LOCATIONS) break;
        }
      }
    }
    if (hits.length === 0 && scanned.length > 0) hits.push({ rel: scanned[0].rel, line: 1, approximate: true });
    out.set(f.id, hits);
  }
  return out;
}
