// Rendering (text, markdown, json, SARIF), the GitHub Job Summary and step outputs.
// Pure string building plus one append-to-file helper. No network.
import { appendFileSync } from "node:fs";
import { relative, join, sep } from "node:path";
import { SURFACE_CHARS, DEEP_MAX_WINDOWS } from "./scan.mjs";
import { countsOf } from "./hashes.mjs";
import { locateFindings } from "./locate.mjs";
import { VERSION } from "./version.mjs";

export const URL_MATRIX = "https://spiral-os-matrix-current.vercel.app/";
export const REPO_URL = "https://github.com/reimsfreitas-alt/spiral-trust-scan";
export const LIMITS_NOTE = "Heuristic scan: it looks for signals in the text, it does not run or prove anything. A missing signal is not proof of a gap, and a present one is not proof of safety.";
export const RECEIPT_NOTE = "A receipt records that these digests were submitted to the issuer at that time. It is not proof that the code is secure or free of problems.";

// ctx.receipt: { status: "off" } | { status: "ok", data, submitted } | { status: "failed", error }
const receiptOf = (ctx) => ctx?.receipt ?? { status: "off" };

function truncationNote(meta) {
  if (!meta.truncated) return "";
  const total = meta.included + meta.skipped;
  if (meta.mode === "deep") {
    return `Deep mode scanned ${meta.included} of ${total} files in ${meta.windows} window(s) (at most ${DEEP_MAX_WINDOWS} windows of ${SURFACE_CHARS} characters); ${meta.skipped} file(s) were not scanned.`;
  }
  return `Only the first ${meta.included} of ${total} files fit the ${SURFACE_CHARS}-character scan window; ${meta.skipped} file(s) were not scanned.`;
}

export function badgeMarkdown(data) {
  if (!data?.badge_url || !data?.validation_url) return "";
  return `[![Spiral Trust Scan receipt](${data.badge_url})](${data.validation_url})`;
}

function receiptLines(ctx, md) {
  const r = receiptOf(ctx);
  if (r.status === "ok") {
    const d = r.data;
    const lines = [md ? `Receipt \`${d.receipt_id}\` issued ${d.issued_at}. Validation: ${d.validation_url}` : `Receipt: ${d.receipt_id} (issued ${d.issued_at})`];
    if (!md) lines.push(`Validation: ${d.validation_url}`);
    lines.push(`Submitted digests: target_hash ${r.submitted.target_hash}, findings_hash ${r.submitted.findings_hash}, ${r.submitted.files_scanned} file(s).`);
    const badge = badgeMarkdown(d);
    if (badge) lines.push(`Badge markdown (opt-in: copy it yourself if you want it; nothing is inserted automatically): ${md ? "`" + badge + "`" : badge}`);
    lines.push(RECEIPT_NOTE);
    return lines;
  }
  if (r.status === "failed") return [`Receipt requested but not created: ${r.error}. The scan result and exit code are unaffected (the receipt is best-effort).`];
  return [];
}

export function renderText(report, meta, ctx) {
  const s = report.summary;
  const r = receiptOf(ctx);
  const where = r.status === "off" ? "nothing leaves your machine" : "scanned locally; only digests and counts are submitted because --receipt was set";
  const lines = [`Spiral Trust Scan — ${meta.included} file(s) scanned locally (${where})`, `Critical ${s.criticalFindings} · High ${s.highFindings} · Medium ${s.mediumFindings} · Low ${s.lowFindings}`, ""];
  for (const f of report.findings) lines.push(`[${f.severity}] ${f.title}`, `    ${f.evidence}`, `    Fix: ${f.recommendation}`, "");
  if (report.findings.length === 0) lines.push("No findings from the heuristic checks.", "");
  lines.push(LIMITS_NOTE);
  const t = truncationNote(meta);
  if (t) lines.push(t);
  const rl = receiptLines(ctx, false);
  if (rl.length) lines.push("", ...rl);
  lines.push(`More: ${URL_MATRIX}#trust-scanner`);
  return lines.join("\n");
}

export function renderMarkdown(report, meta, ctx) {
  const s = report.summary;
  const lines = [`## Spiral Trust Scan`, ``, `${meta.included} file(s) scanned locally. Critical ${s.criticalFindings} · High ${s.highFindings} · Medium ${s.mediumFindings} · Low ${s.lowFindings}`, ``];
  for (const f of report.findings) lines.push(`- **[${f.severity}] ${f.title}** — ${f.recommendation}`);
  if (report.findings.length === 0) lines.push("No findings from the heuristic checks.");
  lines.push("", `_${LIMITS_NOTE}_`);
  const t = truncationNote(meta);
  if (t) lines.push("", `_${t}_`);
  const rl = receiptLines(ctx, true);
  if (rl.length) lines.push("", ...rl.map((l) => `- ${l}`));
  lines.push("", `Free scanner and written review: ${URL_MATRIX}#trust-scanner`);
  return lines.join("\n");
}

export function renderJson(report, meta, ctx, hashes) {
  const r = receiptOf(ctx);
  const out = { ...report, meta: { ...meta, scanner_version: VERSION, ...hashes } };
  if (r.status === "ok") out.receipt = r.data;
  else if (r.status === "failed") out.receipt = { error: r.error };
  return JSON.stringify(out, null, 2);
}

// ---- GitHub Job Summary --------------------------------------------------------

export function renderSummary(report, meta, ctx) {
  const s = report.summary;
  const total = report.findings.length;
  const r = receiptOf(ctx);
  const lines = [
    `## Spiral Trust Scan`,
    ``,
    `| Severity | Findings |`,
    `| --- | ---: |`,
    `| Critical | ${s.criticalFindings} |`,
    `| High | ${s.highFindings} |`,
    `| Medium | ${s.mediumFindings} |`,
    `| Low | ${s.lowFindings} |`,
    `| **Total** | **${total}** |`,
    ``,
    `Mode \`${meta.mode}\` · ${meta.included} file(s) scanned · fail-on \`${ctx.failOn}\` · exit code ${ctx.exitCode}`,
    ``,
  ];
  if (total > 0) {
    for (const f of report.findings) lines.push(`- **[${f.severity}] ${f.title}**: ${f.recommendation}`);
    lines.push("");
  } else {
    lines.push("No findings from the heuristic checks.", "");
  }
  lines.push(`> **Heuristic, not proof.** ${LIMITS_NOTE}`, ``);
  const t = truncationNote(meta);
  if (t) lines.push(`> ${t}`, ``);
  if (r.status === "ok") {
    lines.push(`**Receipt:** [${r.data.validation_url}](${r.data.validation_url}) (id \`${r.data.receipt_id}\`)`, ``);
    lines.push(`${RECEIPT_NOTE}`, ``);
    lines.push(`<details><summary>Digests submitted</summary>`, ``, `- target_hash: \`${r.submitted.target_hash}\``, `- findings_hash: \`${r.submitted.findings_hash}\``, `- files_scanned: ${r.submitted.files_scanned}`, ``, `</details>`, ``);
    const badge = badgeMarkdown(r.data);
    if (badge) lines.push(`Badge markdown (opt-in, add it to a README yourself if you want it):`, ``, "```markdown", badge, "```", ``);
  } else if (r.status === "failed") {
    lines.push(`**Receipt:** requested but not created (${r.error}). The scan result and exit code are unaffected; the receipt is best-effort.`, ``);
  } else {
    lines.push(`**Receipt:** not requested (\`receipt: false\`). Nothing was sent anywhere.`, ``);
  }
  return lines.join("\n");
}

export function writeJobSummary(env, text) {
  if (!env.GITHUB_STEP_SUMMARY) return false;
  try { appendFileSync(env.GITHUB_STEP_SUMMARY, text + "\n"); return true; } catch { return false; }
}

// ---- GitHub step outputs --------------------------------------------------------
// Names: findings, counts-json, receipt_id, validation_url, sarif-file. Single-line
// values only (a newline could inject extra outputs), so everything is flattened.
export function writeStepOutputs(env, { report, ctx, sarifFile }) {
  if (!env.GITHUB_OUTPUT) return false;
  const r = receiptOf(ctx);
  const flat = (v) => String(v ?? "").replace(/[\r\n]+/g, " ");
  const pairs = [
    ["findings", report.findings.length],
    ["counts-json", JSON.stringify(countsOf(report))],
    ["receipt_id", r.status === "ok" ? r.data.receipt_id : ""],
    ["validation_url", r.status === "ok" ? r.data.validation_url : ""],
    ["sarif-file", sarifFile ?? ""],
  ];
  try { appendFileSync(env.GITHUB_OUTPUT, pairs.map(([k, v]) => `${k}=${flat(v)}\n`).join("")); return true; } catch { return false; }
}

// ---- SARIF 2.1.0 ------------------------------------------------------------------
const LEVEL = { CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note" };

// scanned: [{rel, text}] ; root: absolute scan root ; cwd: used to make URIs repo-relative.
export function renderSarif(report, { scanned, root, cwd = process.cwd() }) {
  const inside = root === cwd || root.startsWith(cwd + sep);
  const uriBase = inside ? cwd : root;
  const uriOf = (rel) => relative(uriBase, join(root, rel)).split(sep).join("/");
  const locs = locateFindings(report.findings, scanned);
  const rules = report.findings.map((f) => ({
    id: f.id,
    name: f.id,
    shortDescription: { text: f.title },
    fullDescription: { text: `${f.recommendation} ${LIMITS_NOTE}` },
    help: { text: f.recommendation },
    defaultConfiguration: { level: LEVEL[f.severity] ?? "warning" },
    properties: { tags: ["heuristic", f.category.toLowerCase()], "spiral-severity": f.severity },
  }));
  const results = report.findings.map((f) => {
    const where = locs.get(f.id) ?? [];
    const approximate = where.some((w) => w.approximate);
    const pointer = approximate
      ? "The location is the first scanned file; this finding is about the scanned surface as a whole."
      : "The location is where the triggering signal first appears; the finding is usually about something missing elsewhere.";
    return {
      ruleId: f.id,
      level: LEVEL[f.severity] ?? "warning",
      message: { text: `${f.title}. ${f.evidence} ${pointer} Heuristic, not proof.` },
      locations: where.map((w) => ({ physicalLocation: { artifactLocation: { uri: uriOf(w.rel) }, region: { startLine: w.line } } })),
      properties: { category: f.category, heuristic: true },
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Spiral Trust Scan", version: VERSION, informationUri: REPO_URL, rules } },
      results,
    }],
  };
}
