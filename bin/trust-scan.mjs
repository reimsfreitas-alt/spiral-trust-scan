#!/usr/bin/env node
// Spiral Trust Scan — local, offline scan of agent code or tool logs for
// missing authorization, unverifiable effects, replay risk and unconfirmed
// irreversible actions. Heuristic: it looks for signals in the text, it does
// not execute or prove anything. Nothing leaves your machine (no network code).

import { readdirSync, readFileSync, statSync, appendFileSync } from "node:fs";
import { join, relative, extname, resolve } from "node:path";
import { analyzeTrustSurface } from "../src/core.mjs";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".vercel", "vendor", "coverage", "__pycache__", ".venv", "venv"]);
const EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".java", ".json", ".yml", ".yaml", ".md", ".txt", ".log"]);
const MAX_FILE_BYTES = 200 * 1024;
const SURFACE_CHARS = 120_000; // same ceiling the web scanner applies
const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const URL_MATRIX = "https://spiral-os-matrix-current.vercel.app/";

function usage() {
  return `Usage: trust-scan [paths...] [--format text|json|markdown] [--fail-on critical|high|medium|none] [--label name]

Scans files locally and prints findings. Default path is the current directory.
Exit code 0 = below threshold, 1 = a finding at or above --fail-on (default: high), 2 = usage error.`;
}

export function parseArgs(argv) {
  const opts = { paths: [], format: "text", failOn: "high", label: "" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") return { help: true };
    else if (a === "--format") opts.format = argv[++i];
    else if (a === "--fail-on") opts.failOn = argv[++i];
    else if (a === "--label") opts.label = argv[++i] ?? "";
    else if (a.startsWith("--")) return { error: `unknown option ${a}` };
    else opts.paths.push(a);
  }
  if (!["text", "json", "markdown"].includes(opts.format)) return { error: `invalid --format ${opts.format}` };
  if (!["critical", "high", "medium", "none"].includes(opts.failOn)) return { error: `invalid --fail-on ${opts.failOn}` };
  if (opts.paths.length === 0) opts.paths = ["."];
  return { opts };
}

export function collectFiles(paths) {
  const files = [];
  const walk = (p) => {
    let st;
    try { st = statSync(p); } catch { return; }
    if (st.isDirectory()) {
      for (const name of readdirSync(p).sort()) {
        if (SKIP_DIRS.has(name)) continue;
        walk(join(p, name));
      }
    } else if (st.isFile() && EXTENSIONS.has(extname(p).toLowerCase()) && st.size <= MAX_FILE_BYTES) {
      files.push(p);
    }
  };
  for (const p of paths) walk(resolve(p));
  return files;
}

export function buildSurface(files, root) {
  let surface = "";
  let included = 0;
  for (const f of files) {
    let text;
    try { text = readFileSync(f, "utf8"); } catch { continue; }
    if (text.includes("\u0000")) continue; // binary
    const chunk = `// FILE: ${relative(root, f)}\n${text}\n`;
    if (surface.length + chunk.length > SURFACE_CHARS) {
      return { surface, included, truncated: true, skipped: files.length - included };
    }
    surface += chunk;
    included += 1;
  }
  return { surface, included, truncated: false, skipped: 0 };
}

export function render(report, meta, format) {
  if (format === "json") return JSON.stringify({ ...report, meta }, null, 2);
  const note = "Heuristic scan: it looks for signals in the text, it does not run or prove anything. A missing signal is not proof of a gap, and a present one is not proof of safety.";
  const trunc = meta.truncated ? `Only the first ${meta.included} of ${meta.included + meta.skipped} files fit the ${SURFACE_CHARS}-character scan window; ${meta.skipped} file(s) were not scanned.` : "";
  const s = report.summary;
  if (format === "markdown") {
    const lines = [`## Spiral Trust Scan`, ``, `${meta.included} file(s) scanned locally. Critical ${s.criticalFindings} · High ${s.highFindings} · Medium ${s.mediumFindings} · Low ${s.lowFindings}`, ``];
    for (const f of report.findings) lines.push(`- **[${f.severity}] ${f.title}** — ${f.recommendation}`);
    if (report.findings.length === 0) lines.push("No findings from the heuristic checks.");
    lines.push("", `_${note}_`);
    if (trunc) lines.push("", `_${trunc}_`);
    lines.push("", `Free scanner and written review: ${URL_MATRIX}#trust-scanner`);
    return lines.join("\n");
  }
  const lines = [`Spiral Trust Scan — ${meta.included} file(s) scanned locally (nothing leaves your machine)`, `Critical ${s.criticalFindings} · High ${s.highFindings} · Medium ${s.mediumFindings} · Low ${s.lowFindings}`, ""];
  for (const f of report.findings) lines.push(`[${f.severity}] ${f.title}`, `    ${f.evidence}`, `    Fix: ${f.recommendation}`, "");
  if (report.findings.length === 0) lines.push("No findings from the heuristic checks.", "");
  lines.push(note);
  if (trunc) lines.push(trunc);
  lines.push(`More: ${URL_MATRIX}#trust-scanner`);
  return lines.join("\n");
}

export function exitCodeFor(report, failOn) {
  if (failOn === "none") return 0;
  const threshold = { critical: 4, high: 3, medium: 2 }[failOn];
  return report.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold) ? 1 : 0;
}

export function run(argv, env = process.env, out = (t) => console.log(t)) {
  const parsed = parseArgs(argv);
  if (parsed.help) { out(usage()); return 0; }
  if (parsed.error) { console.error(`trust-scan: ${parsed.error}\n${usage()}`); return 2; }
  const { opts } = parsed;
  const root = resolve(opts.paths.length === 1 ? opts.paths[0] : ".");
  const files = collectFiles(opts.paths);
  if (files.length === 0) { console.error("trust-scan: no scannable files found"); return 2; }
  const { surface, included, truncated, skipped } = buildSurface(files, root);
  const report = analyzeTrustSurface("repo", opts.label || root, surface);
  const meta = { included, truncated, skipped };
  out(render(report, meta, opts.format));
  if (env.GITHUB_STEP_SUMMARY && opts.format !== "json") {
    try { appendFileSync(env.GITHUB_STEP_SUMMARY, render(report, meta, "markdown") + "\n"); } catch { /* summary is best-effort */ }
  }
  return exitCodeFor(report, opts.failOn);
}

import { fileURLToPath } from "node:url";
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.exit(run(process.argv.slice(2)));
}
