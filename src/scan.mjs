// File collection, scan windows and the quick/deep modes. Local filesystem only:
// no network. The analysis itself is analyzeTrustSurface in core.mjs, unchanged.
import { readdirSync, readFileSync, statSync, lstatSync } from "node:fs";
import { join, relative, extname, resolve, dirname, sep } from "node:path";
import { createHash } from "node:crypto";
import { analyzeTrustSurface } from "./core.mjs";

export const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".vercel", "vendor", "coverage", "__pycache__", ".venv", "venv"]);
export const EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".java", ".json", ".yml", ".yaml", ".md", ".txt", ".log"]);
export const MAX_FILE_BYTES = 200 * 1024;
export const SURFACE_CHARS = 120_000; // same ceiling the web scanner applies, per window
export const DEEP_MAX_WINDOWS = 10;   // deep mode: at most 10 windows = 1,200,000 characters
export const MODES = ["quick", "deep"];
export const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export function collectFiles(paths, { followSymlinks = true } = {}) {
  const files = [];
  const stat = followSymlinks ? statSync : lstatSync; // lstat: a symlink is neither a file nor a directory
  const walk = (p) => {
    let st;
    try { st = stat(p); } catch { return; }
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

// The directory that relative paths (and therefore target_hash) are computed from.
export function resolveRoot(paths) {
  const first = resolve(paths.length === 1 ? paths[0] : ".");
  try { return statSync(first).isFile() ? dirname(first) : first; } catch { return first; }
}

const posixRel = (root, f) => relative(root, f).split(sep).join("/");

// Packs files into windows of at most SURFACE_CHARS characters.
//  quick: one window; stops at the first file that does not fit (same behaviour as the web scanner).
//  deep:  up to DEEP_MAX_WINDOWS windows; a file too large for any window is skipped and the rest continue.
export function packWindows(files, root, mode = "quick") {
  const deep = mode === "deep";
  const maxWindows = deep ? DEEP_MAX_WINDOWS : 1;
  const windows = [];
  let cur = { surface: "", files: [] };
  let included = 0;
  let truncated = false;
  for (const f of files) {
    let buf;
    try { buf = readFileSync(f); } catch { continue; }
    const text = buf.toString("utf8");
    if (text.includes("\u0000")) continue; // binary
    const rel = posixRel(root, f);
    const chunk = `// FILE: ${rel}\n${text}\n`;
    if (chunk.length > SURFACE_CHARS) {
      truncated = true;
      if (!deep) break;
      continue;
    }
    if (cur.surface.length + chunk.length > SURFACE_CHARS) {
      if (windows.length + 1 >= maxWindows) { truncated = true; break; }
      windows.push(cur);
      cur = { surface: "", files: [] };
    }
    cur.surface += chunk;
    cur.files.push({ rel, buf, text });
    included += 1;
  }
  if (cur.files.length > 0 || windows.length === 0) windows.push(cur);
  return { windows, included, truncated, skipped: files.length - included };
}

function summarize(findings, toolCallsDetected) {
  return {
    toolCallsDetected,
    criticalFindings: findings.filter((f) => f.severity === "CRITICAL").length,
    highFindings: findings.filter((f) => f.severity === "HIGH").length,
    mediumFindings: findings.filter((f) => f.severity === "MEDIUM").length,
    lowFindings: findings.filter((f) => f.severity === "LOW").length,
    authorizationGaps: findings.filter((f) => f.category === "AUTHORIZATION").length,
    unverifiableEffects: findings.filter((f) => f.category === "OBSERVATION").length,
  };
}

// Deep mode with several windows: every window is analysed exactly as quick mode
// would analyse it, and findings are merged by id (first occurrence kept).
// Absence-based checks (no gate, no receipt, no idempotency...) are evaluated per
// window, so deep can report more of them than quick on the same code: it widens
// coverage, it does not make the heuristic smarter.
export function mergeReports(reports, label) {
  const byId = new Map();
  for (const r of reports) for (const f of r.findings) if (!byId.has(f.id)) byId.set(f.id, f);
  let findings = [...byId.values()];
  if (findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH")) {
    findings = findings.filter((f) => f.id !== "partial-assurance"); // same rule the core applies within one window
  }
  const toolCalls = reports.reduce((n, r) => n + r.summary.toolCallsDetected, 0);
  const reportId = "tscan_" + createHash("sha256").update(reports.map((r) => r.reportId).join(":")).digest("hex").slice(0, 24);
  return { reportId, sourceType: "repo", sourceLabel: label, scannedAt: new Date().toISOString(), summary: summarize(findings, toolCalls), findings };
}

// Returns null when there is nothing scannable.
export function scanPaths({ paths, mode = "quick", label = "", followSymlinks = true }) {
  if (!MODES.includes(mode)) throw new Error(`invalid mode ${mode}`);
  const root = resolveRoot(paths);
  const files = collectFiles(paths, { followSymlinks });
  if (files.length === 0) return null;
  const { windows, included, truncated, skipped } = packWindows(files, root, mode);
  const lbl = label || root;
  const report = windows.length <= 1
    ? analyzeTrustSurface("repo", lbl, windows[0]?.surface ?? "")
    : mergeReports(windows.map((w) => analyzeTrustSurface("repo", lbl, w.surface)), lbl);
  const scanned = windows.flatMap((w) => w.files);
  return { report, scanned, root, meta: { mode, included, truncated, skipped, windows: windows.length } };
}

export function exitCodeFor(report, failOn) {
  if (failOn === "none") return 0;
  const threshold = { critical: 4, high: 3, medium: 2 }[failOn];
  return report.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold) ? 1 : 0;
}
