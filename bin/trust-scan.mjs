#!/usr/bin/env node
// Spiral Trust Scan — local, offline scan of agent code or tool logs for
// missing authorization, unverifiable effects, replay risk and unconfirmed
// irreversible actions. Heuristic: it looks for signals in the text, it does
// not execute or prove anything.
//
// The scan itself has no network code. The one opt-in exception is --receipt, which
// loads src/receipt-client.mjs on demand (see that file for exactly what is sent).

import { writeFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { scanPaths, collectFiles, packWindows, exitCodeFor, MODES } from "../src/scan.mjs";
import { computeTargetHash, computeFindingsHash, countsOf } from "../src/hashes.mjs";
import { renderText, renderMarkdown, renderJson, renderSarif, renderSummary, writeJobSummary, writeStepOutputs } from "../src/report.mjs";

export { collectFiles, exitCodeFor };
export const buildSurface = (files, root) => {
  const { windows, included, truncated, skipped } = packWindows(files, root, "quick");
  return { surface: windows[0].surface, included, truncated, skipped };
};

const FORMATS = ["text", "json", "markdown", "sarif"];

function usage() {
  return `Usage: trust-scan [paths...] [options]
       trust-scan mcp            start the MCP server on stdio (see README)

Scans files locally and prints findings. Default path is the current directory.

Options:
  --mode quick|deep          quick (default): one 120,000-character window, same as the web scanner.
                             deep: up to 10 such windows (1,200,000 characters), merged by finding id.
  --format text|json|markdown|sarif
  --fail-on critical|high|medium|none   (default: high)
  --label name
  --sarif-file path          also write SARIF 2.1.0 to this file
  --receipt                  OPT-IN: submit two digests and counts to the receipt service and print
                             the validation link. Best-effort; never changes the scan result or exit code.
  --include-source           with --receipt: also send GITHUB_REPOSITORY and GITHUB_SHA (off by default)
  --receipt-endpoint url     override the receipt service URL (testing, self-hosting)
  --                         end of options (the rest are paths)

Exit code 0 = below threshold, 1 = a finding at or above --fail-on (default: high), 2 = usage error.
In GitHub Actions the Job Summary and step outputs are written when GITHUB_STEP_SUMMARY / GITHUB_OUTPUT are set.`;
}

export function parseArgs(argv) {
  const opts = { paths: [], format: "text", failOn: "high", label: "", mode: "quick", sarifFile: "", receipt: false, includeSource: false, receiptEndpoint: "" };
  let rest = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (rest) { opts.paths.push(a); continue; }
    if (a === "--help" || a === "-h") return { help: true };
    else if (a === "--") rest = true;
    else if (a === "--format") opts.format = argv[++i];
    else if (a === "--fail-on") opts.failOn = argv[++i];
    else if (a === "--label") opts.label = argv[++i] ?? "";
    else if (a === "--mode") opts.mode = argv[++i];
    else if (a === "--sarif-file") opts.sarifFile = argv[++i] ?? "";
    else if (a === "--receipt") opts.receipt = true;
    else if (a === "--include-source") opts.includeSource = true;
    else if (a === "--receipt-endpoint") opts.receiptEndpoint = argv[++i] ?? "";
    else if (a.startsWith("--")) return { error: `unknown option ${a}` };
    else opts.paths.push(a);
  }
  if (!FORMATS.includes(opts.format)) return { error: `invalid --format ${opts.format}` };
  if (!["critical", "high", "medium", "none"].includes(opts.failOn)) return { error: `invalid --fail-on ${opts.failOn}` };
  if (!MODES.includes(opts.mode)) return { error: `invalid --mode ${opts.mode} (use quick or deep)` };
  if (opts.sarifFile === "" && argv.includes("--sarif-file")) return { error: "--sarif-file needs a path" };
  if (opts.receiptEndpoint) {
    try { if (!/^https?:$/.test(new URL(opts.receiptEndpoint).protocol)) throw new Error(); } catch { return { error: "invalid --receipt-endpoint" }; }
  }
  if (opts.paths.length === 0) opts.paths = ["."];
  return { opts };
}

// Scan + hashes. Synchronous and offline.
function scanStage(opts) {
  const scan = scanPaths({ paths: opts.paths, mode: opts.mode, label: opts.label });
  if (!scan) return null;
  const hashes = { target_hash: computeTargetHash(scan.scanned), findings_hash: computeFindingsHash(scan.report.findings) };
  return { ...scan, hashes };
}

function finish(opts, scan, receipt, env, out) {
  const { report, meta, hashes } = scan;
  const exitCode = exitCodeFor(report, opts.failOn);
  const ctx = { receipt, failOn: opts.failOn, exitCode };
  let sarifFile = "";
  const sarif = () => renderSarif(report, { scanned: scan.scanned, root: scan.root });
  if (opts.sarifFile) {
    try { writeFileSync(opts.sarifFile, JSON.stringify(sarif(), null, 2)); sarifFile = opts.sarifFile; }
    catch (err) { console.error(`trust-scan: could not write ${opts.sarifFile}: ${err.message}`); }
  }
  let text;
  if (opts.format === "json") text = renderJson(report, meta, ctx, hashes);
  else if (opts.format === "markdown") text = renderMarkdown(report, meta, ctx);
  else if (opts.format === "sarif") text = JSON.stringify(sarif(), null, 2);
  else text = renderText(report, meta, ctx);
  out(text);
  writeJobSummary(env, renderSummary(report, meta, ctx)); // best-effort
  writeStepOutputs(env, { report, ctx, sarifFile });      // best-effort
  return exitCode;
}

// Synchronous entry point (no receipt). Kept for tests and embedding.
export function run(argv, env = process.env, out = (t) => console.log(t)) {
  const parsed = parseArgs(argv);
  if (parsed.help) { out(usage()); return 0; }
  if (parsed.error) { console.error(`trust-scan: ${parsed.error}\n${usage()}`); return 2; }
  const { opts } = parsed;
  if (opts.receipt) { console.error("trust-scan: --receipt needs the asynchronous entry point (main)"); return 2; }
  const scan = scanStage(opts);
  if (!scan) { console.error("trust-scan: no scannable files found"); return 2; }
  return finish(opts, scan, { status: "off" }, env, out);
}

// Full entry point, including the opt-in receipt.
export async function main(argv, env = process.env, out = (t) => console.log(t), deps = {}) {
  if (argv[0] === "mcp") {
    const { startStdio } = await import("../mcp/server.mjs");
    startStdio();
    return new Promise(() => {}); // runs until stdin closes
  }
  const parsed = parseArgs(argv);
  if (parsed.help) { out(usage()); return 0; }
  if (parsed.error) { console.error(`trust-scan: ${parsed.error}\n${usage()}`); return 2; }
  const { opts } = parsed;
  const scan = scanStage(opts);
  if (!scan) { console.error("trust-scan: no scannable files found"); return 2; }
  let receipt = { status: "off" };
  if (opts.receipt) {
    try {
      const client = deps.client ?? await import("../src/receipt-client.mjs"); // the only place the network module is loaded
      const submitted = {
        counts: countsOf(scan.report),
        threshold: opts.failOn,
        files_scanned: scan.meta.included,
        target_hash: scan.hashes.target_hash,
        findings_hash: scan.hashes.findings_hash,
      };
      const source = opts.includeSource ? { repo: env.GITHUB_REPOSITORY, commit: env.GITHUB_SHA } : undefined;
      const payload = client.buildReceiptPayload({ targetHash: submitted.target_hash, findingsHash: submitted.findings_hash, counts: submitted.counts, threshold: submitted.threshold, filesScanned: submitted.files_scanned, source });
      const res = await client.submitReceipt(payload, opts.receiptEndpoint ? { endpoint: opts.receiptEndpoint } : {});
      receipt = res.ok ? { status: "ok", data: res.data, submitted } : { status: "failed", error: res.error };
    } catch (err) {
      receipt = { status: "failed", error: String(err?.message ?? err).slice(0, 160) }; // best-effort: never throws past here
    }
  }
  return finish(opts, scan, receipt, env, out);
}

function isMain() {
  try { return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]); } catch { return false; }
}
if (isMain()) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
