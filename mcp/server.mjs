#!/usr/bin/env node
// spiral-trust-scanner: a minimal MCP server over stdio (newline-delimited JSON-RPC 2.0).
//
// Tools (both are backed by working code; nothing else is advertised):
//   scan_path      runs the local, offline Trust Scan on a path under an allowed root
//   verify_receipt checks the Ed25519 signature of a Spiral receipt offline
//
// Not implemented, so not exposed: check_claim and generate_dispute_dossier. They are
// roadmap items that live in Spiral Truth, not in this package.
//
// This file has no network code. verify_receipt loads src/receipt-client.mjs on demand
// (only when it has to fetch a receipt by id); passing the receipt JSON avoids the network.
//
// Allowed roots: scan_path only reads under SPIRAL_TRUST_ALLOWED_ROOTS (path-delimited
// list) or, if unset, the server's working directory. Symlinks are not followed.
import { realpathSync, statSync } from "node:fs";
import { resolve, delimiter, relative, isAbsolute, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { scanPaths, exitCodeFor, MODES } from "../src/scan.mjs";
import { computeTargetHash, computeFindingsHash, countsOf } from "../src/hashes.mjs";
import { LIMITS_NOTE, RECEIPT_NOTE } from "../src/report.mjs";
import { verifyEd25519, ISSUER_PUBLIC_KEY_SPKI_B64 } from "../src/verify.mjs";
import { VERSION } from "../src/version.mjs";

export const SERVER_NAME = "spiral-trust-scanner";
const SUPPORTED_PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

export const TOOLS = [
  {
    name: "scan_path",
    title: "Scan a path with the Spiral Trust Scan",
    description: `Run the local, offline Trust Scan (heuristic) over files under an allowed root and return findings by severity. ${LIMITS_NOTE} Nothing is sent over the network.`,
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "File or directory to scan. Must be inside an allowed root." },
        mode: { type: "string", enum: MODES, description: "quick (default): one 120,000-character window. deep: up to 10 windows." },
        fail_on: { type: "string", enum: ["critical", "high", "medium", "none"], description: "Threshold used only to report whether it would fail (default high)." },
      },
      required: ["path"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "verify_receipt",
    title: "Verify a Spiral receipt signature",
    description: `Check the Ed25519 signature of a Spiral receipt against the issuer's published public key. Pass either receipt_id (the public receipt is fetched, one network call) or the receipt JSON (fully offline). ${RECEIPT_NOTE}`,
    inputSchema: {
      type: "object",
      properties: {
        receipt_id: { type: "string", description: "Receipt id, e.g. rcpt_..." },
        receipt: { type: "object", description: "The public receipt JSON (must contain signedPayload). Avoids the network." },
        signature: { type: "string", description: "ed25519:<128 hex>. Required unless the receipt JSON carries a signature field." },
        public_key: { type: "string", description: "Issuer public key, SPKI DER base64. Defaults to the key pinned in this package (from the README)." },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
];

export function allowedRoots(env = process.env, cwd = process.cwd()) {
  const raw = env.SPIRAL_TRUST_ALLOWED_ROOTS;
  const list = raw ? raw.split(delimiter).filter(Boolean) : [cwd];
  const roots = [];
  for (const r of list) { try { roots.push(realpathSync(resolve(cwd, r))); } catch { /* missing root: ignored */ } }
  return roots;
}

const inside = (root, p) => { const r = relative(root, p); return r === "" || (!r.startsWith("..") && !isAbsolute(r)); };

class ToolError extends Error {}
class InvalidParams extends Error {}

function textResult(text, structured, isError = false) {
  const res = { content: [{ type: "text", text }], isError };
  if (structured) res.structuredContent = structured;
  return res;
}

function scanPathTool(args, env) {
  if (typeof args.path !== "string" || args.path === "") throw new InvalidParams("path must be a non-empty string");
  const mode = args.mode ?? "quick";
  const failOn = args.fail_on ?? "high";
  if (!MODES.includes(mode)) throw new InvalidParams("mode must be quick or deep");
  if (!["critical", "high", "medium", "none"].includes(failOn)) throw new InvalidParams("fail_on must be critical, high, medium or none");
  const roots = allowedRoots(env);
  if (roots.length === 0) throw new ToolError("no allowed root is available; set SPIRAL_TRUST_ALLOWED_ROOTS");
  let real;
  try { real = realpathSync(resolve(args.path)); } catch { throw new ToolError("path does not exist or is not readable"); }
  if (!roots.some((r) => inside(r, real))) throw new ToolError("path is outside the allowed roots (set SPIRAL_TRUST_ALLOWED_ROOTS to widen it deliberately)");
  try { statSync(real); } catch { throw new ToolError("path is not readable"); }
  const scan = scanPaths({ paths: [real], mode, followSymlinks: false });
  if (!scan) return textResult("No scannable files found under that path.", { files_scanned: 0, findings: [] });
  const { report, meta } = scan;
  const counts = countsOf(report);
  const structured = {
    scanner_version: VERSION,
    mode: meta.mode,
    files_scanned: meta.included,
    files_not_scanned: meta.skipped,
    truncated: meta.truncated,
    counts,
    findings: report.findings.map((f) => ({ id: f.id, severity: f.severity, category: f.category, title: f.title, recommendation: f.recommendation })),
    fail_on: failOn,
    would_fail: exitCodeFor(report, failOn) === 1,
    target_hash: computeTargetHash(scan.scanned),
    findings_hash: computeFindingsHash(report.findings),
    limits: LIMITS_NOTE,
  };
  const lines = [`Spiral Trust Scan (${meta.mode}): ${meta.included} file(s) scanned. Critical ${counts.critical}, High ${counts.high}, Medium ${counts.medium}, Low ${counts.low}.`];
  for (const f of report.findings) lines.push(`- [${f.severity}] ${f.title}. ${f.recommendation}`);
  if (meta.truncated) lines.push(`${meta.skipped} file(s) were not scanned (scan window limit).`);
  lines.push(LIMITS_NOTE);
  return textResult(lines.join("\n"), structured);
}

async function verifyReceiptTool(args, env, deps) {
  const { receipt_id: id, receipt: given } = args;
  if (id === undefined && given === undefined) throw new InvalidParams("pass receipt_id or receipt");
  if (id !== undefined && typeof id !== "string") throw new InvalidParams("receipt_id must be a string");
  if (given !== undefined && (given === null || typeof given !== "object" || Array.isArray(given))) throw new InvalidParams("receipt must be an object");
  let receipt = given;
  if (!receipt) {
    const client = deps.client ?? await import("../src/receipt-client.mjs"); // network, only here
    const base = env.SPIRAL_TRUST_BASE_URL ? { baseUrl: env.SPIRAL_TRUST_BASE_URL } : {};
    const res = await client.fetchPublicReceipt(id, base);
    if (!res.ok) throw new ToolError(res.error);
    receipt = res.receipt;
  }
  if (!receipt || typeof receipt !== "object" || !receipt.signedPayload) throw new ToolError("the receipt has no signedPayload, so there is nothing to verify");
  const signature = args.signature ?? receipt.signature;
  if (typeof signature !== "string") throw new ToolError("no signature available: pass signature (ed25519:<hex>) or a receipt that carries one");
  const publicKey = args.public_key ?? ISSUER_PUBLIC_KEY_SPKI_B64;
  const authentic = verifyEd25519(receipt.signedPayload, signature, publicKey);
  const verdict = receipt.signedPayload.verdict;
  const rid = receipt.signedPayload.receiptId ?? id ?? null;
  const parts = [verdict && `verdict ${verdict}`, rid && `receipt ${rid}`].filter(Boolean).join(", ");
  const text = authentic
    ? `AUTHENTIC: the signature matches the issuer public key${parts ? ` (${parts})` : ""}. ${RECEIPT_NOTE}`
    : "NOT AUTHENTIC: the signature does not match this payload and key.";
  return textResult(text, { authentic, receipt_id: rid, verdict: verdict ?? null, public_key_source: args.public_key ? "argument" : "pinned", note: RECEIPT_NOTE }, false);
}

export function createServer({ env = process.env, deps = {} } = {}) {
  async function handle(msg) {
    const isRequest = msg && typeof msg === "object" && "id" in msg && msg.id !== null && typeof msg.method === "string";
    const reply = (result) => ({ jsonrpc: "2.0", id: msg.id, result });
    const fail = (code, message) => ({ jsonrpc: "2.0", id: msg?.id ?? null, error: { code, message } });
    if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return fail(-32600, "Invalid Request");
    if (!isRequest) return undefined; // notifications (e.g. notifications/initialized) get no reply
    switch (msg.method) {
      case "initialize": {
        const asked = msg.params?.protocolVersion;
        return reply({
          protocolVersion: SUPPORTED_PROTOCOLS.includes(asked) ? asked : SUPPORTED_PROTOCOLS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: SERVER_NAME, title: "Spiral Trust Scanner", version: VERSION },
          instructions: `Heuristic local scan plus offline receipt verification. ${LIMITS_NOTE}`,
        });
      }
      case "ping": return reply({});
      case "tools/list": return reply({ tools: TOOLS });
      case "tools/call": {
        const name = msg.params?.name;
        const args = msg.params?.arguments ?? {};
        if (!TOOLS.some((t) => t.name === name)) return fail(-32602, `Unknown tool: ${name}`);
        if (typeof args !== "object" || Array.isArray(args)) return fail(-32602, "arguments must be an object");
        const schema = TOOLS.find((t) => t.name === name).inputSchema;
        const extra = Object.keys(args).filter((k) => !(k in schema.properties));
        if (extra.length) return fail(-32602, `Unexpected argument(s): ${extra.join(", ")}`);
        try {
          return reply(name === "scan_path" ? scanPathTool(args, env) : await verifyReceiptTool(args, env, deps));
        } catch (err) {
          if (err instanceof InvalidParams) return fail(-32602, err.message);
          if (err instanceof ToolError) return reply(textResult(err.message, undefined, true));
          return reply(textResult("internal error while running the tool", undefined, true));
        }
      }
      default: return fail(-32601, `Method not found: ${msg.method}`);
    }
  }
  async function handleLine(line) {
    let parsed;
    try { parsed = JSON.parse(line); } catch { return { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }; }
    if (Array.isArray(parsed)) {
      const out = (await Promise.all(parsed.map(handle))).filter((r) => r !== undefined);
      return out.length ? out : undefined;
    }
    return handle(parsed);
  }
  return { handle, handleLine };
}

export function startStdio({ input = process.stdin, output = process.stdout, env = process.env } = {}) {
  const server = createServer({ env });
  const rl = createInterface({ input, crlfDelay: Infinity });
  rl.on("line", async (line) => {
    if (!line.trim()) return;
    const res = await server.handleLine(line);
    if (res !== undefined) output.write(JSON.stringify(res) + "\n");
  });
  return rl;
}

function isMain() {
  try { return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]); } catch { return false; }
}
if (isMain()) startStdio();
