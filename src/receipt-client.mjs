// Spiral Trust Scan: the ONLY module that uses the network.
//
// The core scan (src/core.mjs, src/scan.mjs, bin/trust-scan.mjs ...) has no network
// code, and test/no-network.test.mjs enforces that. This file is the one named
// exemption, and it is only ever loaded through a dynamic import():
//   - when the user passes --receipt (or sets the Action input receipt: true), or
//   - when the MCP tool verify_receipt fetches a public receipt.
// It is opt-in: it never runs as a side effect of a plain scan.
//
// What is sent by submitReceipt: scanner_version, two sha256 digests, finding counts,
// the fail-on threshold, the number of files scanned and, only if the user asked for
// it (--include-source), the repository name and commit. No file paths, no source
// code, no finding text. Everything else stays on the machine.
//
// The receipt is best-effort: submitReceipt never throws; a network failure returns
// { ok: false, error } and the caller must leave the scan result and exit code alone.
import { VERSION } from "./version.mjs";

export const DEFAULT_BASE_URL = "https://spiral-os-matrix-current.vercel.app";
export const SCAN_RECEIPT_PATH = "/api/v1/public/scan-receipt";
export const PUBLIC_RECEIPT_PATH = "/api/v1/public/receipt";
export const DEFAULT_ENDPOINT = DEFAULT_BASE_URL + SCAN_RECEIPT_PATH;
export const DEFAULT_TIMEOUT_MS = 10_000;

const HEX64 = /^[0-9a-f]{64}$/;
const RECEIPT_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const SIGNATURE = /^ed25519:[0-9a-f]{128}$/;
const THRESHOLDS = new Set(["critical", "high", "medium", "none"]);

// Builds the exact JSON body of the server contract. Throws on a malformed input so a
// bug here surfaces in tests instead of as a silent bad request.
export function buildReceiptPayload({ targetHash, findingsHash, counts, threshold, filesScanned, source }) {
  if (!HEX64.test(targetHash)) throw new Error("target_hash must be 64 hex characters");
  if (!HEX64.test(findingsHash)) throw new Error("findings_hash must be 64 hex characters");
  if (!THRESHOLDS.has(threshold)) throw new Error("threshold must be critical, high, medium or none");
  if (!Number.isInteger(filesScanned) || filesScanned < 0) throw new Error("files_scanned must be a non-negative integer");
  const payload = {
    scanner_version: VERSION,
    target_hash: targetHash,
    findings_hash: findingsHash,
    counts: { critical: counts.critical, high: counts.high, medium: counts.medium, low: counts.low },
    threshold,
    files_scanned: filesScanned,
  };
  if (source && (source.repo || source.commit)) {
    payload.source = {};
    if (source.repo) payload.source.repo = String(source.repo);
    if (source.commit) payload.source.commit = String(source.commit);
  }
  return payload;
}

const isHttpsUrl = (v) => {
  try { return new URL(v).protocol === "https:"; } catch { return false; }
};

// Accepts only a response that matches the contract; anything else is "unexpected".
export function parseReceiptResponse(body) {
  if (!body || typeof body !== "object") return null;
  const { receipt_id, issued_at, signature, verdict, validation_url, badge_url } = body;
  if (typeof receipt_id !== "string" || !RECEIPT_ID.test(receipt_id)) return null;
  if (typeof signature !== "string" || !SIGNATURE.test(signature)) return null;
  if (typeof validation_url !== "string" || !isHttpsUrl(validation_url)) return null;
  if (typeof issued_at !== "string" || issued_at.length > 64 || /[\r\n]/.test(issued_at)) return null;
  const out = { receipt_id, issued_at, signature, validation_url };
  if (typeof verdict === "string" && /^[A-Za-z0-9_ -]{1,32}$/.test(verdict)) out.verdict = verdict;
  if (typeof badge_url === "string" && isHttpsUrl(badge_url)) out.badge_url = badge_url;
  return out;
}

async function readBody(res) {
  const text = await res.text();
  return text.slice(0, 65_536);
}

export async function submitReceipt(payload, { endpoint = DEFAULT_ENDPOINT, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = globalThis.fetch } = {}) {
  try {
    const res = await fetchImpl(endpoint, {
      method: "POST",
      redirect: "error", // never follow a redirect with the digest to another host
      headers: { "content-type": "application/json", "user-agent": `spiral-trust-scanner/${VERSION}`, connection: "close" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await readBody(res);
    if (!res.ok) return { ok: false, error: `receipt service answered HTTP ${res.status}` };
    let json;
    try { json = JSON.parse(text); } catch { return { ok: false, error: "receipt service returned a body that is not JSON" }; }
    const data = parseReceiptResponse(json);
    if (!data) return { ok: false, error: "receipt service returned an unexpected response shape" };
    return { ok: true, data };
  } catch (err) {
    const reason = err?.name === "TimeoutError" || err?.name === "AbortError" ? `no answer within ${timeoutMs} ms` : (err?.cause?.code || err?.message || "network error");
    return { ok: false, error: `could not reach the receipt service (${String(reason).slice(0, 120)})` };
  }
}

// Fetches the public receipt record (GET /api/v1/public/receipt?id=...). Used by the MCP
// verify_receipt tool; the signature is then checked offline by src/verify.mjs.
export async function fetchPublicReceipt(id, { baseUrl = DEFAULT_BASE_URL, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = globalThis.fetch } = {}) {
  if (typeof id !== "string" || !RECEIPT_ID.test(id)) return { ok: false, error: "receipt id has an unexpected format" };
  try {
    const res = await fetchImpl(`${baseUrl}${PUBLIC_RECEIPT_PATH}?id=${encodeURIComponent(id)}`, {
      method: "GET",
      redirect: "error",
      headers: { accept: "application/json", "user-agent": `spiral-trust-scanner/${VERSION}`, connection: "close" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await readBody(res);
    if (!res.ok) return { ok: false, error: `receipt service answered HTTP ${res.status}` };
    try { return { ok: true, receipt: JSON.parse(text) }; } catch { return { ok: false, error: "receipt service returned a body that is not JSON" }; }
  } catch (err) {
    const reason = err?.name === "TimeoutError" || err?.name === "AbortError" ? `no answer within ${timeoutMs} ms` : (err?.cause?.code || err?.message || "network error");
    return { ok: false, error: `could not reach the receipt service (${String(reason).slice(0, 120)})` };
  }
}
