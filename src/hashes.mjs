// Digests that identify what was scanned and what was found. Pure functions: no
// network, no filesystem. A third party can recompute both from the same files.
import { createHash } from "node:crypto";
import { canonical } from "./verify.mjs";

const sha256 = (x) => createHash("sha256").update(x).digest("hex");

// target_hash: sha256 over the scanned files, sorted by relative path (POSIX
// separators, relative to the scan root). For each file the hash input is
//   path "\0" byteLength "\0" raw-bytes "\n"
// Only files that were actually inside the scan window are included, so a
// truncated scan yields a hash of what was scanned, not of the whole tree.
export function computeTargetHash(files) {
  const h = createHash("sha256");
  const sorted = [...files].sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  for (const f of sorted) {
    h.update(f.rel);
    h.update("\0");
    h.update(String(f.buf.length));
    h.update("\0");
    h.update(f.buf);
    h.update("\n");
  }
  return h.digest("hex");
}

// findings_hash: sha256 of the canonical JSON (sorted keys, no whitespace) of the
// findings array, ordered by finding id.
export function computeFindingsHash(findings) {
  const ordered = [...findings].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return sha256(canonical(ordered));
}

export function countsOf(report) {
  const s = report.summary;
  return { critical: s.criticalFindings, high: s.highFindings, medium: s.mediumFindings, low: s.lowFindings };
}
