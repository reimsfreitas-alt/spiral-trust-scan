// Independent HTTP observer. Reads probe/targets.json, requests every URL from a GitHub runner
// (which has open internet), and writes probe/out/latest.json. It only observes: GET/POST with no secrets,
// redirects are NOT followed, so a 307 shows up as 307. Verdicts: CONFIRMED / DEVIATED / INCONCLUSIVE.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";

const targetsPath = process.argv[2] || "probe/targets.json";
const outPath = process.argv[3] || "probe/out/latest.json";
const cfg = JSON.parse(readFileSync(targetsPath, "utf8"));
const TIMEOUT_MS = 15000;

async function observe(t) {
  const started = Date.now();
  const res = { id: t.id ?? null, method: t.method || "GET", url: t.url, observed_at: new Date().toISOString() };
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    const r = await fetch(t.url, {
      method: res.method,
      redirect: "manual",
      headers: { "user-agent": "spiral-probe/1 (independent observer)", ...(t.headers || {}) },
      body: t.body === undefined ? undefined : JSON.stringify(t.body),
      signal: ctl.signal,
    });
    clearTimeout(timer);
    const text = await r.text();
    res.status = r.status;
    res.content_type = r.headers.get("content-type");
    res.location = r.headers.get("location");
    res.body_head = text.slice(0, 200);
    res.body_sha256 = createHash("sha256").update(text).digest("hex");
    res.body_bytes = text.length;
    res.ms = Date.now() - started;
    const problems = [];
    if (t.expect_status !== undefined) {
      const ok = Array.isArray(t.expect_status) ? t.expect_status.includes(r.status) : t.expect_status === r.status;
      if (!ok) problems.push(`status ${r.status} != ${JSON.stringify(t.expect_status)}`);
    }
    for (const s of t.body_contains || []) if (!text.includes(s)) problems.push(`body lacks "${s}"`);
    for (const s of t.body_not_contains || []) if (text.includes(s)) problems.push(`body has forbidden "${s}"`);
    if (t.expect_location !== undefined && res.location !== t.expect_location) problems.push(`location ${res.location} != ${t.expect_location}`);
    res.problems = problems;
    res.verdict = t.expect_status === undefined && !(t.body_contains || []).length && !(t.body_not_contains || []).length ? "OBSERVED" : problems.length ? "DEVIATED" : "CONFIRMED";
  } catch (e) {
    res.error = String(e && e.message ? e.message : e);
    res.verdict = "INCONCLUSIVE";
  }
  return res;
}

const results = [];
for (const t of cfg.targets) results.push(await observe(t));
const summary = results.reduce((a, r) => ((a[r.verdict] = (a[r.verdict] || 0) + 1), a), {});
const out = { schema: "spiral.probe.v1", run_at: new Date().toISOString(), runner: process.env.GITHUB_RUN_ID ? `github-actions:${process.env.GITHUB_RUN_ID}` : "local", summary, results };
mkdirSync(outPath.replace(/\/[^/]*$/, "") || ".", { recursive: true });
writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
console.log(JSON.stringify(summary));
for (const r of results) console.log(`${r.verdict.padEnd(12)} ${String(r.status ?? "-").padEnd(4)} ${r.method} ${r.url}${r.problems && r.problems.length ? "  <- " + r.problems.join("; ") : ""}${r.error ? "  <- " + r.error : ""}`);
