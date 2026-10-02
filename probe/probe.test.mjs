import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("probe classifies CONFIRMED / DEVIATED / INCONCLUSIVE and does not follow redirects", async () => {
  const srv = http.createServer((q, s) => {
    if (q.url === "/ok") { s.writeHead(200, { "content-type": "text/html" }); return s.end("<h1>hello world</h1>"); }
    if (q.url === "/redir") { s.writeHead(307, { location: "/page/" }); return s.end("Redirecting"); }
    s.writeHead(200); s.end("storefront (soft 404)");
  });
  await new Promise((r) => srv.listen(0, r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const dir = mkdtempSync(join(tmpdir(), "probe-"));
  writeFileSync(join(dir, "t.json"), JSON.stringify({ targets: [
    { id: "a", url: base + "/ok", expect_status: 200, body_contains: ["hello"] },
    { id: "b", url: base + "/missing", expect_status: 404 },
    { id: "c", url: base + "/redir", expect_status: 200 },
    { id: "d", url: base + "/ok", body_not_contains: ["hello"] },
    { id: "e", url: "http://127.0.0.1:1/nope", expect_status: 200 },
    { id: "f", url: base + "/ok" }
  ] }));
  // run the script in a child process (async, so the in-process server keeps serving)
  const { spawn } = await import("node:child_process");
  await new Promise((res, rej) => { const p = spawn("node", ["probe/probe.mjs", join(dir, "t.json"), join(dir, "out.json")]); p.on("exit", res); p.on("error", rej); });
  srv.close();
  const out = JSON.parse(readFileSync(join(dir, "out.json"), "utf8"));
  const v = Object.fromEntries(out.results.map((r) => [r.id, r.verdict]));
  assert.deepEqual(v, { a: "CONFIRMED", b: "DEVIATED", c: "DEVIATED", d: "DEVIATED", e: "INCONCLUSIVE", f: "OBSERVED" });
  assert.equal(out.results.find((r) => r.id === "c").status, 307);
  assert.equal(out.results.find((r) => r.id === "c").location, "/page/");
});
