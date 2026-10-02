import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildReceiptPayload, submitReceipt, parseReceiptResponse, fetchPublicReceipt } from '../src/receipt-client.mjs';
import { main } from '../bin/trust-scan.mjs';
import { makeTree, RISKY } from './helpers.mjs';

const SIG = 'ed25519:' + 'ab'.repeat(64);
const GOOD = (over = {}) => ({
  receipt_id: 'rcpt_mock-1234',
  issued_at: '2026-10-02T12:00:00.000Z',
  signature: SIG,
  verdict: 'RECORDED',
  validation_url: 'https://example.test/verify/rcpt_mock-1234',
  badge_url: 'https://example.test/badge/rcpt_mock-1234.svg',
  ...over,
});

// Local mock of POST /api/v1/public/scan-receipt (the contract owned by the Matrix side).
async function mockServer(handler) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      handler(req, res, body);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, endpoint: `${base}/api/v1/public/scan-receipt`, seen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
const ok = (obj) => (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

const payloadArgs = () => ({ targetHash: 'a'.repeat(64), findingsHash: 'b'.repeat(64), counts: { critical: 0, high: 2, medium: 1, low: 0 }, threshold: 'high', filesScanned: 3 });

test('payload matches the server contract exactly, and source is only added when given', () => {
  const p = buildReceiptPayload(payloadArgs());
  assert.deepEqual(Object.keys(p).sort(), ['counts', 'files_scanned', 'findings_hash', 'scanner_version', 'target_hash', 'threshold']);
  assert.deepEqual(p.counts, { critical: 0, high: 2, medium: 1, low: 0 });
  assert.equal(p.threshold, 'high');
  assert.match(p.scanner_version, /^\d+\.\d+\.\d+/);
  const withSource = buildReceiptPayload({ ...payloadArgs(), source: { repo: 'o/r', commit: 'abc' } });
  assert.deepEqual(withSource.source, { repo: 'o/r', commit: 'abc' });
  assert.ok(!('source' in buildReceiptPayload({ ...payloadArgs(), source: { repo: undefined, commit: undefined } })));
  assert.throws(() => buildReceiptPayload({ ...payloadArgs(), targetHash: 'xyz' }), /64 hex/);
  assert.throws(() => buildReceiptPayload({ ...payloadArgs(), threshold: 'severe' }), /threshold/);
});

test('submitReceipt POSTs JSON to the endpoint and returns the validated receipt', async () => {
  const srv = await mockServer(ok(GOOD()));
  try {
    const res = await submitReceipt(buildReceiptPayload(payloadArgs()), { endpoint: srv.endpoint });
    assert.equal(res.ok, true);
    assert.equal(res.data.receipt_id, 'rcpt_mock-1234');
    assert.equal(srv.seen.length, 1);
    assert.equal(srv.seen[0].method, 'POST');
    assert.equal(srv.seen[0].url, '/api/v1/public/scan-receipt');
    assert.match(srv.seen[0].headers['content-type'], /application\/json/);
    const sent = JSON.parse(srv.seen[0].body);
    assert.equal(sent.target_hash, 'a'.repeat(64));
    assert.ok(!('source' in sent));
  } finally { await srv.close(); }
});

test('submitReceipt never throws: HTTP errors, bad JSON, wrong shape, timeouts and refused connections all return ok:false', async () => {
  const cases = [
    [(req, res) => { res.writeHead(500); res.end('boom'); }, /HTTP 500/],
    [(req, res) => { res.writeHead(200); res.end('not json'); }, /not JSON/],
    [ok({ receipt_id: 'x' }), /unexpected response shape/],
    [ok(GOOD({ validation_url: 'javascript:alert(1)' })), /unexpected response shape/],
    [ok(GOOD({ receipt_id: 'bad id\nwith newline' })), /unexpected response shape/],
  ];
  for (const [handler, pattern] of cases) {
    const srv = await mockServer(handler);
    try {
      const res = await submitReceipt(buildReceiptPayload(payloadArgs()), { endpoint: srv.endpoint });
      assert.equal(res.ok, false);
      assert.match(res.error, pattern);
    } finally { await srv.close(); }
  }
  const slow = await mockServer(() => { /* never answers */ });
  try {
    const res = await submitReceipt(buildReceiptPayload(payloadArgs()), { endpoint: slow.endpoint, timeoutMs: 150 });
    assert.equal(res.ok, false);
    assert.match(res.error, /no answer within 150 ms/);
  } finally { await slow.close(); }
  const dead = await mockServer(ok({}));
  const endpoint = dead.endpoint;
  await dead.close();
  const refused = await submitReceipt(buildReceiptPayload(payloadArgs()), { endpoint });
  assert.equal(refused.ok, false);
  assert.match(refused.error, /could not reach the receipt service/);
});

test('a redirect is not followed (the digest is never forwarded to another host)', async () => {
  const srv = await mockServer((req, res) => { res.writeHead(302, { location: 'https://example.test/elsewhere' }); res.end(); });
  try {
    const res = await submitReceipt(buildReceiptPayload(payloadArgs()), { endpoint: srv.endpoint });
    assert.equal(res.ok, false);
  } finally { await srv.close(); }
});

test('parseReceiptResponse keeps only validated fields', () => {
  const d = parseReceiptResponse({ ...GOOD(), extra: 'ignored', verdict: '<script>' });
  assert.ok(!('extra' in d));
  assert.ok(!('verdict' in d));
  assert.equal(parseReceiptResponse(GOOD({ signature: 'ed25519:short' })), null);
  assert.equal(parseReceiptResponse(null), null);
  assert.ok(!('badge_url' in parseReceiptResponse(GOOD({ badge_url: 'http://insecure.test/b.svg' }))));
});

test('CLI --receipt: prints validation URL and badge markdown, sends only digests and counts, exit code follows the scan', async () => {
  const srv = await mockServer(ok(GOOD()));
  try {
    const dir = makeTree({ 'agent.js': RISKY });
    const lines = [];
    const code = await main([dir, '--receipt', '--receipt-endpoint', srv.endpoint], {}, (t) => lines.push(t));
    assert.equal(code, 1, 'HIGH finding still fails at the default threshold');
    const text = lines.join('\n');
    assert.match(text, /Validation: https:\/\/example\.test\/verify\/rcpt_mock-1234/);
    assert.match(text, /\[!\[Spiral Trust Scan receipt\]\(https:\/\/example\.test\/badge\/rcpt_mock-1234\.svg\)\]\(https:\/\/example\.test\/verify\/rcpt_mock-1234\)/);
    assert.match(text, /nothing is inserted automatically/);
    assert.match(text, /not proof that the code is secure/);
    const sent = JSON.parse(srv.seen[0].body);
    assert.deepEqual(Object.keys(sent).sort(), ['counts', 'files_scanned', 'findings_hash', 'scanner_version', 'target_hash', 'threshold']);
    assert.equal(sent.threshold, 'high');
    assert.equal(sent.files_scanned, 1);
    assert.ok(!srv.seen[0].body.includes('agent.js'), 'no file paths are sent');
    assert.ok(!srv.seen[0].body.includes('fetch('), 'no source code is sent');
  } finally { await srv.close(); }
});

test('CLI --receipt with the network down: warning only, scan output and exit code are unchanged', async () => {
  const dead = await mockServer(ok({}));
  const endpoint = dead.endpoint;
  await dead.close();
  const dir = makeTree({ 'agent.js': RISKY });
  const withReceipt = [];
  const codeWith = await main([dir, '--receipt', '--receipt-endpoint', endpoint, '--format', 'json'], {}, (t) => withReceipt.push(t));
  const without = [];
  const codeWithout = await main([dir, '--format', 'json'], {}, (t) => without.push(t));
  assert.equal(codeWith, codeWithout);
  assert.equal(codeWith, 1);
  const a = JSON.parse(withReceipt[0]);
  const b = JSON.parse(without[0]);
  assert.match(a.receipt.error, /could not reach the receipt service/);
  assert.deepEqual(a.findings, b.findings);
  assert.equal(a.meta.target_hash, b.meta.target_hash);
  const clean = makeTree({ 'b.js': 'const x = 1;' });
  assert.equal(await main([clean, '--receipt', '--receipt-endpoint', endpoint], {}, () => {}), 0, 'clean code still exits 0');
});

test('CLI --receipt: a client that throws is contained too', async () => {
  const dir = makeTree({ 'agent.js': RISKY });
  const out = [];
  const code = await main([dir, '--receipt', '--format', 'json'], {}, (t) => out.push(t), { client: { buildReceiptPayload: () => { throw new Error('bug in client'); }, submitReceipt: () => { throw new Error('unreachable'); } } });
  assert.equal(code, 1);
  assert.match(JSON.parse(out[0]).receipt.error, /bug in client/);
});

test('--include-source sends repo and commit from the GitHub env; without it nothing identifying is sent', async () => {
  const srv = await mockServer(ok(GOOD()));
  try {
    const dir = makeTree({ 'agent.js': RISKY });
    const env = { GITHUB_REPOSITORY: 'owner/name', GITHUB_SHA: 'deadbeef' };
    await main([dir, '--receipt', '--receipt-endpoint', srv.endpoint, '--fail-on', 'none'], env, () => {});
    assert.ok(!('source' in JSON.parse(srv.seen[0].body)));
    await main([dir, '--receipt', '--include-source', '--receipt-endpoint', srv.endpoint, '--fail-on', 'none'], env, () => {});
    assert.deepEqual(JSON.parse(srv.seen[1].body).source, { repo: 'owner/name', commit: 'deadbeef' });
  } finally { await srv.close(); }
});

test('without --receipt no request is made (the mock sees nothing)', async () => {
  const srv = await mockServer(ok(GOOD()));
  try {
    await main([makeTree({ 'agent.js': RISKY }), '--fail-on', 'none', '--receipt-endpoint', srv.endpoint], {}, () => {});
    assert.equal(srv.seen.length, 0);
  } finally { await srv.close(); }
});

test('the Job Summary and outputs carry the receipt when one was created', async () => {
  const srv = await mockServer(ok(GOOD()));
  try {
    const tmp = mkdtempSync(join(tmpdir(), 'gh-'));
    const env = { GITHUB_STEP_SUMMARY: join(tmp, 'summary.md'), GITHUB_OUTPUT: join(tmp, 'output.txt') };
    await main([makeTree({ 'agent.js': RISKY }), '--receipt', '--receipt-endpoint', srv.endpoint, '--fail-on', 'none'], env, () => {});
    const summary = readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8');
    assert.match(summary, /\*\*Receipt:\*\* \[https:\/\/example\.test\/verify\/rcpt_mock-1234\]/);
    assert.match(summary, /Heuristic, not proof/);
    const outputs = readFileSync(env.GITHUB_OUTPUT, 'utf8');
    assert.match(outputs, /^receipt_id=rcpt_mock-1234$/m);
    assert.match(outputs, /^validation_url=https:\/\/example\.test\/verify\/rcpt_mock-1234$/m);
  } finally { await srv.close(); }
});

test('fetchPublicReceipt validates the id and reads the public receipt', async () => {
  const srv = await mockServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ signedPayload: { receiptId: 'rcpt_1' } })); });
  try {
    const res = await fetchPublicReceipt('rcpt_1', { baseUrl: srv.base });
    assert.equal(res.ok, true);
    assert.equal(srv.seen[0].url, '/api/v1/public/receipt?id=rcpt_1');
    assert.equal((await fetchPublicReceipt('../../etc/passwd', { baseUrl: srv.base })).ok, false);
    assert.equal(srv.seen.length, 1, 'a malformed id never reaches the network');
  } finally { await srv.close(); }
});
