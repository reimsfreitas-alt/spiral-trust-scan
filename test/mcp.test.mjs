import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, symlinkSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonical } from '../src/verify.mjs';
import { TOOLS } from '../mcp/server.mjs';
import { makeTree, RISKY } from './helpers.mjs';

const SERVER = resolve('mcp/server.mjs');

// Scripted JSON-RPC session against the real server process (stdio, newline-delimited).
function session(env = {}, cwd = process.cwd()) {
  const child = spawn(process.execPath, [SERVER], { cwd, env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map();
  let buf = '';
  let stderr = '';
  child.stderr.on('data', (d) => (stderr += d));
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      const msg = JSON.parse(line); // every stdout line must be JSON-RPC
      pending.get(msg.id)?.(msg);
    }
  });
  let id = 0;
  const call = (method, params) => new Promise((res) => { const n = ++id; pending.set(n, res); child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n'); });
  const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  const raw = (line) => child.stdin.write(line + '\n');
  const close = () => new Promise((res) => { child.on('close', () => res(stderr)); child.stdin.end(); });
  return { call, notify, raw, close, pendingFor: (n) => new Promise((res) => pending.set(n, res)) };
}

async function init(s) {
  const r = await s.call('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } });
  s.notify('notifications/initialized');
  return r;
}

test('MCP session: initialize, tools/list, tools/call scan_path', async () => {
  const dir = makeTree({ 'agent.js': RISKY });
  const s = session({ SPIRAL_TRUST_ALLOWED_ROOTS: dir });
  const init1 = await init(s);
  assert.equal(init1.result.protocolVersion, '2025-06-18');
  assert.equal(init1.result.serverInfo.name, 'spiral-trust-scanner');
  assert.ok(init1.result.capabilities.tools);

  const list = await s.call('tools/list');
  assert.deepEqual(list.result.tools.map((t) => t.name).sort(), ['scan_path', 'verify_receipt']);
  for (const t of list.result.tools) {
    assert.equal(t.inputSchema.type, 'object');
    assert.ok(t.description.length > 20);
  }

  const call = await s.call('tools/call', { name: 'scan_path', arguments: { path: dir } });
  assert.equal(call.result.isError, false);
  const sc = call.result.structuredContent;
  assert.deepEqual(sc.counts, { critical: 0, high: 2, medium: 1, low: 0 });
  assert.equal(sc.files_scanned, 1);
  assert.equal(sc.would_fail, true);
  assert.match(sc.target_hash, /^[0-9a-f]{64}$/);
  assert.match(call.result.content[0].text, /Heuristic scan/);
  assert.match(sc.limits, /not proof/);
  const stderr = await s.close();
  assert.equal(stderr, '', 'nothing is written to stderr during a normal session');
});

test('only tools that are backed by working code are exposed (no check_claim, no generate_dispute_dossier)', async () => {
  const names = TOOLS.map((t) => t.name);
  assert.deepEqual(names.sort(), ['scan_path', 'verify_receipt']);
  const s = session();
  await init(s);
  for (const name of ['check_claim', 'generate_dispute_dossier']) {
    const r = await s.call('tools/call', { name, arguments: {} });
    assert.equal(r.error.code, -32602);
  }
  await s.close();
});

test('scan_path refuses paths outside the allowed roots, including via ../ and symlinks', async () => {
  const root = makeTree({ 'ok/a.js': RISKY });
  const outside = makeTree({ 'secret.js': 'const k = 1;' });
  symlinkSync(outside, join(root, 'link'));
  const s = session({ SPIRAL_TRUST_ALLOWED_ROOTS: root });
  await init(s);
  for (const p of [outside, join(root, '..'), join(root, 'ok', '..', '..'), join(root, 'link')]) {
    const r = await s.call('tools/call', { name: 'scan_path', arguments: { path: p } });
    assert.equal(r.result.isError, true, p);
    assert.match(r.result.content[0].text, /outside the allowed roots/);
  }
  const good = await s.call('tools/call', { name: 'scan_path', arguments: { path: join(root, 'ok') } });
  assert.equal(good.result.isError, false);
  await s.close();
});

test('scan_path does not follow symlinks inside an allowed root', async () => {
  const root = makeTree({ 'a.js': 'const x = 1;' });
  const outside = makeTree({ 'leak.js': RISKY });
  symlinkSync(outside, join(root, 'linked-dir'));
  symlinkSync(join(outside, 'leak.js'), join(root, 'linked-file.js'));
  const s = session({ SPIRAL_TRUST_ALLOWED_ROOTS: root });
  await init(s);
  const r = await s.call('tools/call', { name: 'scan_path', arguments: { path: root } });
  assert.equal(r.result.structuredContent.files_scanned, 1);
  assert.equal(r.result.structuredContent.counts.high, 0);
  await s.close();
});

test('default allowed root is the working directory', async () => {
  const dir = makeTree({ 'a.js': RISKY });
  const s = session({ SPIRAL_TRUST_ALLOWED_ROOTS: '' }, dir);
  await init(s);
  assert.equal((await s.call('tools/call', { name: 'scan_path', arguments: { path: '.' } })).result.isError, false);
  assert.equal((await s.call('tools/call', { name: 'scan_path', arguments: { path: tmpdir() } })).result.isError, true);
  await s.close();
});

test('protocol errors: bad params, unknown method, parse error, unknown tool, extra arguments', async () => {
  const s = session();
  await init(s);
  assert.equal((await s.call('tools/call', { name: 'scan_path', arguments: {} })).error.code, -32602);
  assert.equal((await s.call('tools/call', { name: 'scan_path', arguments: { path: '.', mode: 'turbo' } })).error.code, -32602);
  assert.equal((await s.call('tools/call', { name: 'scan_path', arguments: { path: '.', surprise: 1 } })).error.code, -32602);
  assert.equal((await s.call('nope/nothing')).error.code, -32601);
  assert.deepEqual((await s.call('ping')).result, {});
  const parse = s.pendingFor(null);
  s.raw('{not json');
  assert.equal((await parse).error.code, -32700);
  await s.close();
});

test('an unknown protocol version is answered with a version the server supports', async () => {
  const s = session();
  const r = await s.call('initialize', { protocolVersion: '1999-01-01', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  assert.ok(['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'].includes(r.result.protocolVersion));
  await s.close();
});

test('verify_receipt verifies a signed receipt offline, with an explicit public key, and rejects tampering', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const signedPayload = { receiptId: 'rcpt_t', verdict: 'RECORDED', counts: { high: 1 } };
  const signature = 'ed25519:' + sign(null, Buffer.from(canonical(signedPayload)), privateKey).toString('hex');
  const s = session();
  await init(s);
  const good = await s.call('tools/call', { name: 'verify_receipt', arguments: { receipt: { signedPayload }, signature, public_key: spki } });
  assert.equal(good.result.isError, false);
  assert.equal(good.result.structuredContent.authentic, true);
  assert.match(good.result.content[0].text, /^AUTHENTIC/);
  assert.match(good.result.content[0].text, /not proof that the code is secure/);
  const bad = await s.call('tools/call', { name: 'verify_receipt', arguments: { receipt: { signedPayload: { ...signedPayload, verdict: 'OTHER' } }, signature, public_key: spki } });
  assert.equal(bad.result.structuredContent.authentic, false);
  assert.match(bad.result.content[0].text, /^NOT AUTHENTIC/);
  const wrongKey = await s.call('tools/call', { name: 'verify_receipt', arguments: { receipt: { signedPayload }, signature } }); // pinned issuer key, not ours
  assert.equal(wrongKey.result.structuredContent.authentic, false);
  assert.equal(wrongKey.result.structuredContent.public_key_source, 'pinned');
  const noSig = await s.call('tools/call', { name: 'verify_receipt', arguments: { receipt: { signedPayload } } });
  assert.equal(noSig.result.isError, true);
  const none = await s.call('tools/call', { name: 'verify_receipt', arguments: {} });
  assert.equal(none.error.code, -32602);
  await s.close();
});

test('verify_receipt by id fetches the public receipt from the configured base URL and verifies it', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const signedPayload = { receiptId: 'rcpt_net', verdict: 'RECORDED' };
  const signature = 'ed25519:' + sign(null, Buffer.from(canonical(signedPayload)), privateKey).toString('hex');
  const urls = [];
  const server = createServer((req, res) => { urls.push(req.url); res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ signedPayload, signature })); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const s = session({ SPIRAL_TRUST_BASE_URL: `http://127.0.0.1:${server.address().port}` });
    await init(s);
    const r = await s.call('tools/call', { name: 'verify_receipt', arguments: { receipt_id: 'rcpt_net', public_key: spki } });
    assert.equal(r.result.structuredContent.authentic, true);
    assert.deepEqual(urls, ['/api/v1/public/receipt?id=rcpt_net']);
    await s.close();
  } finally { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); }
});

test('verify_receipt reports a network failure as a tool error, not a crash', async () => {
  const dead = createServer(() => {});
  await new Promise((r) => dead.listen(0, '127.0.0.1', r));
  const port = dead.address().port;
  await new Promise((r) => dead.close(r));
  const s = session({ SPIRAL_TRUST_BASE_URL: `http://127.0.0.1:${port}` });
  await init(s);
  const r = await s.call('tools/call', { name: 'verify_receipt', arguments: { receipt_id: 'rcpt_x' } });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /could not reach the receipt service/);
  assert.deepEqual((await s.call('ping')).result, {}, 'the server keeps running');
  await s.close();
});
