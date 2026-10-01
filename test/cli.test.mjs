import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeTrustSurface as cliAnalyze } from '../src/core.mjs';
import { run, parseArgs, exitCodeFor, collectFiles } from '../bin/trust-scan.mjs';

test('CLI scans a directory, skips node_modules, and exits 1 on a HIGH finding by default', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tscan-'));
  mkdirSync(join(dir, 'node_modules', 'x'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', 'x', 'index.js'), `fetch('/a'); stripe.charge()`);
  writeFileSync(join(dir, 'agent.js'), `function runAction() { return fetch('/api/execute'); }`);
  const files = collectFiles([dir]);
  assert.equal(files.length, 1);
  const lines = [];
  const code = run([dir], {}, (t) => lines.push(t));
  assert.equal(code, 1);
  const text = lines.join('\n');
  assert.match(text, /Heuristic scan/);
  assert.match(text, /nothing leaves your machine/);
});

test('CLI exits 0 with --fail-on none, and a clean file has no HIGH finding', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tscan-'));
  writeFileSync(join(dir, 'a.js'), `fetch('/a')`);
  assert.equal(run([dir, '--fail-on', 'none'], {}, () => {}), 0);
  const clean = mkdtempSync(join(tmpdir(), 'tscan-'));
  writeFileSync(join(clean, 'b.js'), `const x = 1;`);
  assert.equal(run([clean], {}, () => {}), 0);
});

test('CLI json and markdown formats are well formed, and secrets are never echoed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tscan-'));
  writeFileSync(join(dir, 'a.js'), `const k = "sk_live_SUPERSECRET123"; fetch('/a')`);
  const json = [];
  run([dir, '--format', 'json', '--fail-on', 'none'], {}, (t) => json.push(t));
  const parsed = JSON.parse(json[0]);
  assert.ok(parsed.findings.length > 0);
  assert.ok(!json[0].includes('SUPERSECRET123'));
  const md = [];
  run([dir, '--format', 'markdown', '--fail-on', 'none'], {}, (t) => md.push(t));
  assert.match(md[0], /^## Spiral Trust Scan/);
  assert.ok(!md[0].includes('SUPERSECRET123'));
});

test('argument errors exit 2 and truncation is reported honestly', () => {
  assert.equal(run(['--nope'], {}, () => {}), 2);
  assert.equal(parseArgs(['--format', 'xml']).error !== undefined, true);
  const dir = mkdtempSync(join(tmpdir(), 'tscan-'));
  const big = 'x'.repeat(150 * 1024);
  writeFileSync(join(dir, 'a.js'), `fetch('/a');\n${big}`);
  writeFileSync(join(dir, 'b.js'), `${big}`);
  const out = [];
  run([dir, '--fail-on', 'none'], {}, (t) => out.push(t));
  assert.match(out[0], /were not scanned/);
});

test('exitCodeFor honours thresholds', () => {
  const rep = { findings: [{ severity: 'MEDIUM' }] };
  assert.equal(exitCodeFor(rep, 'high'), 0);
  assert.equal(exitCodeFor(rep, 'medium'), 1);
});

test('the CLI package contains no network code (the "nothing leaves your machine" claim is checked, not asserted)', () => {
  const root = process.cwd();
  const files = ['bin/trust-scan.mjs', 'src/core.mjs'];
  for (const f of files) {
    const text = readFileSync(join(root, f), 'utf8');
    assert.ok(!/\bfetch\s*\(/.test(text.replace(/\/\/.*$/gm, '').replace(/'[^']*'|"[^"]*"|`[^`]*`/g, '')) , `${f} must not call fetch`);
    assert.ok(!/from\s+['"]node:(http|https|net|dgram|tls)['"]/.test(text), `${f} must not import network modules`);
  }
  assert.ok(readdirSync(root).includes('action.yml'));
});

test('code that merely parses an Authorization header is not reported as leaked credentials; a real-looking Bearer literal still is', () => {
  const parsesHeader = `const key = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : null; fetch(\`\${url}\`, { headers: { Authorization: \`Bearer \${key}\` } })`;
  for (const analyze of [cliAnalyze]) {
    assert.ok(!analyze('repo', 't', parsesHeader).findings.some((f) => f.id === 'secret-exposure'));
    assert.ok(analyze('repo', 't', 'Authorization: Bearer abcdef0123456789abcdef.xyz').findings.some((f) => f.id === 'secret-exposure'));
    assert.ok(analyze('repo', 't', 'k = "sk_live_abc123"').findings.some((f) => f.id === 'secret-exposure'));
  }
});

import { generateKeyPairSync, sign } from 'node:crypto';
import { canonical, verifyEd25519 } from '../bin/verify-receipt.mjs';

test('verify-receipt: an Ed25519 signature over the canonical payload verifies offline, and any change breaks it', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const payload = { receiptId: 'rcpt_x', verdict: 'CONFIRMED', claim: { b: 1, a: 2 } };
  const sig = 'ed25519:' + sign(null, Buffer.from(canonical(payload)), privateKey).toString('hex');
  assert.equal(verifyEd25519({ claim: { a: 2, b: 1 }, verdict: 'CONFIRMED', receiptId: 'rcpt_x' }, sig, spki), true); // key order irrelevant
  assert.equal(verifyEd25519({ ...payload, verdict: 'DEVIATED' }, sig, spki), false);
  assert.equal(verifyEd25519(payload, 'ed25519:' + '0'.repeat(128), spki), false);
});
