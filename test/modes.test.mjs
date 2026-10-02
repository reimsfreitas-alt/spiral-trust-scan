import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanPaths, SURFACE_CHARS, DEEP_MAX_WINDOWS } from '../src/scan.mjs';
import { run, parseArgs } from '../bin/trust-scan.mjs';
import { makeTree, RISKY } from './helpers.mjs';

test('quick and deep are identical when everything fits in one window', () => {
  const dir = makeTree({ 'a.js': RISKY });
  const q = scanPaths({ paths: [dir], mode: 'quick' });
  const d = scanPaths({ paths: [dir], mode: 'deep' });
  assert.deepEqual(d.report.findings, q.report.findings);
  assert.equal(d.meta.windows, 1);
});

test('deep scans files that quick leaves out, and says so', () => {
  const filler = 'const x = 1;\n'.repeat(5000); // about 65 KB
  const dir = makeTree({ 'a.js': filler, 'b.js': filler, 'c.js': `${RISKY}\nconst k = "sk_live_abcdef123456";` });
  const q = scanPaths({ paths: [dir], mode: 'quick' });
  const d = scanPaths({ paths: [dir], mode: 'deep' });
  assert.equal(q.meta.truncated, true);
  assert.equal(q.meta.included, 1);
  assert.ok(!q.report.findings.some((f) => f.id === 'secret-exposure'), 'quick never reached c.js');
  assert.equal(d.meta.included, 3);
  assert.equal(d.meta.truncated, false);
  assert.ok(d.meta.windows >= 2);
  assert.ok(d.report.findings.some((f) => f.id === 'secret-exposure'), 'deep reached c.js');
});

test('deep stops at the window cap and reports what was not scanned', () => {
  const chunk = 'a'.repeat(SURFACE_CHARS - 200);
  const files = {};
  for (let i = 0; i < DEEP_MAX_WINDOWS + 3; i++) files[`f${String(i).padStart(2, '0')}.js`] = chunk;
  const d = scanPaths({ paths: [makeTree(files)], mode: 'deep' });
  assert.equal(d.meta.windows, DEEP_MAX_WINDOWS);
  assert.equal(d.meta.included, DEEP_MAX_WINDOWS);
  assert.equal(d.meta.truncated, true);
  assert.equal(d.meta.skipped, 3);
});

test('deep merges findings by id and drops partial-assurance when a HIGH finding exists', () => {
  const filler = 'const x = 1;\n'.repeat(5000);
  const governed = 'function tool_call() {}\nconst policy = authorize(); const ledger = receipt;';
  const dir = makeTree({ 'a.js': governed, 'b.js': filler, 'c.js': filler, 'd.js': RISKY });
  const d = scanPaths({ paths: [dir], mode: 'deep' });
  const ids = d.report.findings.map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length, 'one finding per id');
  assert.ok(ids.includes('authorization-gap'));
  assert.ok(!ids.includes('partial-assurance'));
  assert.equal(d.report.summary.highFindings, d.report.findings.filter((f) => f.severity === 'HIGH').length);
});

test('--mode is validated and reaches the CLI report', () => {
  assert.ok(parseArgs(['--mode', 'turbo']).error);
  assert.equal(parseArgs(['--mode', 'deep']).opts.mode, 'deep');
  const dir = makeTree({ 'a.js': RISKY });
  const out = [];
  assert.equal(run([dir, '--mode', 'deep', '--format', 'json', '--fail-on', 'none'], {}, (t) => out.push(t)), 0);
  const j = JSON.parse(out[0]);
  assert.equal(j.meta.mode, 'deep');
  assert.match(j.meta.target_hash, /^[0-9a-f]{64}$/);
  assert.match(j.meta.findings_hash, /^[0-9a-f]{64}$/);
});

test('"--" ends option parsing so a path that starts with a dash is treated as a path', () => {
  const p = parseArgs(['--fail-on', 'none', '--', '--weird-dir']);
  assert.deepEqual(p.opts.paths, ['--weird-dir']);
});
