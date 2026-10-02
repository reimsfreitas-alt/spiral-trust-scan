import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { scanPaths } from '../src/scan.mjs';
import { computeTargetHash, computeFindingsHash } from '../src/hashes.mjs';
import { makeTree, RISKY } from './helpers.mjs';

const hashesOf = (dir, mode = 'quick') => {
  const s = scanPaths({ paths: [dir], mode });
  return { target: computeTargetHash(s.scanned), findings: computeFindingsHash(s.report.findings), s };
};

test('hashes are 64 hex characters and deterministic across runs', () => {
  const dir = makeTree({ 'a.js': RISKY, 'sub/b.js': 'const x = 1;' });
  const one = hashesOf(dir);
  const two = hashesOf(dir);
  assert.match(one.target, /^[0-9a-f]{64}$/);
  assert.match(one.findings, /^[0-9a-f]{64}$/);
  assert.equal(one.target, two.target);
  assert.equal(one.findings, two.findings);
});

test('target_hash is independent of input order and depends on paths and contents', () => {
  const dir = makeTree({ 'a.js': RISKY, 'b.js': 'const x = 1;' });
  const { s, target } = hashesOf(dir);
  assert.equal(computeTargetHash([...s.scanned].reverse()), target);
  writeFileSync(join(dir, 'b.js'), 'const x = 2;');
  assert.notEqual(hashesOf(dir).target, target, 'a content change must change the hash');
  writeFileSync(join(dir, 'b.js'), 'const x = 1;');
  assert.equal(hashesOf(dir).target, target);
  renameSync(join(dir, 'b.js'), join(dir, 'c.js'));
  assert.notEqual(hashesOf(dir).target, target, 'a path change must change the hash');
});

test('target_hash matches the documented algorithm (path NUL length NUL bytes LF, sorted by path)', () => {
  const dir = makeTree({ 'b.js': 'B', 'a.js': 'AA' });
  const expected = createHash('sha256').update('a.js\u00002\u0000AA\nb.js\u00001\u0000B\n').digest('hex');
  assert.equal(hashesOf(dir).target, expected);
});

test('target_hash does not depend on where the tree lives on disk', () => {
  assert.equal(hashesOf(makeTree({ 'a.js': RISKY })).target, hashesOf(makeTree({ 'a.js': RISKY })).target);
});

test('findings_hash ignores finding order and changes when a finding changes', () => {
  const f1 = { id: 'a', severity: 'HIGH', title: 't' };
  const f2 = { id: 'b', severity: 'LOW', title: 'u' };
  assert.equal(computeFindingsHash([f1, f2]), computeFindingsHash([f2, f1]));
  assert.notEqual(computeFindingsHash([f1, f2]), computeFindingsHash([{ ...f1, severity: 'LOW' }, f2]));
  assert.equal(computeFindingsHash([{ title: 't', id: 'a', severity: 'HIGH' }, f2]), computeFindingsHash([f1, f2]), 'key order inside a finding is irrelevant');
});

test('files that did not fit the window are not part of target_hash', () => {
  const big = 'x'.repeat(100 * 1024);
  const dir = makeTree({ 'a.js': `fetch('/a');\n${big}`, 'b.js': big, 'c.js': big });
  const s = scanPaths({ paths: [dir] });
  assert.equal(s.meta.truncated, true);
  assert.ok(s.meta.skipped >= 1);
  assert.equal(s.scanned.length, s.meta.included);
});
