import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = process.cwd();
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

test('package.json is publishable as @spiralcodes/trust-scanner with provenance and public access', () => {
  assert.equal(pkg.name, '@spiralcodes/trust-scanner');
  assert.deepEqual(pkg.publishConfig, { access: 'public', provenance: true });
  assert.equal(pkg.bin['trust-scan'], 'bin/trust-scan.mjs');
  assert.equal(pkg.bin['trust-scanner'], 'bin/trust-scan.mjs', 'npx @spiralcodes/trust-scanner needs a bin named like the package');
  assert.equal(pkg.bin['spiral-trust-scanner'], 'mcp/server.mjs');
  assert.equal(pkg.license, 'MIT');
  assert.equal(pkg.mcpName, 'io.github.reimsfreitas-alt/spiral-trust-scanner');
  assert.match(pkg.repository.url, /reimsfreitas-alt\/spiral-trust-scan\.git$/);
  assert.ok(!pkg.dependencies, 'the package has no runtime dependencies');
});

test('npm pack --dry-run: the tarball contains exactly what should ship, and nothing else', () => {
  const out = execFileSync(npm, ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: ROOT, encoding: 'utf8' });
  const [info] = JSON.parse(out);
  const files = info.files.map((f) => f.path).sort();
  const required = [
    'LICENSE', 'README.md', 'package.json', 'action.yml',
    'bin/trust-scan.mjs', 'bin/verify-receipt.mjs',
    'src/core.mjs', 'src/scan.mjs', 'src/hashes.mjs', 'src/report.mjs', 'src/locate.mjs', 'src/verify.mjs', 'src/version.mjs', 'src/receipt-client.mjs',
    'mcp/server.mjs',
  ];
  for (const f of required) assert.ok(files.includes(f), `tarball must contain ${f}`);
  const allowed = /^(LICENSE|README\.md|package\.json|action\.yml|bin\/[^/]+\.mjs|src\/[^/]+\.mjs|mcp\/server\.mjs)$/;
  const extra = files.filter((f) => !allowed.test(f));
  assert.deepEqual(extra, [], `unexpected files in the tarball: ${extra.join(', ')}`);
  for (const bad of ['test/', 'python/', '.github/', 'node_modules/', 'PUBLISHING.md', '.git']) {
    assert.ok(!files.some((f) => f.startsWith(bad)), `tarball must not contain ${bad}`);
  }
  assert.ok(info.size < 100_000, `tarball should stay small, got ${info.size} bytes`);
});

test('installed from the tarball, the bins work through npm\'s symlinks (CLI, receipt verifier, MCP)', { timeout: 120_000 }, () => {
  const work = mkdtempSync(join(tmpdir(), 'pack-'));
  const packOut = execFileSync(npm, ['pack', '--json', '--ignore-scripts', '--pack-destination', work], { cwd: ROOT, encoding: 'utf8' });
  const tgz = join(work, JSON.parse(packOut)[0].filename);
  const proj = join(work, 'proj');
  mkdirSync(proj);
  writeFileSync(join(proj, 'package.json'), '{"name":"consumer","version":"1.0.0","private":true}');
  execFileSync(npm, ['install', tgz, '--offline', '--no-audit', '--no-fund', '--ignore-scripts'], { cwd: proj, encoding: 'utf8' });
  const bin = (n) => join(proj, 'node_modules', '.bin', n);
  assert.ok(existsSync(bin('trust-scan')) && existsSync(bin('trust-scanner')) && existsSync(bin('spiral-trust-scanner')));

  const target = join(work, 'target');
  mkdirSync(target);
  writeFileSync(join(target, 'agent.js'), `function runAction() { return fetch('/api/execute'); }`);
  for (const name of ['trust-scan', 'trust-scanner']) {
    const r = spawnSync(bin(name), [target], { encoding: 'utf8' });
    assert.equal(r.status, 1, `${name}: ${r.stderr}`);
    assert.match(r.stdout, /Spiral Trust Scan/);
  }
  const help = spawnSync(bin('trust-scan'), ['--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /--mode quick\|deep/);
  const verify = spawnSync(join(proj, 'node_modules', '@spiralcodes', 'trust-scanner', 'bin', 'verify-receipt.mjs'), [], { encoding: 'utf8' });
  assert.equal(verify.status, 2);
  assert.match(verify.stderr, /usage/);

  const init = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } });
  for (const [cmd, args] of [[bin('spiral-trust-scanner'), []], [bin('trust-scan'), ['mcp']]]) {
    const r = spawnSync(cmd, args, { input: init + '\n', encoding: 'utf8', cwd: proj, timeout: 20_000 });
    assert.equal(JSON.parse(r.stdout.trim().split('\n')[0]).result.serverInfo.name, 'spiral-trust-scanner', `${cmd} ${args.join(' ')}`);
  }
});
