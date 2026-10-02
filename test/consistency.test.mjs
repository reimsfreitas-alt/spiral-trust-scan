import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const read = (f) => readFileSync(join(ROOT, f), 'utf8');
const pkg = JSON.parse(read('package.json'));

test('versions agree across package.json, server.json and the Python package', () => {
  const server = JSON.parse(read('mcp/server.json'));
  assert.equal(server.version, pkg.version);
  assert.equal(server.packages[0].version, pkg.version);
  assert.equal(server.packages[0].identifier, pkg.name);
  assert.match(read('python/pyproject.toml'), new RegExp(`^version = "${pkg.version.replace(/\./g, '\\.')}"`, 'm'));
});

test('server.json follows the Official MCP Registry shape (unvalidated by the live registry; schema-checked offline)', () => {
  const s = JSON.parse(read('mcp/server.json'));
  assert.equal(s.name, 'io.github.reimsfreitas-alt/spiral-trust-scanner');
  assert.equal(s.name, pkg.mcpName, 'registry ownership check: package.json mcpName must equal server.json name');
  assert.match(s.$schema, /^https:\/\/static\.modelcontextprotocol\.io\/schemas\/.+\/server\.schema\.json$/);
  assert.ok(s.description.length <= 100, 'registry limit: description <= 100 characters');
  assert.equal(s.repository.source, 'github');
  assert.equal(s.repository.url, 'https://github.com/reimsfreitas-alt/spiral-trust-scan');
  const [p] = s.packages;
  assert.equal(p.registryType, 'npm');
  assert.equal(p.registryBaseUrl, 'https://registry.npmjs.org');
  assert.equal(p.transport.type, 'stdio');
  assert.deepEqual(p.packageArguments, [{ type: 'positional', value: 'mcp' }]);
});

test('action.yml declares the documented inputs and outputs and passes inputs through env, not script text', () => {
  const y = read('action.yml');
  for (const input of ['path', 'mode', 'fail-on', 'receipt', 'include-source', 'sarif-file']) assert.match(y, new RegExp(`^  ${input}:`, 'm'), `input ${input}`);
  for (const out of ['findings', 'counts-json', 'receipt_id', 'validation_url', 'sarif-file']) assert.match(y, new RegExp(`^  ${out}:`, 'm'), `output ${out}`);
  assert.ok(!/^\s+score:/m.test(y), 'no invented score output');
  assert.match(y, /default: "false"/);
  const runBlock = y.slice(y.indexOf('run: |'));
  assert.ok(!runBlock.includes('${{'), 'inputs must not be interpolated into the shell script');
  assert.match(y, /id: scan/);
});

test('workflows exist and use trusted publishing (OIDC), provenance and pinned triggers', () => {
  const npmWf = read('.github/workflows/publish-npm.yml');
  assert.match(npmWf, /release:\s*\n\s+types: \[published\]/);
  assert.match(npmWf, /id-token: write/);
  assert.match(npmWf, /contents: read/);
  assert.match(npmWf, /npm publish --provenance --access public/);
  assert.ok(!/NPM_TOKEN|NODE_AUTH_TOKEN/.test(npmWf), 'no long-lived npm token');
  const pyWf = read('.github/workflows/publish-pypi.yml');
  assert.match(pyWf, /pypa\/gh-action-pypi-publish@release\/v1/);
  assert.match(pyWf, /id-token: write/);
  assert.ok(!/PYPI_API_TOKEN|password:/.test(pyWf), 'no long-lived PyPI token');
  const testWf = read('.github/workflows/test.yml');
  assert.match(testWf, /npm test/);
  assert.match(testWf, /npm pack --dry-run/);
  assert.ok(existsSync(join(ROOT, 'PUBLISHING.md')));
});

// Honesty: words that overclaim must not appear in any user-facing copy.
const FORBIDDEN = /irrefut[aá]vel|incontest[aá]vel|garantia|\bseguro\b|irrefutable|incontestable|guarantee|tamper-proof|unforgeable/i;
const COPY = ['README.md', 'PUBLISHING.md', 'action.yml', 'package.json', 'python/README.md', 'python/pyproject.toml', 'mcp/server.json', 'src/report.mjs', 'src/receipt-client.mjs', 'mcp/server.mjs', 'bin/trust-scan.mjs'];

test('no overclaiming words in user-facing copy', () => {
  for (const f of COPY) assert.ok(!FORBIDDEN.test(read(f)), `${f} contains an overclaiming word`);
});

test('README keeps the measured-precision caveats and the receipt limits', () => {
  const r = read('README.md');
  assert.match(r, /Measured precision/);
  assert.match(r, /2,285 source files/);
  assert.match(r, /not proof/i);
  assert.match(r, /never inserted automatically|nothing is inserted automatically/i);
  assert.match(r, /not proof that (the )?code is secure|does not show that the code is secure/i);
});

test('docs do not claim a spiral-codes GitHub org exists; the repository owner is reimsfreitas-alt', () => {
  for (const f of ['README.md', 'PUBLISHING.md', 'action.yml', 'python/README.md']) {
    const t = read(f);
    assert.ok(!/(uses:|github\.com\/)\s*spiral-codes\//.test(t), `${f} must not point at a spiral-codes org`);
  }
  assert.match(read('PUBLISHING.md'), /reimsfreitas-alt/);
  assert.match(read('PUBLISHING.md'), /spiral-codes/); // it says explicitly that this org does not exist
});

test('README documents every surface: CLI, Action, npm, PyPI, MCP, receipts and badge', () => {
  const r = read('README.md');
  for (const h of [/^## CLI/m, /^## GitHub Action/m, /^## npm/m, /^## PyPI/m, /^## MCP server/m, /^## Receipts and badge/m]) assert.match(r, h);
  assert.match(r, /uses: reimsfreitas-alt\/spiral-trust-scan@v1/);
  assert.match(r, /check_claim/);
  assert.match(r, /roadmap/i);
});
