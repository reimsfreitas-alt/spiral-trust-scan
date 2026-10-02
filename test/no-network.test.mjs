// The core scan has no network code, and this test enforces it.
//
// The ONE exemption is src/receipt-client.mjs, by explicit name. Reason: it implements the
// opt-in receipt (POST of two digests and counts when the user passes --receipt) and the
// MCP verify_receipt fetch. Nothing else may touch the network, and nothing may import the
// exempt file statically: it is only ever loaded through a dynamic import() after an
// explicit opt-in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
export const NETWORK_EXEMPT = 'src/receipt-client.mjs';

// Replaces comments, string literals and regex literals with spaces; keeps code, including
// code inside template-literal ${...} expressions. Throws if it ends inside a string/comment.
export function stripNonCode(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  const braceStack = []; // for template expressions: depth of { inside ${ }
  let lastSig = '';
  const blank = (s) => s.replace(/[^\n]/g, ' ');
  const readString = (q) => { let j = i + 1; while (j < n && src[j] !== q) { if (src[j] === '\\') j++; j++; } if (j >= n) throw new Error('unterminated string'); const t = src.slice(i, j + 1); i = j + 1; return t; };
  const readTemplate = () => { // returns when it hits ${ or closing backtick
    let j = i; let seg = '';
    while (j < n) {
      if (src[j] === '\\') { seg += src.slice(j, j + 2); j += 2; continue; }
      if (src[j] === '`') { out += blank(seg + '`'); i = j + 1; return 'end'; }
      if (src[j] === '$' && src[j + 1] === '{') { out += blank(seg) + '  '; i = j + 2; braceStack.push(0); return 'expr'; }
      seg += src[j]; j++;
    }
    throw new Error('unterminated template');
  };
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') { let j = i; while (j < n && src[j] !== '\n') j++; out += blank(src.slice(i, j)); i = j; continue; }
    if (c === '/' && d === '*') { const j = src.indexOf('*/', i + 2); if (j < 0) throw new Error('unterminated comment'); out += blank(src.slice(i, j + 2)); i = j + 2; continue; }
    if (c === '"' || c === "'") { out += blank(readString(c)); lastSig = '"'; continue; }
    if (c === '`') { i++; const r = readTemplate(); lastSig = r === 'end' ? '"' : '${'; continue; }
    if (braceStack.length && c === '{') braceStack[braceStack.length - 1]++;
    if (braceStack.length && c === '}') {
      if (braceStack[braceStack.length - 1] === 0) { braceStack.pop(); out += ' '; i++; const r = readTemplate(); lastSig = r === 'end' ? '"' : '${'; continue; }
      braceStack[braceStack.length - 1]--;
    }
    if (c === '/' && (lastSig === '' || '(,=:[!&|?{};+-*%<>~^'.includes(lastSig) || /(^|[^\w$])(return|typeof)$/.test(out.slice(-12)))) {
      let j = i + 1; let inClass = false;
      while (j < n && (src[j] !== '/' || inClass)) { if (src[j] === '\\') j++; else if (src[j] === '[') inClass = true; else if (src[j] === ']') inClass = false; else if (src[j] === '\n') throw new Error('unterminated regex'); j++; }
      j++; while (j < n && /[a-z]/.test(src[j])) j++;
      out += blank(src.slice(i, j)); i = j; lastSig = '"'; continue;
    }
    out += c; if (!/\s/.test(c)) lastSig = c; i++;
  }
  if (braceStack.length) throw new Error('unterminated template expression');
  return out;
}

function sourceFiles() {
  const dirs = ['bin', 'src', 'mcp'];
  const files = [];
  for (const d of dirs) for (const f of readdirSync(join(ROOT, d))) if (f.endsWith('.mjs')) files.push(`${d}/${f}`);
  return files;
}

const NETWORK_MODULES = '(http|https|http2|net|dgram|tls|dns|worker_threads|child_process)';

test('stripNonCode handles strings, regexes, comments and template expressions', () => {
  const code = "const a = 'fetch(x)'; // fetch(y)\nconst b = /fetch\\(/g; const c = `x ${fetch(z)} y`; /* fetch(w) */";
  const out = stripNonCode(code);
  assert.equal((out.match(/\bfetch\b/g) ?? []).length, 1); // only the one inside ${ }
});

test('only src/receipt-client.mjs may use the network; every other source file has no network code', () => {
  const files = sourceFiles();
  assert.ok(files.includes('src/core.mjs') && files.includes('bin/trust-scan.mjs') && files.includes('mcp/server.mjs') && files.includes(NETWORK_EXEMPT));
  for (const f of files) {
    if (f === NETWORK_EXEMPT) continue;
    const text = readFileSync(join(ROOT, f), 'utf8');
    const code = stripNonCode(text);
    assert.ok(!/\bfetch\b/.test(code), `${f} must not reference fetch`);
    assert.ok(!/\b(XMLHttpRequest|WebSocket|EventSource|XMLHttpRequest)\b/.test(code), `${f} must not use browser network APIs`);
    assert.ok(!new RegExp(`(from\\s+|import\\s*\\(\\s*|require\\s*\\(\\s*)['"](node:)?${NETWORK_MODULES}['"]`).test(text), `${f} must not import network modules`);
  }
});

test('the exemption is real, narrow and documented: the exempt file is the only one that fetches, and its header says why', () => {
  const exempt = readFileSync(join(ROOT, NETWORK_EXEMPT), 'utf8');
  assert.match(exempt, /the ONLY module that uses the network/i);
  assert.match(exempt, /opt-in/i);
  assert.ok(/\bfetch\b/.test(stripNonCode(exempt)), 'the exempt file is expected to use fetch');
});

test('nothing imports the network module statically: it is loaded only by dynamic import() after an opt-in', () => {
  for (const f of sourceFiles()) {
    const code = readFileSync(join(ROOT, f), 'utf8').replace(/\/\/.*$/gm, '');
    assert.ok(!/^\s*(import|export)\s[^;]*from\s+['"][^'"]*receipt-client(\.mjs)?['"]/m.test(code), `${f} must not import receipt-client statically`);
  }
  const cli = readFileSync(join(ROOT, 'bin/trust-scan.mjs'), 'utf8');
  assert.match(cli, /await import\("\.\.\/src\/receipt-client\.mjs"\)/);
});

test('a plain scan never calls fetch and never loads node:http/https/net/tls (behavioural check, with a control)', async () => {
  const { execFileSync } = await import('node:child_process');
  const script = (body) => `
    globalThis.fetch = () => { throw new Error('NETWORK CALL'); };
    import { run } from './bin/trust-scan.mjs';
    import { mkdtempSync, writeFileSync } from 'node:fs'; import { tmpdir } from 'node:os'; import { join } from 'node:path';
    const d = mkdtempSync(join(tmpdir(), 'nn-')); writeFileSync(join(d, 'a.js'), 'const x = fetch;');
    ${body}
    console.log(JSON.stringify(process.moduleLoadList.filter((m) => /^NativeModule (https?|net|tls|dns)$/.test(m))));
  `;
  const plain = execFileSync(process.execPath, ['--input-type=module', '-e', script("run([d, '--fail-on', 'none'], {}, () => {});")], { cwd: ROOT }).toString().trim();
  assert.deepEqual(JSON.parse(plain), [], 'a plain scan must not load network modules');
  const control = execFileSync(process.execPath, ['--input-type=module', '-e', script("await import('node:https');")], { cwd: ROOT }).toString().trim();
  assert.ok(JSON.parse(control).length > 0, 'control: the detector must notice node:https when it is loaded');
});
