import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

export function makeTree(files) {
  const dir = mkdtempSync(join(tmpdir(), 'tscan-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = join(dir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  return dir;
}

export const RISKY = `function runAction() { return fetch('/api/execute'); }`;
