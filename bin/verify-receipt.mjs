#!/usr/bin/env node
// Offline check of a Spiral Trust receipt signed with Ed25519. No network: node:crypto only.
//
//   node bin/verify-receipt.mjs receipt.json --signature ed25519:<hex> --public-key <SPKI base64>
//
// receipt.json is the response of GET /api/v1/public/receipt?id=... (it contains `signedPayload`).
// The public key is published at /api/v1/public/key and in this README.
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonical, verifyEd25519 } from '../src/verify.mjs';

export { canonical, verifyEd25519 };

function main(argv) {
  const file = argv[0];
  const get = (flag) => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : undefined; };
  const signature = get('--signature');
  const publicKey = get('--public-key');
  if (!file || !signature || !publicKey) {
    console.error('usage: verify-receipt.mjs receipt.json --signature ed25519:<hex> --public-key <SPKI base64>');
    return 2;
  }
  const receipt = JSON.parse(readFileSync(file, 'utf8'));
  if (!receipt.signedPayload) { console.error('receipt.json has no signedPayload'); return 2; }
  const ok = verifyEd25519(receipt.signedPayload, signature, publicKey);
  console.log(ok ? `AUTHENTIC: signature matches the issuer's public key (verdict ${receipt.signedPayload.verdict}, receipt ${receipt.signedPayload.receiptId})` : 'NOT AUTHENTIC: signature does not match this payload and key');
  return ok ? 0 : 1;
}

// realpath on both sides: an installed bin is a symlink, so argv[1] differs from import.meta.url.
function isMain() {
  try { return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]); } catch { return false; }
}
if (isMain()) process.exit(main(process.argv.slice(2)));
