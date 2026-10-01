#!/usr/bin/env node
// Offline check of a Spiral Trust receipt signed with Ed25519. No network: node:crypto only.
//
//   node bin/verify-receipt.mjs receipt.json --signature ed25519:<hex> --public-key <SPKI base64>
//
// receipt.json is the response of GET /api/v1/public/receipt?id=... (it contains `signedPayload`).
// The public key is published at /api/v1/public/key and in this README.
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter((k) => value[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function verifyEd25519(signedPayload, signature, spkiBase64) {
  if (!/^ed25519:[0-9a-f]{128}$/.test(signature)) return false;
  const key = createPublicKey({ key: Buffer.from(spkiBase64, 'base64'), format: 'der', type: 'spki' });
  return verify(null, Buffer.from(canonical(signedPayload), 'utf8'), key, Buffer.from(signature.slice(8), 'hex'));
}

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

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main(process.argv.slice(2)));
