// Offline Ed25519 verification of Spiral receipts. node:crypto only, no network.
import { createPublicKey, verify } from "node:crypto";

// The issuer's public key (SPKI, base64), copied from this repository's README.
// The issuer also publishes it at /api/v1/public/key. Pinning it here means a
// receipt is checked against a key obtained through a different channel than
// the receipt itself. If the issuer rotates its key, pass the new one explicitly.
export const ISSUER_PUBLIC_KEY_SPKI_B64 = "MCowBQYDK2VwAyEALriybIkO1GdZ/3SNB+vccalGzaNDxmiiU+hdEzD4EzE=";

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).filter((k) => value[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function verifyEd25519(signedPayload, signature, spkiBase64) {
  if (typeof signature !== "string" || !/^ed25519:[0-9a-f]{128}$/.test(signature)) return false;
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(spkiBase64, "base64"), format: "der", type: "spki" });
  } catch {
    return false;
  }
  return verify(null, Buffer.from(canonical(signedPayload), "utf8"), key, Buffer.from(signature.slice(8), "hex"));
}
