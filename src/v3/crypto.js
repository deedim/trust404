import canonicalize from 'canonicalize';
import { createHash, sign as cryptoSign, verify as cryptoVerify, createPublicKey } from 'node:crypto';

export function check(condition, code) {
  if (!condition) throw new Error(code);
}
export function fields(value, expected) {
  check(value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key)), 'INVALID_SCHEMA');
}
export function canonical(value) {
  // This wire format contains JSON values only; never silently drop undefined.
  function validate(v) {
    if (typeof v === 'string') { check(v.isWellFormed(), 'INVALID_UNICODE'); return; }
    if (v === null || typeof v === 'boolean') return;
    if (typeof v === 'number') { check(Number.isFinite(v), 'INVALID_NUMBER'); return; }
    if (Array.isArray(v)) { for (const item of v) validate(item); return; }
    check(v && Object.getPrototypeOf(v) === Object.prototype, 'INVALID_JSON');
    for (const [key, item] of Object.entries(v)) { validate(key); validate(item); }
  }
  validate(value);
  return canonicalize(value);
}
export function parseWire(text) {
  const value = JSON.parse(text);
  check(canonical(value) === text, 'NON_CANONICAL_WIRE');
  return value;
}
export const sha = bytes => '0x' + createHash('sha256').update(bytes).digest('hex');
export const hash = (domain, payload) => sha(Buffer.from(canonical({ domain, payload })));
export const hashShape = v => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v);
export const addressShape = v => typeof v === 'string' && /^0x[0-9a-f]{40}$/.test(v);
export function integer(value, positive = false) {
  check(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && value.length <= 78, 'INVALID_INTEGER');
  const n = BigInt(value);
  check(n <= (1n << 256n) - 1n && (!positive || n > 0n), 'INVALID_INTEGER');
  return n;
}
export function sign(domain, keyId, payload, privateKey) {
  return { domain, keyId, payload, signature: cryptoSign(null,
    Buffer.from(canonical({ domain, keyId, payload })), privateKey).toString('base64') };
}
export function verifySignature(envelope, domain, keys) {
  fields(envelope, ['domain', 'keyId', 'payload', 'signature']);
  check(envelope.domain === domain && Object.hasOwn(keys, envelope.keyId), 'UNKNOWN_SIGNER');
  check(typeof envelope.signature === 'string', 'INVALID_SIGNATURE');
  const sig = Buffer.from(envelope.signature, 'base64');
  const key = createPublicKey(keys[envelope.keyId]);
  check(key.asymmetricKeyType === 'ed25519' && sig.length === 64 && sig.toString('base64') === envelope.signature,
    'INVALID_SIGNATURE');
  check(cryptoVerify(null, Buffer.from(canonical({ domain, keyId: envelope.keyId, payload: envelope.payload })), key, sig),
    'INVALID_SIGNATURE');
  return envelope.payload;
}
