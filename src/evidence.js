import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

function requireThat(condition, code) { if (!condition) throw new Error(code); }
export function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    requireThat(value === value.normalize('NFC'), 'NON_CANONICAL_STRING');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    requireThat(Number.isSafeInteger(value) && !Object.is(value, -0), 'INVALID_NUMBER');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  requireThat(value && Object.getPrototypeOf(value) === Object.prototype, 'INVALID_JSON_VALUE');
  return `{${Object.keys(value).sort().map(k => `${canonical(k)}:${canonical(value[k])}`).join(',')}}`;
}
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export const hash = value => digest(Buffer.from(canonical(value)));
const leaf = entry => digest(Buffer.concat([Buffer.from([0]), Buffer.from(canonical(entry))]));
const branch = (left, right) => digest(Buffer.concat([Buffer.from([1]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]));
const split = n => 2 ** Math.floor(Math.log2(n - 1));
const isHash = h => typeof h === 'string' && /^[a-f0-9]{64}$/.test(h);
export function merkle(entries) {
  if (!entries.length) return digest(Buffer.alloc(0));
  if (entries.length === 1) return leaf(entries[0]);
  const k = split(entries.length);
  return branch(merkle(entries.slice(0, k)), merkle(entries.slice(k)));
}
export function proof(entries, index) {
  requireThat(Number.isSafeInteger(index) && index >= 0 && index < entries.length, 'INVALID_INDEX');
  if (entries.length === 1) return [];
  const k = split(entries.length);
  return index < k
    ? [...proof(entries.slice(0, k), index), { side: 'right', hash: merkle(entries.slice(k)) }]
    : [...proof(entries.slice(k), index - k), { side: 'left', hash: merkle(entries.slice(0, k)) }];
}
export function verifyProof(entry, index, size, path, root) {
  if (!Number.isSafeInteger(size) || size < 1 || !Number.isSafeInteger(index) || index < 0 || index >= size || !Array.isArray(path) || !isHash(root)) return false;
  function directions(i, n) {
    if (n === 1) return [];
    const k = split(n);
    return i < k ? [...directions(i, k), 'right'] : [...directions(i - k, n - k), 'left'];
  }
  const expected = directions(index, size);
  if (path.length !== expected.length) return false;
  let current = leaf(entry);
  for (let i = 0; i < path.length; i++) {
    if (path[i]?.side !== expected[i] || !isHash(path[i]?.hash)) return false;
    current = path[i].side === 'left' ? branch(path[i].hash, current) : branch(current, path[i].hash);
  }
  return current === root;
}
export function sign(domain, payload, key) {
  return { domain, payload, signature: cryptoSign(null, Buffer.from(canonical({ domain, payload })), key).toString('base64') };
}
function signature(envelope, domain, key) {
  requireThat(envelope?.domain === domain && typeof envelope.signature === 'string', 'INVALID_ENVELOPE');
  const raw = Buffer.from(envelope.signature, 'base64');
  requireThat(raw.length === 64 && raw.toString('base64') === envelope.signature, 'INVALID_SIGNATURE_ENCODING');
  requireThat(cryptoVerify(null, Buffer.from(canonical({ domain, payload: envelope.payload })), key, raw), 'INVALID_SIGNATURE');
  return envelope.payload;
}
function fields(object, keys) {
  requireThat(object && canonical(Object.keys(object).sort()) === canonical([...keys].sort()), 'INVALID_SCHEMA');
}
function timestamp(value) { requireThat(Number.isSafeInteger(value) && value >= 0, 'INVALID_TIME'); }
function validatePolicy(policy) {
  fields(policy, ['version', 'id', 'institution', 'currency', 'limit', 'decisionWindow']);
  requireThat(policy.version === 1 && policy.id === 'per-transfer-limit-v1' && policy.institution === 'demo-bank' && policy.currency === 'KRW' && policy.limit === 1000000 && policy.decisionWindow === 60, 'UNSUPPORTED_POLICY');
}
function requestPayload(envelope, trust) {
  const r = signature(envelope, 'request', trust.customerKey);
  fields(r, ['version', 'id', 'customer', 'institution', 'amount', 'currency', 'policyHash']);
  requireThat(r.version === 1 && typeof r.id === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(r.id), 'INVALID_REQUEST');
  requireThat(r.customer === 'demo-customer' && r.institution === trust.policy.institution && r.currency === 'KRW' && r.policyHash === hash(trust.policy), 'REQUEST_CONTEXT_MISMATCH');
  requireThat(Number.isSafeInteger(r.amount) && r.amount > 0, 'INVALID_AMOUNT');
  return r;
}
function expectedDecision(r) {
  return r.amount > 1000000 ? { outcome: 'REJECTED', reason: 'LIMIT_EXCEEDED' } : { outcome: 'APPROVED', reason: 'WITHIN_LIMIT' };
}
function decisionPayload(envelope, request, trust) {
  const d = signature(envelope, 'decision', trust.institutionKey);
  fields(d, ['version', 'requestHash', 'policyHash', 'outcome', 'reason']);
  requireThat(d.version === 1 && d.requestHash === hash(request) && d.policyHash === hash(trust.policy), 'DECISION_CONTEXT_MISMATCH');
  const expected = expectedDecision(request.payload);
  requireThat(d.outcome === expected.outcome && d.reason === expected.reason, 'POLICY_MISMATCH');
  return d;
}
function checkpoint(trust) {
  validatePolicy(trust.policy);
  const c = signature(trust.checkpoint, 'checkpoint', trust.witnessKey);
  fields(c, ['version', 'logId', 'size', 'root', 'issuedAt']);
  timestamp(c.issuedAt);
  requireThat(c.version === 1 && c.logId === 'trust404-demo' && Number.isSafeInteger(c.size) && c.size >= 0 && isHash(c.root), 'INVALID_CHECKPOINT');
  return c;
}
function entryShape(entry, c) {
  const isRequest = entry?.evidence?.domain === 'request';
  fields(entry, isRequest ? ['index', 'acceptedAt', 'deadline', 'evidence'] : ['index', 'acceptedAt', 'evidence']);
  fields(entry.evidence, ['domain', 'payload', 'signature']);
  requireThat(Number.isSafeInteger(entry.index) && entry.index >= 0 && entry.index < c.size, 'INVALID_INDEX');
  timestamp(entry.acceptedAt);
  requireThat(entry.acceptedAt <= c.issuedAt, 'FUTURE_ENTRY');
  requireThat(isRequest || entry.evidence.domain === 'decision', 'UNKNOWN_ENTRY');
  if (isRequest) requireThat(Number.isSafeInteger(entry.deadline) && entry.deadline === entry.acceptedAt + 60, 'INVALID_DEADLINE');
}
export function verifySingle(bundle, trust) {
  const c = checkpoint(trust);
  requireThat(canonical(bundle.checkpoint) === canonical(trust.checkpoint), 'CHECKPOINT_MISMATCH');
  for (const item of [bundle.request, bundle.decision]) {
    entryShape(item.entry, c);
    requireThat(verifyProof(item.entry, item.entry.index, c.size, item.proof, c.root), 'INVALID_INCLUSION_PROOF');
  }
  const r = requestPayload(bundle.request.entry.evidence, trust);
  const d = decisionPayload(bundle.decision.entry.evidence, bundle.request.entry.evidence, trust);
  requireThat(bundle.request.entry.index < bundle.decision.entry.index && bundle.request.entry.acceptedAt <= bundle.decision.entry.acceptedAt, 'INVALID_EVENT_ORDER');
  return { ok: true, requestId: r.id, amount: r.amount, outcome: d.outcome, reason: d.reason };
}
export function audit(entries, trust) {
  const c = checkpoint(trust);
  requireThat(Array.isArray(entries) && entries.length === c.size, 'LOG_SIZE_MISMATCH');
  requireThat(merkle(entries) === c.root, 'LOG_ROOT_MISMATCH');
  const requests = new Map(); const ids = new Set(); const decisions = new Set();
  let previousTime = 0;
  entries.forEach((entry, index) => {
    entryShape(entry, c);
    requireThat(entry.index === index && entry.acceptedAt >= previousTime, 'INVALID_LOG_ORDER');
    previousTime = entry.acceptedAt;
    if (entry.evidence.domain === 'request') {
      const r = requestPayload(entry.evidence, trust);
      requireThat(!ids.has(r.id), 'DUPLICATE_REQUEST'); ids.add(r.id);
      requests.set(hash(entry.evidence), entry);
    } else {
      const key = entry.evidence.payload.requestHash;
      requireThat(requests.has(key) && !decisions.has(key), 'UNMATCHED_OR_DUPLICATE_DECISION');
      decisionPayload(entry.evidence, requests.get(key).evidence, trust); decisions.add(key);
    }
  });
  const pending = []; const overdue = [];
  for (const [key, entry] of requests) if (!decisions.has(key)) (c.issuedAt >= entry.deadline ? overdue : pending).push(entry.evidence.payload.id);
  return { ok: overdue.length === 0, requests: requests.size, decisions: decisions.size, pending, overdue };
}

// The demo coordinator holds all keys in memory. Production actors must not share this boundary.
export function createSystem({ onAppend = () => {} } = {}) {
  const keys = Object.fromEntries(['customer', 'institution', 'witness'].map(role => [role, generateKeyPairSync('ed25519')]));
  const policy = { version: 1, id: 'per-transfer-limit-v1', institution: 'demo-bank', currency: 'KRW', limit: 1000000, decisionWindow: 60 };
  const entries = [];
  const baseTrust = { policy, ...Object.fromEntries(Object.entries(keys).map(([role, pair]) => [`${role}Key`, pair.publicKey.export({ type: 'spki', format: 'pem' })])) };
  function append(evidence, acceptedAt) {
    timestamp(acceptedAt);
    requireThat(!entries.length || acceptedAt >= entries.at(-1).acceptedAt, 'INVALID_LOG_ORDER');
    const entry = { index: entries.length, acceptedAt, ...(evidence.domain === 'request' ? { deadline: acceptedAt + policy.decisionWindow } : {}), evidence };
    // Persist externally before acknowledging the request or decision.
    onAppend(structuredClone([...entries, entry]));
    entries.push(entry); return entry;
  }
  return {
    keys, entries, policy,
    submit(id, amount, now) {
      const envelope = sign('request', { version: 1, id, customer: 'demo-customer', institution: policy.institution, amount, currency: 'KRW', policyHash: hash(policy) }, keys.customer.privateKey);
      requestPayload(envelope, baseTrust);
      requireThat(!entries.some(e => e.evidence.domain === 'request' && e.evidence.payload.id === id), 'DUPLICATE_REQUEST');
      return append(envelope, now);
    },
    decide(request, now) {
      requireThat(entries.includes(request) && request.evidence.domain === 'request', 'REQUEST_NOT_RECEIVED');
      const r = requestPayload(request.evidence, baseTrust);
      requireThat(!entries.some(e => e.evidence.domain === 'decision' && e.evidence.payload.requestHash === hash(request.evidence)), 'DUPLICATE_DECISION');
      return append(sign('decision', { version: 1, requestHash: hash(request.evidence), policyHash: hash(policy), ...expectedDecision(r) }, keys.institution.privateKey), now);
    },
    trust(now) {
      timestamp(now); requireThat(!entries.length || now >= entries.at(-1).acceptedAt, 'INVALID_CHECKPOINT_TIME');
      return { ...baseTrust, checkpoint: sign('checkpoint', { version: 1, logId: 'trust404-demo', size: entries.length, root: merkle(entries), issuedAt: now }, keys.witness.privateKey) };
    },
    bundle(request, decision, trust) {
      requireThat(merkle(entries) === trust.checkpoint.payload.root && entries.length === trust.checkpoint.payload.size, 'CHECKPOINT_MISMATCH');
      return structuredClone({ checkpoint: trust.checkpoint, request: { entry: request, proof: proof(entries, request.index) }, decision: { entry: decision, proof: proof(entries, decision.index) } });
    },
  };
}
