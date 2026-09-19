import { fields, check, canonical, hash, integer, hashShape, addressShape, verifySignature, sign } from './crypto.js';

const scopeFields = ['version', 'logId', 'chainId', 'anchorAddress'];
export const scope = value => Object.fromEntries(scopeFields.map(k => [k, value[k]]));
function validateScope(value) {
  check(value.version === 3 && typeof value.logId === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(value.logId), 'INVALID_SCOPE');
  integer(value.chainId, true);
  check(addressShape(value.anchorAddress), 'INVALID_SCOPE');
}
export function validateTrust(trust) {
  const p = trust.policy;
  fields(p, [...scopeFields, 'policyId', 'ruleVersion', 'institutionId', 'token', 'decimals', 'treasury',
    'limitAtomic', 'reserveAtomic', 'decisionWindowSeconds', 'stateRule']);
  validateScope(p);
  check(p.policyId === 'usdc-reserve-v1' && p.ruleVersion === 1 && typeof p.institutionId === 'string' &&
    p.decimals === 6 && p.decisionWindowSeconds === 90 && p.stateRule === 'RECEIPT_BLOCK_END', 'UNSUPPORTED_POLICY');
  check(addressShape(p.token) && addressShape(p.treasury) && addressShape(trust.publisher) && hashShape(trust.codeHash), 'INVALID_TRUST');
  integer(p.limitAtomic, true); integer(p.reserveAtomic);
  check(hash('policy-v3', p) === trust.policyHash, 'POLICY_HASH_MISMATCH');
  check(trust.requesterKeys && trust.institutionKeys, 'INVALID_TRUST');
  return p;
}
export function validateRequest(record, trust) {
  fields(record, ['kind', 'requestId', 'request']);
  check(record.kind === 'REQUEST', 'INVALID_RECORD');
  const p = validateTrust(trust), r = verifySignature(record.request, 'request-v3', trust.requesterKeys);
  fields(r, [...scopeFields, 'requesterId', 'institutionId', 'token', 'treasury', 'recipient', 'amountAtomic', 'createdAtMs', 'policyHash']);
  check(canonical(scope(r)) === canonical(scope(p)) && r.institutionId === p.institutionId && r.token === p.token &&
    r.treasury === p.treasury && r.policyHash === trust.policyHash && r.requesterId === record.request.keyId,
    'REQUEST_CONTEXT_MISMATCH');
  check(addressShape(r.recipient), 'INVALID_RECIPIENT');
  integer(r.amountAtomic, true); integer(r.createdAtMs);
  check(hash('request-id-v3', r) === record.requestId, 'REQUEST_ID_MISMATCH');
  return r;
}
export function requestRecord(payload, keyId, key) {
  return { kind: 'REQUEST', requestId: hash('request-id-v3', payload), request: sign('request-v3', keyId, payload, key) };
}
export function evaluate(amount, balance, policy) {
  const a = integer(amount, true), limit = integer(policy.limitAtomic, true), reserve = integer(policy.reserveAtomic);
  if (a > limit) return { outcome: 'REJECTED', reason: 'LIMIT_EXCEEDED' };
  check(balance !== null && balance !== undefined, 'STATE_UNAVAILABLE');
  return integer(balance) < a + reserve
    ? { outcome: 'REJECTED', reason: 'RESERVE_FLOOR' }
    : { outcome: 'APPROVED', reason: 'POLICY_SATISFIED' };
}
export function receiptRef(meta, index) {
  return { batchId: String(meta.batchId), leafIndex: index, blockNumber: String(meta.blockNumber), blockHash: meta.blockHash };
}
export async function makeDecision(request, ref, trust, reader, keyId, privateKey) {
  const r = validateRequest(request, trust), p = trust.policy;
  check(Object.hasOwn(trust.institutionKeys, keyId), 'UNKNOWN_SIGNER');
  let snapshot = null;
  if (integer(r.amountAtomic) <= integer(p.limitAtomic)) {
    snapshot = { ...scope(p), requestId: request.requestId, receiptRef: ref, token: p.token, treasury: p.treasury,
      method: 'balanceOf', args: [p.treasury], balanceAtomic: await reader.balance(ref, p) };
  }
  const payload = { ...scope(p), requestId: request.requestId, policyHash: trust.policyHash, receiptRef: ref,
    stateHash: snapshot ? hash('state-v3', snapshot) : null, ...evaluate(r.amountAtomic, snapshot?.balanceAtomic, p) };
  const decision = sign('decision-v3', keyId, payload, privateKey);
  verifySignature(decision, 'decision-v3', trust.institutionKeys);
  return { record: { kind: 'DECISION', decision }, snapshot };
}
export async function validateDecision(record, request, ref, snapshot, trust, reader) {
  fields(record, ['kind', 'decision']); check(record.kind === 'DECISION', 'INVALID_RECORD');
  const d = verifySignature(record.decision, 'decision-v3', trust.institutionKeys), p = trust.policy;
  fields(d, [...scopeFields, 'requestId', 'policyHash', 'receiptRef', 'stateHash', 'outcome', 'reason']);
  check(canonical(scope(d)) === canonical(scope(p)) && d.requestId === request.requestId && d.policyHash === trust.policyHash,
    'DECISION_CONTEXT_MISMATCH');
  check(canonical(d.receiptRef) === canonical(ref), 'RECEIPT_MISMATCH');
  const amount = request.request.payload.amountAtomic;
  let balance = null;
  if (integer(amount) <= integer(p.limitAtomic)) {
    check(snapshot, 'DATA_UNAVAILABLE');
    check(hash('state-v3', snapshot) === d.stateHash, 'STATE_HASH_MISMATCH');
    balance = await reader.balance(ref, p);
    const expected = { ...scope(p), requestId: request.requestId, receiptRef: ref, token: p.token, treasury: p.treasury,
      method: 'balanceOf', args: [p.treasury], balanceAtomic: balance };
    check(canonical(snapshot) === canonical(expected), 'STATE_MISMATCH');
  } else check(d.stateHash === null && snapshot === null, 'UNEXPECTED_STATE');
  const expected = evaluate(amount, balance, p);
  check(d.outcome === expected.outcome && d.reason === expected.reason, 'POLICY_MISMATCH');
  return d;
}
