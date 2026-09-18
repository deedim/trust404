import test from 'node:test';
import assert from 'node:assert/strict';
import { createSystem, verifySingle, audit, sign, hash, merkle, proof, verifyProof } from '../src/evidence.js';

function fixture() {
  const s = createSystem();
  const request = s.submit('req-1', 1500000, 1000);
  const decision = s.decide(request, 1001);
  const trust = s.trust(1100);
  return { s, request, decision, trust, bundle: s.bundle(request, decision, trust) };
}
test('R3: limit boundaries', () => {
  for (const amount of [999999, 1000000, 1000001]) {
    const s = createSystem();
    const r = s.submit(String(amount), amount, 1000);
    assert.equal(s.decide(r, 1001).evidence.payload.outcome, amount > 1000000 ? 'REJECTED' : 'APPROVED');
  }
});
test('R1–R5: independent single evidence verification', () => {
  const { bundle, trust } = fixture();
  assert.equal(verifySingle(bundle, trust).outcome, 'REJECTED');
});
test('R1,R3–R5: altered amount, reason and signatures fail', () => {
  const { bundle, trust } = fixture();
  for (const change of [b => b.request.entry.evidence.payload.amount++, b => b.decision.entry.evidence.payload.reason = 'OTHER', b => b.decision.entry.evidence.signature = 'AAAA']) {
    const b = structuredClone(bundle); change(b);
    assert.throws(() => verifySingle(b, trust));
  }
});
test('R3,R5: even valid institution signature cannot legitimize false decision', () => {
  const { s, request, decision } = fixture();
  decision.evidence = sign('decision', { ...decision.evidence.payload, outcome: 'APPROVED', reason: 'WITHIN_LIMIT' }, s.keys.institution.privateKey);
  const trust = s.trust(1100);
  assert.throws(() => verifySingle(s.bundle(request, decision, trust), trust), /POLICY_MISMATCH/);
});
test('R6: complete log covers approval and rejection', () => {
  const { s } = fixture();
  const r = s.submit('req-2', 500000, 1002); s.decide(r, 1003);
  assert.deepEqual(audit(s.entries, s.trust(1100)), { ok: true, requests: 2, decisions: 2, pending: [], overdue: [] });
});
test('R4,R6: deletion, reordering and duplication are detected', () => {
  const { s, trust } = fixture();
  for (const entries of [s.entries.slice(1), [...s.entries].reverse(), [s.entries[0], s.entries[0]]]) assert.throws(() => audit(entries, trust));
});
test('R2,R6: missing initial decision is pending then overdue', () => {
  const s = createSystem(); s.submit('forgotten', 100, 1000);
  assert.deepEqual(audit(s.entries, s.trust(1059)).pending, ['forgotten']);
  const result = audit(s.entries, s.trust(1060));
  assert.equal(result.ok, false); assert.deepEqual(result.overdue, ['forgotten']);
});
test('R1: invalid amount and duplicate ID rejected', () => {
  const s = createSystem();
  for (const amount of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => s.submit('bad', amount, 1000));
  s.submit('unique', 1, 1000); assert.throws(() => s.submit('unique', 1, 1000));
});
test('R1: different institution or policy rejected even with customer signature', () => {
  for (const field of ['institution', 'policyHash']) {
    const { s, request } = fixture();
    request.evidence = sign('request', { ...request.evidence.payload, [field]: 'other' }, s.keys.customer.privateKey);
    assert.throws(() => audit(s.entries, s.trust(1100)));
  }
});
test('R5,R6: replaced key, checkpoint or old audit scope fails', () => {
  const { s, bundle, trust } = fixture();
  const other = createSystem();
  assert.throws(() => verifySingle(bundle, { ...trust, witnessKey: other.trust(1100).witnessKey }));
  s.submit('new', 1, 1101);
  assert.throws(() => verifySingle(bundle, s.trust(1102)), /CHECKPOINT/);
  assert.throws(() => audit([], trust));
});
test('R4,R5: Merkle paths bind size, index, direction and contents', () => {
  for (let size = 1; size <= 17; size++) {
    const entries = Array.from({ length: size }, (_, index) => ({ index }));
    const root = merkle(entries);
    for (let index = 0; index < size; index++) {
      const p = proof(entries, index);
      assert.equal(verifyProof(entries[index], index, size, p, root), true);
      assert.equal(verifyProof({ index: -1 }, index, size, p, root), false);
      assert.equal(verifyProof(entries[index], size, size, p, root), false);
      assert.equal(verifyProof(entries[index], index, size, [...p, { side: 'left', hash: hash('fake') }], root), false);
    }
  }
});
test('R1,R3: invalid signature is rejected even inside a valid anchored log', () => {
  for (const role of ['customer', 'institution']) {
    const { s, request, decision } = fixture();
    const target = role === 'customer' ? request : decision;
    target.evidence = sign(target.evidence.domain, target.evidence.payload, createSystem().keys[role].privateKey);
    const trust = s.trust(1100);
    assert.throws(() => verifySingle(s.bundle(request, decision, trust), trust), /INVALID_SIGNATURE/);
  }
});
test('R2,R3: persistence failure must not acknowledge or append evidence', () => {
  const s = createSystem({ onAppend() { throw new Error('DISK_FAILURE'); } });
  assert.throws(() => s.submit('not-persisted', 1, 1000), /DISK_FAILURE/);
  assert.equal(s.entries.length, 0);
  const second = createSystem({ onAppend(entries) { if (entries.length > 1) throw new Error('DISK_FAILURE'); } });
  const request = second.submit('received', 1, 1000);
  assert.throws(() => second.decide(request, 1001), /DISK_FAILURE/);
  assert.equal(second.entries.length, 1);
});
