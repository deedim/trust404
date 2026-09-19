import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  createSystem, verifyReceipt, verifySingle, audit, canonical, sign, hash,
  decodePayload, encodePayload, requestPayload,
} from '../src/evidence.js';
import { createTestWitness, entryView, receiptFor, recordedReceipt, alterPayload, fixture, disk, OTHER } from './helpers.js';
import { buildTree } from '../src/evm.js';

test('original canonical bytes, SHA-256 links and Ed25519 signatures remain stable', () => {
  const value = { z: 1, a: ['한글', true] };
  assert.equal(canonical(value), '{"a":["한글",true],"z":1}');
  assert.equal(hash(value), createHash('sha256').update('{"a":["한글",true],"z":1}').digest('hex'));
  const { privateKey } = generateKeyPairSync('ed25519');
  assert.deepEqual(sign('request', value, privateKey), sign('request', { a: ['한글', true], z: 1 }, privateKey));
  assert.throws(() => canonical(-0), /INVALID_NUMBER/);
  assert.throws(() => canonical('e\u0301'), /NON_CANONICAL_STRING/);
  assert.throws(() => createSystem(), TypeError);
});

test('R3: limit boundaries through the existing system interface', async () => {
  for (const amount of [999999, 1000000, 1000001]) {
    const { bundle, trust } = await fixture(amount);
    assert.equal(verifySingle(bundle, trust).outcome, amount > 1000000 ? 'REJECTED' : 'APPROVED');
  }
});

test('R1–R5: receipt and single evidence verify independently offline', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  const request = await s.submit('req-1', 1500000);
  const receiptTrust = await s.trust(request.checkpointId);
  const receipt = s.bundle(request, undefined, receiptTrust);
  assert.deepEqual(Object.keys(receipt), ['checkpointId', 'request']);
  assert.deepEqual(Object.keys(receiptTrust).sort(), [
    'chainId', 'evidenceLogAddress', 'depth', 'customerAddress', 'institutionAddress',
    'policy', 'customerKey', 'institutionKey', 'checkpointId', 'checkpoint',
  ].sort());
  assert.equal(verifyReceipt(disk(receipt), disk(receiptTrust)).ok, true);
  assert.deepEqual(Object.keys(request).sort(), ['checkpointId', 'payloadBytes', 'record']);
  const decision = await s.decide(disk(receipt));
  const trust = await s.trust();
  assert.deepEqual(verifySingle(disk(s.bundle(request, decision, trust)), disk(trust)), {
    ok: true, requestId: 'req-1', amount: 1500000, outcome: 'REJECTED', reason: 'LIMIT_EXCEEDED',
  });
  assert.equal(verifyReceipt(receipt, receiptTrust).ok, true);
  assert.throws(() => verifyReceipt(receipt, trust), /CHECKPOINT_MISMATCH/);
});

test('R1,R3–R5: altered bytes, metadata and proofs fail', async () => {
  const { bundle, trust } = await fixture();
  for (const change of [
    b => alterPayload(b.request.entry, e => e.payload.amount++),
    b => alterPayload(b.decision.entry, e => e.payload.reason = 'OTHER'),
    b => alterPayload(b.decision.entry, e => e.signature = 'AAAA'),
    b => b.request.entry.record.index++,
    b => b.request.entry.record.recordedAt++,
    b => b.request.entry.payloadBytes = '0x00',
    b => b.request.proof.reverse(),
    b => b.request.proof.pop(),
    b => b.checkpointId++,
    b => { delete b.checkpointId; },
    b => { b.checkpointId = -1; },
  ]) {
    const b = structuredClone(bundle); change(b);
    assert.throws(() => verifySingle(b, trust));
  }
});

test('institution decides from customer receipt without transaction hashes or a local request log', async () => {
  const witness = createTestWitness();
  const customer = createSystem({ witness });
  const request = await customer.submit('external-receipt', 1500000);
  const receipt = disk(await receiptFor(customer, request));
  const institution = createSystem({ witness, keys: customer.keys });
  witness.readRecord = async () => assert.fail('UNEXPECTED_RECEIPT_READ');
  witness.checkpoint = async () => assert.fail('UNEXPECTED_CHECKPOINT_ISSUE');
  const reads = [];
  const readCheckpoint = witness.readCheckpoint;
  witness.readCheckpoint = async id => { reads.push(id); return readCheckpoint(id); };

  const decision = await institution.decide(receipt);
  assert.deepEqual(reads, [receipt.checkpointId]);
  assert.deepEqual(institution.entries, [decision]);
  assert.equal(Object.hasOwn(decision, 'txHash'), false);
  assert.equal(Object.hasOwn(request, 'txHash'), false);
  assert.equal(Object.hasOwn(receipt.request.entry, 'txHash'), false);
  const envelope = decodePayload(decision.payloadBytes, decision.record);
  assert.equal(envelope.payload.outcome, 'REJECTED');
  assert.equal(envelope.payload.requestHash, hash(decodePayload(request.payloadBytes, request.record)));
  customer.entries.push(decision);
  const trust = await customer.trust(decision.checkpointId);
  assert.equal(verifySingle(customer.bundle(request, decision, trust), trust).ok, true);
});

test('decision requires receipt inclusion against the fetched checkpoint before persisting or registering', async () => {
  const witness = createTestWitness();
  let stored = 0;
  const s = createSystem({ witness, onPayload() { stored++; } });
  const request = await s.submit('checked-before-decision', 10);
  const receipt = await receiptFor(s, request);
  witness.checkpoint = async () => assert.fail('UNEXPECTED_CHECKPOINT_ISSUE');
  const cases = [
    [r => { delete r.checkpointId; }, /MISSING_EVIDENCE/],
    [r => { r.checkpointId = null; }, /MISSING_EVIDENCE/],
    [r => { r.checkpointId = 999n; }, /CHECKPOINT_NOT_FOUND/],
    [r => { delete r.request; }, /MISSING_EVIDENCE/],
    [r => { r.request.proof.pop(); }, /INVALID_PROOF_LENGTH/],
    [r => { r.request.proof[0] = `0x${hash('wrong-sibling')}`; }, /INVALID_INCLUSION_PROOF/],
    [r => { r.request.entry.record.payloadHash = `0x${hash('other')}`; }, /INVALID_INCLUSION_PROOF/],
    [r => { r.request.entry.payloadBytes = encodePayload(sign('request', {
      ...decodePayload(request.payloadBytes, request.record).payload, amount: 20,
    }, s.keys.customer.privateKey)); }, /PAYLOAD_HASH_MISMATCH/],
  ];
  for (const [mutate, error] of cases) {
    const invalid = structuredClone(receipt);
    mutate(invalid);
    await assert.rejects(s.decide(invalid), error);
  }
  await assert.rejects(s.decide(request), /MISSING_EVIDENCE/);

  const forged = structuredClone(receipt);
  forged.request.entry.record.recordedAt--;
  const tree = buildTree([forged.request.entry.record], witness.context);
  forged.request.proof = tree.proof(0);
  forged.checkpoint = { size: 1n, root: tree.root, issuedAt: 1000n };
  await assert.rejects(s.decide(forged), /INVALID_INCLUSION_PROOF/);
  assert.equal(witness.calls.length, 1);
  assert.equal(stored, 1);
  assert.equal(s.entries.length, 1);
});

test('decision rejects anchored wrong actors, signatures, schemas and decision records as requests', async () => {
  for (const variant of ['actor', 'signature', 'schema']) {
    const witness = createTestWitness();
    const s = createSystem({ witness });
    const request = await s.submit('valid', 1);
    const original = decodePayload(request.payloadBytes, request.record);
    const bytes = encodePayload(sign('request', {
      ...original.payload, id: variant, ...(variant === 'schema' ? { extra: true } : {}),
    }, variant === 'signature' ? s.keys.institution.privateKey : s.keys.customer.privateKey));
    const entry = entryView(witness.record(bytes, variant === 'actor' ? { actor: OTHER } : {}), bytes);
    const error = { actor: /ACTOR_MISMATCH/, signature: /INVALID_SIGNATURE/, schema: /INVALID_SCHEMA/ }[variant];
    await assert.rejects(s.decide(await recordedReceipt(witness, entry)), error);
    assert.equal(witness.calls.length, 1);
  }
  const { s, witness, bundle } = await fixture();
  const count = witness.calls.length;
  await assert.rejects(s.decide({ checkpointId: bundle.checkpointId, request: bundle.decision }), /EXPECTED_REQUEST/);
  assert.equal(witness.calls.length, count);
});

test('decision uses a receipt snapshot across the asynchronous checkpoint read', async () => {
  const witness = createTestWitness();
  const s = createSystem({ witness });
  const request = await s.submit('snapshot', 1);
  const receipt = await receiptFor(s, request);
  const readCheckpoint = witness.readCheckpoint;
  witness.readCheckpoint = async id => {
    receipt.request.entry.payloadBytes = '0x00';
    receipt.request.proof.length = 0;
    return readCheckpoint(id);
  };
  const decision = await s.decide(receipt);
  assert.equal(decodePayload(decision.payloadBytes, decision.record).payload.outcome, 'APPROVED');
});

test('R3,R5: a genuinely anchored false institution decision fails policy validation', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  const request = await s.submit('req-1', 1500000);
  const envelope = sign('decision', { version: 1, requestHash: hash(decodePayload(request.payloadBytes, request.record)), policyHash: hash(s.policy),
    outcome: 'APPROVED', reason: 'WITHIN_LIMIT' }, s.keys.institution.privateKey);
  const bytes = encodePayload(envelope);
  const decision = entryView(await witness.registerDecision(request.record.index, bytes), bytes);
  const trust = await s.trust();
  s.entries[decision.record.index] = decision;
  assert.throws(() => verifySingle(s.bundle(request, decision, trust), trust), /POLICY_MISMATCH/);
  assert.throws(() => audit(s.entries, trust), /POLICY_MISMATCH/);
});

test('R6: complete log covers approval and rejection, retaining summary fields', async () => {
  const { s } = await fixture();
  const r = await s.submit('req-2', 500000); await s.decide(await receiptFor(s, r));
  const result = audit(s.entries, await s.trust());
  assert.deepEqual(result, { ok: true, requests: 2, decisions: 2, pending: [], overdue: [] });
});

test('audit preserves deadline precision at the safe integer boundary and rejects out-of-range records', async () => {
  const witness = createTestWitness();
  const s = createSystem({ witness });
  witness.time = Number.MAX_SAFE_INTEGER - 60;
  const request = await s.submit('boundary-time', 1);
  witness.time = Number.MAX_SAFE_INTEGER;
  await s.decide(await receiptFor(s, request));
  const trust = disk(await s.trust());
  const entries = disk(s.entries);

  const result = audit(entries, trust);
  assert.equal(result.ok, true);
  assert.equal(result.decisions, 1);

  const outside = String(BigInt(Number.MAX_SAFE_INTEGER) + 1n);
  const wrongIndex = structuredClone(entries);
  wrongIndex[1].record.requestIndex = outside;
  assert.throws(() => audit(wrongIndex, trust), /REQUEST_LINK_MISMATCH/);

  const wrongTime = structuredClone(entries);
  wrongTime[1].record.recordedAt = outside;
  assert.throws(() => audit(wrongTime, trust), /ENTRY_OUTSIDE_CHECKPOINT/);
  assert.equal(audit(entries, { ...trust, checkpoint: { ...trust.checkpoint, issuedAt: outside } }).ok, true);

  witness.time = Number.MAX_SAFE_INTEGER;
  await s.submit('beyond-safe-deadline', 1);
  const boundary = disk(await s.trust());
  const deadline = BigInt(Number.MAX_SAFE_INTEGER) + 60n;
  const anchor = issuedAt => ({ ...boundary, checkpoint: { ...boundary.checkpoint, issuedAt: String(issuedAt) } });
  assert.deepEqual(audit(disk(s.entries), anchor(deadline - 1n)).pending, ['beyond-safe-deadline']);
  assert.deepEqual(audit(disk(s.entries), anchor(deadline)).overdue, ['beyond-safe-deadline']);
});

test('R4,R6: deletion, reordering and duplication are detected', async () => {
  const { s, trust } = await fixture();
  for (const entries of [s.entries.slice(1), [...s.entries].reverse(), [s.entries[0], s.entries[0]]]) {
    assert.throws(() => audit(entries, trust));
  }
  const entries = structuredClone(s.entries); entries[0].record.recordedAt++;
  assert.throws(() => audit(entries, trust), /LOG_ROOT_MISMATCH/);
});

test('R2,R6: missing decisions use checkpoint time; later decisions preserve past overdue', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  const request = await s.submit('forgotten', 100);
  witness.time = 1059;
  assert.deepEqual(audit(s.entries, await s.trust()).pending, ['forgotten']);
  witness.time = 1060;
  const pastTrust = await s.trust(); const pastEntries = structuredClone(s.entries);
  assert.deepEqual(audit(pastEntries, pastTrust).overdue, ['forgotten']);
  witness.time = 1061;
  const decision = await s.decide(await receiptFor(s, request)); const trust = await s.trust();
  assert.equal(verifySingle(s.bundle(request, decision, trust), trust).ok, true);
  assert.deepEqual(audit(s.entries, trust), {
    ok: true, requests: 1, decisions: 1, pending: [], overdue: [],
  });
  assert.deepEqual(audit(pastEntries, pastTrust).overdue, ['forgotten']);
});

test('R1: invalid amounts and duplicate IDs are rejected', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  for (const amount of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) await assert.rejects(s.submit('bad', amount), /INVALID_AMOUNT|INVALID_NUMBER/);
  assert.equal(witness.calls.length, 0);
  await s.submit('unique', 1);
  await assert.rejects(s.submit('unique', 2), /DUPLICATE_REQUEST/);
});

test('extra arguments do not override witness timestamps', async () => {
  const witness = createTestWitness();
  const s = createSystem({ witness });
  const request = await s.submit('timed', 1, 999);
  assert.equal(request.record.recordedAt, 1000n);

  witness.time = 1050;
  const decision = await s.decide(await receiptFor(s, request), 9999);
  assert.equal(decision.record.recordedAt, 1050n);
  const trust = await s.trust(undefined, 9999);
  assert.equal(trust.checkpoint.issuedAt, 1050n);
  assert.equal(verifySingle(s.bundle(request, decision, trust), trust).ok, true);
});

test('R1: different institution or policy is rejected with an otherwise valid customer signature', async () => {
  for (const field of ['institution', 'policyHash']) {
    const { s, request, trust } = await fixture();
    const envelope = sign('request', { ...decodePayload(request.payloadBytes, request.record).payload, [field]: 'other' }, s.keys.customer.privateKey);
    assert.throws(() => requestPayload(envelope, trust), /REQUEST_CONTEXT_MISMATCH/);
  }
});

test('R5,R6: replaced keys, checkpoint metadata and old checkpoints fail', async () => {
  const { s, bundle, trust } = await fixture();
  const wrongKey = generateKeyPairSync('ed25519').publicKey;
  for (const key of ['customerKey', 'institutionKey']) assert.throws(() => verifySingle(bundle, { ...trust, [key]: wrongKey }), /INVALID_SIGNATURE/);
  assert.throws(() => verifySingle(bundle, { ...trust, depth: 7 }), /INVALID_DEPTH/);
  for (const change of [
    t => { t.chainId = '1'; }, t => { t.evidenceLogAddress = OTHER; },
    t => { t.checkpoint.root = `0x${hash('other root')}`; },
    t => { t.checkpoint.size = '1'; }, t => { t.checkpoint.issuedAt = '999'; },
  ]) {
    const changed = disk(trust); change(changed);
    assert.throws(() => verifySingle(bundle, changed), /INVALID_INCLUSION_PROOF|INVALID_PROOF_LENGTH|ENTRY_OUTSIDE_CHECKPOINT/);
  }
  await s.submit('new', 1);
  assert.throws(() => audit([], trust), /LOG_SIZE_MISMATCH/);
  const newer = await s.trust();
  assert.throws(() => verifySingle(bundle, newer), /CHECKPOINT_MISMATCH/);
  assert.equal(verifySingle(bundle, trust).ok, true);
});

test('identical roots do not allow a different checkpoint ID', async () => {
  const { s, bundle, trust } = await fixture();
  const later = await s.trust();
  assert.deepEqual(later.checkpoint, trust.checkpoint);
  assert.notEqual(later.checkpointId, trust.checkpointId);
  assert.throws(() => verifySingle(bundle, later), /CHECKPOINT_MISMATCH/);
  assert.equal(verifySingle({ ...bundle, checkpointId: later.checkpointId }, later).ok, true);
});

test('a root supplied inside evidence cannot replace the independently obtained root', async () => {
  const { bundle, trust } = await fixture();
  const forged = structuredClone(bundle);
  forged.request.entry.record.recordedAt++;
  const tree = buildTree([forged.request.entry.record, forged.decision.entry.record], trust);
  forged.request.proof = tree.proof(0);
  forged.decision.proof = tree.proof(1);
  const forgedTrust = { ...trust, checkpoint: { ...trust.checkpoint, root: tree.root } };
  assert.equal(verifySingle(forged, forgedTrust).ok, true);
  forged.checkpoint = forgedTrust;
  assert.throws(() => verifySingle(forged, trust), /INVALID_INCLUSION_PROOF/);
});

test('R1,R3: wrong signatures fail even with valid registration and inclusion', async () => {
  for (const role of ['customer', 'institution']) {
    const witness = createTestWitness(); const s = createSystem({ witness });
    const wrongKey = generateKeyPairSync('ed25519').privateKey;
    const requestEnvelope = sign('request', { version: 1, id: 'bad-signature', customer: 'demo-customer',
      institution: s.policy.institution, currency: 'KRW', amount: 1, policyHash: hash(s.policy) },
    role === 'customer' ? wrongKey : s.keys.customer.privateKey);
    const bytes = encodePayload(requestEnvelope);
    const request = entryView(await witness.registerRequest(bytes), bytes);
    const decisionBytes = encodePayload(sign('decision', { version: 1, requestHash: hash(requestEnvelope),
      policyHash: hash(s.policy), outcome: 'APPROVED', reason: 'WITHIN_LIMIT' },
    role === 'institution' ? wrongKey : s.keys.institution.privateKey));
    const decision = entryView(await witness.registerDecision(request.record.index, decisionBytes), decisionBytes);
    const trust = await s.trust();
    s.entries.splice(0, s.entries.length, request, decision);
    assert.throws(() => verifySingle(s.bundle(request, decision, trust), trust), /INVALID_SIGNATURE/);
  }
});

test('R2,R3: originals persist before sending and post-registration failure is recoverable', async () => {
  const before = createTestWitness();
  const s = createSystem({ witness: before, onPayload() { throw new Error('DISK_FAILURE'); } });
  await assert.rejects(s.submit('not-persisted', 1), /DISK_FAILURE/);
  assert.equal(before.calls.length, 0); assert.equal(s.entries.length, 0);
  const after = createTestWitness(); let fail = true; const bytes = [];
  const second = createSystem({ witness: after, onPayload(value) { bytes.push(value); },
    onAppend() { if (fail) throw new Error('DISK_FAILURE'); } });
  let txHash;
  await assert.rejects(second.submit('received', 1), error => {
    txHash = error.txHash; return error.message === 'DISK_FAILURE' && Boolean(error.registration);
  });
  assert.equal(after.calls.length, 1); assert.equal(second.entries.length, 0);
  assert.equal(bytes.length, 1);
  fail = false;
  const registration = await after.readRecord(txHash);
  const trust = await second.trust(registration.checkpointId);
  assert.equal(second.entries.length, 0, 'checkpoint lookup does not restore local records');
  const request = entryView(registration, bytes[0]);
  second.entries.push(request);
  assert.equal(verifyReceipt(second.bundle(request, undefined, trust), trust).ok, true);
  assert.equal(after.calls.length, 1);
  assert.equal(request.payloadBytes, bytes[0]);
});

test('institution and offline verifier share the exact envelope schema', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  const good = await s.submit('good', 1);
  const bytes = encodePayload({ ...decodePayload(good.payloadBytes, good.record), extra: true });
  const request = entryView(await witness.registerRequest(bytes), bytes);
  const count = witness.calls.length;
  await assert.rejects(s.decide(await recordedReceipt(witness, request)), /INVALID_ENVELOPE/);
  const trust = await s.trust();
  s.entries[request.record.index] = request;
  assert.throws(() => verifyReceipt(s.bundle(request, undefined, trust), trust), /INVALID_ENVELOPE/);
  assert.equal(witness.calls.length, count);
});

test('repeated decisions and different registrations with the same request ID are rejected', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  const request = await s.submit('same-id', 10);
  const receipt = await receiptFor(s, request);
  await s.decide(receipt);
  await assert.rejects(s.decide(receipt), /DUPLICATE_DECISION/);
  assert.equal(witness.calls.length, 2);
  const bytes = encodePayload(sign('request', { ...decodePayload(request.payloadBytes, request.record).payload, amount: 20 }, s.keys.customer.privateKey));
  const duplicate = entryView(await witness.registerRequest(bytes), bytes);
  await assert.rejects(s.decide(await recordedReceipt(witness, duplicate)), /DUPLICATE_REQUEST/);
  const trust = await s.trust(); s.entries[duplicate.record.index] = duplicate;
  assert.throws(() => audit(s.entries, trust), /DUPLICATE_REQUEST/);
});

test('failed registrations leave the local log unchanged and can be retried explicitly', async () => {
  for (const status of ['FAILED', 'NOT_SENT']) {
    const witness = createTestWitness(); const s = createSystem({ witness });
    const request = await s.submit('retry', 1); const registerDecision = witness.registerDecision;
    const receipt = await receiptFor(s, request);
    witness.registerDecision = async () => {
      throw Object.assign(new Error('SEND_FAILED'), { registrationStatus: status,
        txHash: status === 'FAILED' ? `0x${hash('failed')}` : undefined });
    };
    await assert.rejects(s.decide(receipt), /SEND_FAILED/);
    witness.registerDecision = registerDecision;
    assert.equal(s.entries.length, 1);
    assert.equal((await s.decide(receipt)).record.kind, 1n);
    assert.equal(witness.calls.length, 2);
  }
});

test('external registrations are not imported by trust and an incomplete supplied log is rejected', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  const first = await s.submit('first', 1);
  witness.record(encodePayload({ foreign: true }), { actor: OTHER });
  const second = await s.submit('second', 2);
  assert.equal(first.record.index, 0n); assert.equal(second.record.index, 2n);
  const trust = await s.trust();
  assert.deepEqual(s.entries, [first, second]);
  assert.throws(() => s.bundle(second, undefined, trust), /LOG_SIZE_MISMATCH/);
  const tree = buildTree(witness.records, trust);
  const receipt = { checkpointId: trust.checkpointId, request: { entry: second, proof: tree.proof(second.record.index) } };
  assert.equal(verifyReceipt(receipt, trust).ok, true);
  assert.throws(() => audit(s.entries, trust), /LOG_SIZE_MISMATCH/);
  assert.throws(() => audit([first, second], trust), /LOG_SIZE_MISMATCH/);
});

test('missing or mismatched originals cannot make an on-time registration valid', async () => {
  const { s, trust } = await fixture();
  for (const [value, error] of [[null, 'MISSING_PAYLOAD'], ['0x00', 'PAYLOAD_HASH_MISMATCH']]) {
    const entries = structuredClone(s.entries); entries[1].payloadBytes = value;
    assert.throws(() => audit(entries, trust), new RegExp(error));
  }
});

test('valid inclusion paths cannot mix a request with another request decision', async () => {
  const { s, request } = await fixture();
  const other = await s.submit('other', 10); const decision = await s.decide(await receiptFor(s, other));
  const trust = await s.trust();
  assert.throws(() => verifySingle(s.bundle(request, decision, trust), trust), /DECISION_LINK_MISMATCH/);
});

test('empty checkpoint logs audit successfully but cannot produce a receipt', async () => {
  const s = createSystem({ witness: createTestWitness() });
  const trust = await s.trust();
  const result = audit(s.entries, trust);
  assert.equal(result.ok, true); assert.equal(result.requests, 0); assert.equal(result.decisions, 0);
});

test('uncertain customer registrations preserve the original error and recover without resending', async () => {
  for (const hasHash of [true, false]) {
    const witness = createTestWitness();
    let savedBytes;
    const s = createSystem({ witness, onPayload(bytes) { savedBytes = bytes; } });
    const registerRequest = witness.registerRequest;
    const failure = Object.assign(new Error('RESPONSE_LOST'), { registrationStatus: 'UNKNOWN' });
    let registration;
    witness.registerRequest = async (...args) => {
      registration = await registerRequest(...args);
      if (hasHash) failure.txHash = registration.txHash;
      throw failure;
    };
    await assert.rejects(s.submit('uncertain', 1), error => error === failure);
    witness.registerRequest = registerRequest;
    const trust = await s.trust(registration.checkpointId);
    assert.equal(witness.calls.length, 1);
    assert.equal(s.entries.length, 0);
    s.entries.push(entryView(await witness.readRecord(registration.txHash), savedBytes));
    assert.equal(verifyReceipt(s.bundle(s.entries[0], undefined, trust), trust).ok, true);
  }
});

test('business fields absent from registered array payloads cannot be supplied through views', async () => {
  const witness = createTestWitness(); const s = createSystem({ witness });
  const rawRequest = sign('request', [], s.keys.customer.privateKey);
  const requestBytes = encodePayload(rawRequest);
  const request = entryView(await witness.registerRequest(requestBytes), requestBytes);
  request.evidence = structuredClone(rawRequest);
  Object.assign(request.evidence.payload, { version: 1, id: 'invented', customer: 'demo-customer',
    institution: s.policy.institution, amount: 1, currency: 'KRW', policyHash: hash(s.policy) });
  const rawDecision = sign('decision', [], s.keys.institution.privateKey);
  const decisionBytes = encodePayload(rawDecision);
  const decision = entryView(await witness.registerDecision(request.record.index, decisionBytes), decisionBytes);
  decision.evidence = structuredClone(rawDecision);
  Object.assign(decision.evidence.payload, { version: 1, requestHash: hash(rawRequest), policyHash: hash(s.policy),
    outcome: 'APPROVED', reason: 'WITHIN_LIMIT' });
  const trust = await s.trust();
  s.entries.splice(0, s.entries.length, request, decision);
  const bundle = s.bundle(request, decision, trust);
  assert.throws(() => verifySingle(bundle, trust), /INVALID_SCHEMA/);
  assert.throws(() => requestPayload(rawRequest, trust), /INVALID_SCHEMA/);
});

test('only registrations persist entries; checkpoint reads never collect, save or replace the log', async () => {
  const witness = createTestWitness();
  const saved = [];
  const s = createSystem({ witness, async onAppend(entries) {
    await new Promise(setImmediate);
    saved.push(entries.map(entry => entry.record.index));
    entries.length = 0;
  } });
  const entries = s.entries;
  const first = await s.submit('first', 1);
  assert.deepEqual(saved, [[0n]]);
  await s.trust();
  await s.submit('second', 2);
  const oldTrust = await s.trust(first.checkpointId);
  assert.equal(s.entries, entries);
  assert.deepEqual(saved, [[0n], [0n, 1n]]);
  assert.deepEqual(entries.map(entry => entry.record.index), [0n, 1n]);
  assert.equal(verifyReceipt(s.bundle(first, undefined, oldTrust), oldTrust).ok, true);
});

test('trust reads a selected checkpoint ID without fetching receipts or issuing another checkpoint', async () => {
  const witness = createTestWitness();
  const s = createSystem({ witness });
  const request = await s.submit('selected-checkpoint', 1);
  const expected = await witness.readCheckpoint(request.checkpointId);
  witness.readRecord = async () => assert.fail('UNEXPECTED_RECEIPT_READ');
  witness.checkpoint = async () => assert.fail('UNEXPECTED_CHECKPOINT_ISSUE');

  const trust = await s.trust(String(request.checkpointId));
  assert.equal(trust.checkpointId, request.checkpointId);
  assert.deepEqual(trust.checkpoint, expected.checkpoint);
  assert.equal(verifyReceipt(s.bundle(request, undefined, trust), trust).ok, true);
  await assert.rejects(s.trust(999n), /CHECKPOINT_NOT_FOUND/);
  assert.equal(s.entries.length, 1);
});

test('trust without an ID issues a checkpoint then reads its state by ID', async () => {
  const witness = createTestWitness();
  const s = createSystem({ witness });
  const request = await s.submit('fresh-checkpoint', 1);
  const checkpoint = witness.checkpoint;
  witness.checkpoint = async () => {
    const registration = await checkpoint();
    return { ...registration, checkpoint: { ...registration.checkpoint, size: 999n } };
  };

  const trust = await s.trust();
  assert.notEqual(trust.checkpointId, request.checkpointId);
  assert.equal(trust.checkpoint.size, 1n);
  assert.deepEqual(trust.checkpoint, (await witness.readCheckpoint(trust.checkpointId)).checkpoint);
});

test('checkpoint lookup does not repair a deleted institution log entry', async () => {
  const { s, decision } = await fixture();
  s.entries.pop();
  const trust = await s.trust(decision.checkpointId);
  assert.equal(s.entries.length, 1);
  assert.throws(() => audit(s.entries, trust), /LOG_SIZE_MISMATCH/);
});

test('a repeated decision never returns a previously saved acknowledgement', async () => {
  const { s, witness, receipt } = await fixture();
  witness.readRecord = async () => assert.fail('UNEXPECTED_RECEIPT_READ');
  const count = witness.calls.length;
  await assert.rejects(s.decide(receipt), /DUPLICATE_DECISION/);
  assert.equal(witness.calls.length, count);
});

test('replacing a request at an already decided local index does not reuse an old decision', async () => {
  const { s, witness, request } = await fixture();
  const replacement = createTestWitness();
  const bytes = encodePayload(sign('request', { ...decodePayload(request.payloadBytes, request.record).payload, amount: 20 }, s.keys.customer.privateKey));
  const registration = await replacement.registerRequest(bytes);
  const other = entryView(registration, bytes);
  witness.readCheckpoint = replacement.readCheckpoint;
  const count = witness.calls.length;
  await assert.rejects(s.decide(await recordedReceipt(replacement, other)), /DUPLICATE_DECISION/);
  assert.equal(witness.calls.length, count);
});
