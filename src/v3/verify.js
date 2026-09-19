import { check, canonical, verifySignature } from './crypto.js';
import { buildTree, verifyProof } from './merkle.js';
import { validateTrust, validateRequest, validateDecision, receiptRef } from './policy.js';

const operational = new Set(['RPC_UNAVAILABLE', 'BLOCK_UNAVAILABLE', 'FINALITY_UNAVAILABLE', 'STATE_UNAVAILABLE',
  'DATA_UNAVAILABLE', 'REORG', 'BATCH_UNAVAILABLE']);
export function timing(requestMeta, decisionMeta, context) {
  const deadline = BigInt(requestMeta.anchoredAt) + 90n;
  return decisionMeta ? (BigInt(decisionMeta.anchoredAt) <= deadline ? 'REGISTERED_ON_TIME' : 'REGISTERED_LATE')
    : (BigInt(context.timestamp) <= deadline ? 'PENDING' : 'MISSING_AS_OF_H');
}
async function inclusion(item, chain) {
  check(item && item.record, 'DATA_UNAVAILABLE');
  const meta = await chain.batch(item.batchId);
  check(item.count === meta.count, 'INVALID_INCLUSION');
  verifyProof(item.record, item.index, item.count, item.proof, meta.root);
  return meta;
}
async function checkPair(request, decision, ref, rm, dm, snapshot, trust, chain) {
  check(BigInt(dm.blockNumber) > BigInt(rm.blockNumber), 'INVALID_EVENT_ORDER');
  return validateDecision(decision, request, ref, snapshot, trust, chain);
}
export async function verifyOne(bundle, trust, chain) {
  validateTrust(trust); await chain.assertCanonical();
  const rm = await inclusion(bundle.request, chain), dm = await inclusion(bundle.decision, chain);
  const request = bundle.request.record;
  validateRequest(request, trust);
  const ref = receiptRef(rm, bundle.request.index);
  const decision = await checkPair(request, bundle.decision.record, ref, rm, dm, bundle.snapshot ?? null, trust, chain);
  await chain.assertCanonical();
  return { ok: true, requestId: request.requestId, record: 'VALID', policy: 'MATCH', outcome: decision.outcome,
    reason: decision.reason, timing: timing(rm, dm, chain.context), finality: chain.finality, asOf: chain.context };
}
export async function auditAll(archive, trust, chain) {
  validateTrust(trust); await chain.assertCanonical();
  const count = BigInt(await chain.count());
  const requests = new Map(), decisions = new Map(), issues = [];
  let complete = true;
  for (let id = 1n; id <= count; id++) {
    const meta = await chain.batch(id.toString());
    let records;
    try { records = await archive.batch(id.toString()); }
    catch { complete = false; issues.push({ batchId: id.toString(), code: 'DATA_UNAVAILABLE' }); continue; }
    let validRoot = false;
    try { validRoot = Array.isArray(records) && records.length === meta.count && buildTree(records).root === meta.root; } catch {}
    if (!validRoot) {
      complete = false; issues.push({ batchId: id.toString(), code: 'TAMPERED_EXPORT' }); continue;
    }
    for (const [index, record] of records.entries()) {
      try {
        if (record.kind === 'REQUEST') {
          validateRequest(record, trust);
          if (requests.has(record.requestId)) issues.push({ requestId: record.requestId, code: 'DUPLICATE_REQUEST' });
          else requests.set(record.requestId, { record, meta, ref: receiptRef(meta, index) });
        } else if (record.kind === 'DECISION') {
          const id = record.decision?.payload?.requestId;
          check(typeof id === 'string', 'INVALID_RECORD');
          const list = decisions.get(id) ?? [];
          list.push({ record, meta }); decisions.set(id, list);
        } else throw new Error('INVALID_RECORD');
      } catch (e) {
        // Invalid committed records may hide a request ID; absence is not conclusive.
        complete = false; issues.push({ batchId: id.toString(), index, code: e.message });
      }
    }
  }
  const results = [];
  for (const [id, r] of requests) {
    const list = decisions.get(id) ?? [];
    const result = { requestId: id, timing: !complete && !list.length ? 'UNKNOWN' : timing(r.meta, list[0]?.meta, chain.context),
      decisions: [] };
    const payloads = new Set();
    for (const { record, meta } of list) {
      try {
        const signedPayload = verifySignature(record.decision, 'decision-v3', trust.institutionKeys);
        payloads.add(canonical(signedPayload));
        const stateHash = signedPayload.stateHash;
        let snapshot = null;
        if (stateHash !== null) {
          try { snapshot = await archive.blob(stateHash); } catch { throw new Error('DATA_UNAVAILABLE'); }
        }
        const d = await checkPair(r.record, record, r.ref, r.meta, meta, snapshot, trust, chain);
        payloads.add(canonical(d));
        result.decisions.push({ record: 'VALID', policy: 'MATCH', outcome: d.outcome, reason: d.reason,
          timing: timing(r.meta, meta, chain.context) });
      } catch (e) {
        if (operational.has(e.message)) complete = false;
        result.decisions.push({ error: e.message }); issues.push({ requestId: id, code: e.message });
      }
    }
    if (list.length > 1) issues.push({ requestId: id, code: payloads.size > 1 ? 'CONFLICTING_DECISIONS' : 'DUPLICATE_DECISION' });
    results.push(result);
  }
  for (const id of decisions.keys()) if (!requests.has(id)) issues.push({ requestId: id, code: 'UNMATCHED_DECISION' });
  // A late read failure must not leave earlier missing-status conclusions intact.
  if (!complete) for (const r of results) if (!r.decisions.length) r.timing = 'UNKNOWN';
  await chain.assertCanonical();
  return { ok: complete && !issues.length && results.every(r => !['MISSING_AS_OF_H', 'REGISTERED_LATE'].includes(r.timing)),
    complete, batchCount: count.toString(), asOf: chain.context, finality: chain.finality, requests: results, issues };
}
