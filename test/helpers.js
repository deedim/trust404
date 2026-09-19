import assert from 'node:assert/strict';
import { createSystem, decodePayload, encodePayload, hash } from '../src/evidence.js';
import { buildTree, payloadHash } from '../src/evm.js';

export const CUSTOMER = '0x0000000000000000000000000000000000000001';
export const INSTITUTION = '0x0000000000000000000000000000000000000002';
export const OTHER = '0x0000000000000000000000000000000000000004';
export const json = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item);
export const disk = value => JSON.parse(json(value));

// A boundary double for business tests; actual EVM roots/state are checked by the Anvil suite.
export function createTestWitness() {
  const context = { chainId: 31337n, evidenceLogAddress: '0x0000000000000000000000000000000000000003',
    depth: 6, deploymentBlock: 0, customerAddress: CUSTOMER, institutionAddress: INSTITUTION };
  const records = []; const registrations = new Map(); const calls = [];
  let sequence = 0;
  const witness = { context, records, calls, time: 1000,
    publish(entry = null) {
      const checkpointId = BigInt(sequence++);
      const result = { txHash: `0x${hash(`tx-${sequence}`)}`, entry, checkpointId,
        checkpoint: { size: BigInt(records.length), root: buildTree(records, context).root, issuedAt: BigInt(witness.time) },
        blockNumber: sequence, blockHash: `0x${hash(`block-${sequence}`)}` };
      registrations.set(result.txHash, structuredClone(result));
      return structuredClone(result);
    },
    record(bytes, { actor = CUSTOMER, requestIndex } = {}) {
      const index = BigInt(records.length); const kind = requestIndex === undefined ? 0n : 1n;
      assert(index < 2n ** BigInt(context.depth), 'TREE_CAPACITY_EXCEEDED');
      assert(!records.length || BigInt(witness.time) >= records.at(-1).recordedAt, 'INVALID_TIME');
      if (kind === 0n) {
        assert(!records.some(entry => entry.kind === 0n && entry.actor === actor && entry.payloadHash === payloadHash(bytes)), 'DUPLICATE_REQUEST_HASH');
      } else {
        assert(actor === INSTITUTION && records[Number(requestIndex)]?.kind === 0n, 'INVALID_DECISION_LINK');
        assert(!records.some(entry => entry.kind === 1n && entry.requestIndex === BigInt(requestIndex)), 'DUPLICATE_DECISION');
      }
      const entry = { index, kind, actor, requestIndex: kind === 0n ? index : BigInt(requestIndex),
        payloadHash: payloadHash(bytes), recordedAt: BigInt(witness.time) };
      records.push(entry);
      return witness.publish(entry);
    },
    async registerRequest(bytes) {
      calls.push({ method: 'registerRequest', bytes });
      return witness.record(bytes);
    },
    async registerDecision(requestIndex, bytes) {
      calls.push({ method: 'registerDecision', bytes, requestIndex });
      return witness.record(bytes, { actor: INSTITUTION, requestIndex });
    },
    async readRecord(txHash) {
      assert(registrations.has(txHash), 'REGISTRATION_NOT_CONFIRMED');
      return structuredClone(registrations.get(txHash));
    },
    async checkpoint() { return witness.publish(); },
  };
  return witness;
}

export function entryView(registration, bytes) {
  return { payloadBytes: bytes, record: registration.entry, txHash: registration.txHash };
}

export function alterPayload(entry, change) {
  const envelope = decodePayload(entry.payloadBytes, entry.record);
  change(envelope);
  entry.payloadBytes = encodePayload(envelope);
}

export async function fixture(amount = 1500000) {
  const witness = createTestWitness();
  const s = createSystem({ witness });
  const request = await s.submit('req-1', amount);
  witness.time = 1060;
  const decision = await s.decide(request);
  const trust = await s.trust();
  return { witness, s, request, decision, trust, bundle: s.bundle(request, decision, trust) };
}
