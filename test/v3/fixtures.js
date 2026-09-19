import { generateKeyPairSync } from 'node:crypto';
import { hash } from '../../src/v3/crypto.js';
import { requestRecord, scope, makeDecision, receiptRef } from '../../src/v3/policy.js';
import { buildTree } from '../../src/v3/merkle.js';
export function fixture() {
  const requester = generateKeyPairSync('ed25519'), institution = generateKeyPairSync('ed25519');
  const pub = key => key.export({ type: 'spki', format: 'pem' });
  const address = '0x' + '11'.repeat(20);
  const policy = { version: 3, logId: 'test-log', chainId: '31337', anchorAddress: address, policyId: 'usdc-reserve-v1',
    ruleVersion: 1, institutionId: 'company', token: '0x' + '22'.repeat(20), decimals: 6, treasury: address,
    limitAtomic: '100000000', reserveAtomic: '100000000', decisionWindowSeconds: 90, stateRule: 'RECEIPT_BLOCK_END' };
  const trust = { policy, policyHash: hash('policy-v3', policy), publisher: address, codeHash: '0x' + '33'.repeat(32),
    requesterKeys: { alice: pub(requester.publicKey) }, institutionKeys: { company: pub(institution.publicKey) } };
  const request = (amount = '50000000', created = '1') => requestRecord({ ...scope(policy), requesterId: 'alice',
    institutionId: policy.institutionId, token: policy.token, treasury: policy.treasury, recipient: address,
    amountAtomic: amount, createdAtMs: created, policyHash: trust.policyHash }, 'alice', requester.privateKey);
  return { trust, requester, institution, request };
}
export class FakeChain {
  constructor() { this.batches = []; this.timestamp = 100; this.reads = 0; this.finality = 'FINALIZED'; }
  get context() { return { timestamp: String(this.timestamp), blockHash: '0x' + 'ab'.repeat(32), blockNumber: '100' }; }
  async assertCanonical() {}
  async count() { return String(this.batches.length); }
  async batch(id) { if (!this.batches[Number(id) - 1]) throw new Error('BATCH_UNAVAILABLE'); return this.batches[Number(id) - 1]; }
  async balance() { this.reads++; return '120000000'; }
  add(records, time = this.timestamp) {
    const tree = buildTree(records), batchId = String(this.batches.length + 1);
    const meta = { batchId, root: tree.root, count: tree.count, blockNumber: batchId,
      blockHash: '0x' + Number(batchId).toString(16).padStart(64, '0'), anchoredAt: String(time) };
    this.batches.push(meta); return meta;
  }
}
export async function paired() {
  const f = fixture(), chain = new FakeChain(), request = f.request();
  const rm = chain.add([request]);
  const { record: decision, snapshot } = await makeDecision(request, receiptRef(rm, 0), f.trust, chain, 'company', f.institution.privateKey);
  chain.add([decision], 110);
  const batches = [[request], [decision]];
  const archive = { batch: id => batches[Number(id) - 1], blob: () => snapshot };
  const bundle = { request: { batchId: '1', record: request, count: 1, index: 0, proof: [] },
    decision: { batchId: '2', record: decision, count: 1, index: 0, proof: [] }, snapshot };
  return { ...f, request, decision, snapshot, chain, archive, bundle, batches };
}
