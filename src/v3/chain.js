import { parseAbi, encodeFunctionData, decodeFunctionResult, keccak256 } from 'viem';
import { check, integer, hashShape, canonical } from './crypto.js';
import { validateTrust } from './policy.js';

export const anchorAbi = parseAbi([
  'function publisher() view returns (address)',
  'function batchCount() view returns (uint256)',
  'function batches(uint256) view returns (bytes32 root, uint256 count, uint256 blockNumber, uint256 anchoredAt)',
  'function anchorBatch(uint256 expectedBatchId, bytes32 root, uint256 count)',
]);
const tokenAbi = parseAbi(['function balanceOf(address) view returns (uint256)']);
export const quantity = value => '0x' + BigInt(value).toString(16);

export function jsonRpc(url, { fetchImpl = fetch, timeoutMs = 10000 } = {}) {
  let id = 0;
  return async (method, params) => {
    const requestId = ++id;
    let response;
    try {
      response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }), signal: AbortSignal.timeout(timeoutMs) });
      check(response.ok, 'RPC_UNAVAILABLE');
      const body = await response.json();
      check(body.id === requestId && body.jsonrpc === '2.0' && !body.error && Object.hasOwn(body, 'result'), 'RPC_UNAVAILABLE');
      return body.result;
    } catch { throw new Error('RPC_UNAVAILABLE'); }
  };
}
export class ChainReader {
  constructor(rpc, trust) {
    validateTrust(trust);
    this.rpc = rpc; this.trust = structuredClone(trust); this.reads = new Map();
  }
  async at(block = 'finalized') {
    const { rpc, trust } = this;
    check(BigInt(await rpc('eth_chainId', [])) === integer(trust.policy.chainId), 'CHAIN_MISMATCH');
    const h = await rpc(hashShape(block) ? 'eth_getBlockByHash' : 'eth_getBlockByNumber', [block, false]);
    check(h && hashShape(h.hash), 'BLOCK_UNAVAILABLE');
    const view = new ChainView(this, h);
    await view.assertCanonical();
    const code = await rpc('eth_getCode', [trust.policy.anchorAddress, { blockHash: h.hash, requireCanonical: true }]);
    check(code !== '0x' && keccak256(code) === trust.codeHash, 'CONTRACT_MISMATCH');
    check((await view.call('publisher')).toLowerCase() === trust.publisher, 'PUBLISHER_MISMATCH');
    const finalized = await rpc('eth_getBlockByNumber', ['finalized', false]);
    check(finalized, 'FINALITY_UNAVAILABLE');
    view.finality = BigInt(finalized.number) >= BigInt(h.number) ? 'FINALIZED' : 'PROVISIONAL';
    return view;
  }
}
class ChainView {
  constructor(reader, h) {
    this.reader = reader; this.h = h; this.metas = new Map();
    this.context = { blockNumber: BigInt(h.number).toString(), blockHash: h.hash, timestamp: BigInt(h.timestamp).toString() };
  }
  async assertCanonical() {
    const h = await this.reader.rpc('eth_getBlockByNumber', [this.h.number, false]);
    check(h?.hash === this.h.hash, 'REORG');
  }
  async block(ref) {
    integer(ref.blockNumber); check(hashShape(ref.blockHash), 'INVALID_BLOCK');
    check(BigInt(ref.blockNumber) <= BigInt(this.h.number), 'FUTURE_BLOCK');
    const b = await this.reader.rpc('eth_getBlockByNumber', [quantity(ref.blockNumber), false]);
    check(b?.hash === ref.blockHash, 'REORG');
    return b;
  }
  async call(functionName, args = []) {
    const data = encodeFunctionData({ abi: anchorAbi, functionName, args });
    const raw = await this.reader.rpc('eth_call', [{ to: this.reader.trust.policy.anchorAddress, data },
      { blockHash: this.h.hash, requireCanonical: true }]);
    return decodeFunctionResult({ abi: anchorAbi, functionName, data: raw });
  }
  async count() { return (await this.call('batchCount')).toString(); }
  async batch(id) {
    integer(String(id), true);
    if (!this.metas.has(String(id))) {
      const task = (async () => {
        const [root, count, number, time] = await this.call('batches', [BigInt(id)]);
        check(count > 0n && count <= 32n && number <= BigInt(this.h.number), 'BATCH_UNAVAILABLE');
        const block = await this.reader.rpc('eth_getBlockByNumber', [quantity(number), false]);
        check(block && BigInt(block.timestamp) === time, 'ANCHOR_MISMATCH');
        return { batchId: String(id), root, count: Number(count), blockNumber: number.toString(),
          blockHash: block.hash, anchoredAt: time.toString() };
      })();
      this.metas.set(String(id), task);
      task.catch(() => this.metas.delete(String(id)));
    }
    return this.metas.get(String(id));
  }
  async balance(ref, policy) {
    await this.block(ref);
    const data = encodeFunctionData({ abi: tokenAbi, functionName: 'balanceOf', args: [policy.treasury] });
    const params = [{ to: policy.token, data }, { blockHash: ref.blockHash, requireCanonical: true }];
    const key = canonical({ chainId: policy.chainId, params });
    const reads = this.reader.reads;
    if (!reads.has(key)) {
      if (reads.size >= 256) reads.delete(reads.keys().next().value);
      const task = this.reader.rpc('eth_call', params).then(raw => {
        check(/^0x[0-9a-fA-F]{64}$/.test(raw), 'INVALID_STATE');
        return decodeFunctionResult({ abi: tokenAbi, functionName: 'balanceOf', data: raw }).toString();
      });
      reads.set(key, task);
      task.catch(() => { if (reads.get(key) === task) reads.delete(key); });
    }
    return reads.get(key);
  }
}
export function anchorCall(batch, trust) {
  check(hashShape(batch.root) && Number.isInteger(batch.count) && batch.count > 0 && batch.count <= 32, 'INVALID_BATCH');
  integer(String(batch.batchId), true);
  return { chainId: trust.policy.chainId, to: trust.policy.anchorAddress, value: '0',
    data: encodeFunctionData({ abi: anchorAbi, functionName: 'anchorBatch',
      args: [BigInt(batch.batchId), batch.root, BigInt(batch.count)] }) };
}
