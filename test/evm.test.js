import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  AbiCoder, ContractFactory, Interface, JsonRpcProvider, TransactionResponse,
  ZeroHash, concat, getAddress, keccak256, toUtf8Bytes,
} from 'ethers';
import {
  buildTree, checkedLog, checkpointInfo, createEvmWitness,
  deployEvmWitness, verifyInclusions, leafHash, payloadHash, readRecord, safeNumber,
} from '../src/evm.js';

const artifact = JSON.parse(await readFile(new URL('../contracts/out/EvidenceLog.sol/EvidenceLog.json', import.meta.url), 'utf8'));
const iface = new Interface(artifact.abi);
const CUSTOMER = '0x0000000000000000000000000000000000000001';
const INSTITUTION = '0x0000000000000000000000000000000000000002';
const EVIDENCE_LOG = '0x0000000000000000000000000000000000000003';
const OTHER = '0x0000000000000000000000000000000000000004';
const digest = text => keccak256(toUtf8Bytes(text));
const pair = (a, b) => keccak256(concat([a, b].sort()));
const disk = value => JSON.parse(JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item));
const context = {
  chainId: 31337n, evidenceLogAddress: EVIDENCE_LOG, depth: 6, deploymentBlock: 10n,
  customerAddress: CUSTOMER, institutionAddress: INSTITUTION,
};
const payloadBytes = '0x00ff80';
const requestEntry = {
  index: 0n, kind: 0n, actor: CUSTOMER, requestIndex: 0n, payloadHash: payloadHash(payloadBytes), recordedAt: 1011n,
};
const decisionEntry = {
  index: 1n, kind: 1n, actor: INSTITUTION, requestIndex: 0n, payloadHash: payloadHash('0xabcd'), recordedAt: 1012n,
};

function trustFor(entries, changes = {}) {
  const ctx = { ...context, ...changes };
  return {
    ...ctx, checkpointId: BigInt(entries.length),
    checkpoint: { size: BigInt(entries.length), root: buildTree(entries, ctx).root, issuedAt: 2000n },
    blockNumber: 20n, blockHash: digest('checkpoint-block'), txHash: digest('checkpoint-tx'),
  };
}

function eventLog(name, values) {
  const event = iface.getEvent(name);
  return { address: EVIDENCE_LOG, ...iface.encodeEventLog(event, event.inputs.map(input => values[input.name])) };
}

function fixture({ seeded = true } = {}) {
  const entries = [];
  const receipts = new Map();
  const checkpoints = new Map();
  const blocks = new Map();
  const calls = [];
  let nextCheckpoint = 0n;
  function record(rawEntry = null, { blockNumber, timestamp } = {}) {
    const checkpointId = nextCheckpoint++;
    blockNumber ??= Number(checkpointId) + 10;
    timestamp ??= blockNumber + 1000;
    const blockHash = digest(`block-${blockNumber}`);
    const logs = [];
    if (rawEntry) {
      const entry = { ...rawEntry, recordedAt: BigInt(timestamp) };
      entries.push(entry);
      const log = eventLog('EntryRecorded', { ...entry, checkpointId });
      logs.push(log);
    }
    const checkpoint = { size: BigInt(entries.length), root: buildTree(entries, context).root, issuedAt: BigInt(timestamp) };
    logs.push(eventLog('CheckpointPublished', { checkpointId, ...checkpoint }));
    const receipt = { hash: digest(`tx-${checkpointId}`), status: 1, blockNumber, blockHash, logs };
    receipts.set(receipt.hash, receipt);
    checkpoints.set(checkpointId, checkpoint);
    blocks.set(blockNumber, { hash: blockHash, timestamp });
    return receipt;
  }
  const provider = {
    getNetwork: async () => ({ chainId: context.chainId }),
    getTransactionReceipt: async hash => receipts.get(hash) ?? null,
    getBlock: async number => blocks.get(number) ?? null,
  };
  const customerSigner = { provider, getAddress: async () => CUSTOMER };
  const institutionSigner = { provider, getAddress: async () => INSTITUTION };
  const response = receipt => ({ hash: receipt.hash, wait: async () => receipt });
  const evidenceLog = {
    interface: iface, runner: customerSigner, getAddress: async () => EVIDENCE_LOG,
    depth: async () => BigInt(context.depth), institution: async () => INSTITUTION,
    connect(signer) { return { ...this, runner: signer }; },
    async registerRequest(hash) {
      const actor = await this.runner.getAddress();
      calls.push(['registerRequest', hash, actor]);
      const index = BigInt(entries.length);
      return response(record({ index, kind: 0n, actor, requestIndex: index, payloadHash: hash }));
    },
    async registerDecision(requestIndex, hash) {
      const actor = await this.runner.getAddress();
      calls.push(['registerDecision', requestIndex, hash, actor]);
      return response(record({ index: BigInt(entries.length), kind: 1n, actor, requestIndex, payloadHash: hash }));
    },
    async createCheckpoint() {
      calls.push(['createCheckpoint']);
      return response(record());
    },
  };
  const deployment = record();
  const receipt = seeded ? record(requestEntry) : deployment;
  return {
    evidenceLog, provider, customerSigner, institutionSigner, record, receipt, deployment,
    entries, receipts, checkpoints, blocks, calls, trust: { ...context },
  };
}

function changeEvent(receipt, name, changes) {
  const topic = iface.getEvent(name).topicHash;
  const i = receipt.logs.findIndex(log => log.topics[0] === topic);
  receipt.logs[i] = eventLog(name, { ...iface.parseLog(receipt.logs[i]).args.toObject(), ...changes });
}

test('payload hashing accepts finalized hex bytes without decoding and rejects malformed hex', async () => {
  for (const bytes of ['0x', '0x00', '0xabcdef', '0xABCDEF', payloadBytes]) {
    assert.equal(payloadHash(bytes), keccak256(bytes));
  }
  for (const bytes of [null, undefined, '', 'abcd', '0x0', '0xgg', '0X00', '0x00 ', 0, [0], new Uint8Array([0])]) {
    assert.throws(() => payloadHash(bytes), /INVALID_PAYLOAD_BYTES/);
  }
  const f = fixture();
  const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
  assert.throws(() => witness.registerRequest('0x0'), /INVALID_PAYLOAD_BYTES/);
  assert.throws(() => witness.registerDecision(0, '0x0'), /INVALID_PAYLOAD_BYTES/);
  assert.equal(f.calls.length, 0);
});

test('registration hashes raw bytes and reads bigint metadata from ABI events', async () => {
  const f = fixture({ seeded: false });
  const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
  const result = await witness.registerRequest(payloadBytes);
  assert.deepEqual(f.calls, [['registerRequest', payloadHash(payloadBytes), CUSTOMER]]);
  assert.deepEqual(result.entry, requestEntry);
  assert.equal(result.txHash, digest('tx-1'));
  assert.equal(result.checkpointId, 1n);
  assert.equal(result.blockNumber, 11n);
  assert.equal(result.blockHash, digest('block-11'));
  assert.deepEqual(result.checkpoint, { size: 1n, root: buildTree([requestEntry], context).root, issuedAt: 1011n });
  const decision = await witness.registerDecision('0', '0xabcd');
  assert.deepEqual(decision.entry, decisionEntry);
  assert.deepEqual(f.calls[1], ['registerDecision', 0n, payloadHash('0xabcd'), INSTITUTION]);
  assert.equal(decision.checkpoint.size, 2n);
  assert.deepEqual(await readRecord({ ...f.evidenceLog, runner: f.provider }, decision.txHash, f.trust), decision);
});

test('wrong signer fails before contract invocation', async t => {
  for (const [name, change, error] of [
    ['customer signer', f => { f.evidenceLog.runner.getAddress = async () => OTHER; }, /SIGNER_MISMATCH/],
    ['provider-only sender', f => { f.evidenceLog.runner = f.provider; }, TypeError],
  ]) {
    await t.test(name, async () => {
      const f = fixture();
      const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
      change(f);
      await assert.rejects(witness.registerRequest(payloadBytes), error);
      assert.equal(f.calls.length, 0);
    });
  }
  const f = fixture();
  const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
  f.institutionSigner.getAddress = async () => CUSTOMER;
  await assert.rejects(witness.registerDecision(0n, payloadBytes), /SIGNER_MISMATCH/);
  for (const index of [-1n, 2n ** 256n, Number.MAX_SAFE_INTEGER + 1, null]) {
    assert.throws(() => witness.registerDecision(index, payloadBytes));
  }
  assert.equal(f.calls.length, 0);
});

test('record reads reject unconfirmed receipts, block mismatches and ambiguous event sources', async t => {
  for (const [name, change, error] of [
    ['pending', f => { f.provider.getTransactionReceipt = async () => null; }, /REGISTRATION_NOT_CONFIRMED/],
    ['failed', f => { f.receipt.status = 0; }, /REGISTRATION_NOT_CONFIRMED/],
    ['wrong transaction', f => { f.receipt.hash = digest('other tx'); }, /TRANSACTION_MISMATCH/],
    ['missing block', f => { f.provider.getBlock = async () => null; }, /BLOCK_MISMATCH/],
    ['orphaned block', f => { f.blocks.get(11).hash = digest('other block'); }, /BLOCK_MISMATCH/],
    ['foreign events', f => { f.receipt.logs.forEach(log => { log.address = OTHER; }); }, /INVALID_RECEIPT/],
    ['no checkpoint', f => { f.receipt.logs.pop(); }, /INVALID_RECEIPT/],
    ['duplicate checkpoint', f => { f.receipt.logs.push(f.receipt.logs[1]); }, /INVALID_RECEIPT/],
    ['duplicate entry', f => { f.receipt.logs.push(f.receipt.logs[0]); }, /INVALID_RECEIPT/],
  ]) {
    await t.test(name, async () => {
      const f = fixture();
      const txHash = f.receipt.hash;
      change(f);
      await assert.rejects(readRecord(f.evidenceLog, txHash, f.trust), error);
      assert.equal(f.calls.length, 0);
    });
  }
});

test('record reads ignore foreign events and support provider-only connections', async () => {
  const f = fixture();
  const extra = f.receipt.logs.map(log => ({ ...log, address: OTHER }));
  f.receipt.logs.push(...extra, { address: EVIDENCE_LOG, topics: [digest('unrelated event')], data: '0x' });
  const result = await readRecord({ ...f.evidenceLog, runner: f.provider }, f.receipt.hash, f.trust);
  assert.deepEqual(result.entry, requestEntry);
  assert.deepEqual(await readRecord(f.evidenceLog, f.deployment.hash, f.trust), {
    txHash: f.deployment.hash, entry: null, checkpointId: 0n, checkpoint: f.checkpoints.get(0n),
    blockNumber: 10n, blockHash: f.deployment.blockHash,
  });

  const upperHash = value => `0x${value.slice(2).toUpperCase()}`;
  f.receipt.hash = upperHash(f.receipt.hash);
  f.receipt.blockHash = upperHash(f.receipt.blockHash);
  f.blocks.get(f.receipt.blockNumber).hash = upperHash(f.blocks.get(f.receipt.blockNumber).hash);
  assert.deepEqual(await readRecord(f.evidenceLog, f.receipt.hash, f.trust), result);
});

test('send verifies payload, actor, kind and decision link in returned records', async t => {
  await t.test('request actor', async () => {
    const f = fixture({ seeded: false });
    const register = f.evidenceLog.registerRequest;
    f.evidenceLog.registerRequest = async (...args) => {
      const tx = await register.apply(f.evidenceLog, args);
      changeEvent(f.receipts.get(tx.hash), 'EntryRecorded', { actor: OTHER });
      return tx;
    };
    const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
    await assert.rejects(witness.registerRequest(payloadBytes), /ACTOR_MISMATCH/);
  });

  for (const [name, changes, error] of [
    ['payload', { payloadHash: digest('other payload') }, /REGISTRATION_MISMATCH/],
    ['actor', { actor: OTHER }, /ACTOR_MISMATCH/],
    ['kind', { kind: 0n, actor: CUSTOMER, requestIndex: 1n }, /REGISTRATION_MISMATCH/],
  ]) {
    await t.test(name, async () => {
      const f = fixture();
      const contract = f.evidenceLog.connect(f.institutionSigner);
      const register = contract.registerDecision;
      contract.registerDecision = async (...args) => {
        const tx = await register.apply(contract, args);
        changeEvent(f.receipts.get(tx.hash), 'EntryRecorded', changes);
        return tx;
      };
      f.evidenceLog.connect = () => contract;
      const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
      await assert.rejects(witness.registerDecision(0n, '0xabcd'), caught => {
        assert.match(caught.message, error);
        assert.equal(caught.txHash, digest('tx-2'));
        assert.equal(caught.registrationStatus, 'UNKNOWN');
        return true;
      });
      assert.equal(f.calls.length, 1);
    });
  }
  const f = fixture();
  f.record({ ...requestEntry, index: 1n, requestIndex: 1n, payloadHash: digest('second request') });
  const contract = f.evidenceLog.connect(f.institutionSigner);
  const register = contract.registerDecision;
  contract.registerDecision = async (...args) => {
    const tx = await register.apply(contract, args);
    changeEvent(f.receipts.get(tx.hash), 'EntryRecorded', { requestIndex: 1n });
    return tx;
  };
  f.evidenceLog.connect = () => contract;
  const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
  await assert.rejects(witness.registerDecision(0n, '0xabcd'), /REQUEST_LINK_MISMATCH/);
});

test('checkpoints are fresh even without new entries and cannot contain an entry', async () => {
  const f = fixture();
  const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
  const a = await witness.checkpoint();
  const b = await witness.checkpoint();
  assert.equal(a.entry, null);
  assert.equal(b.entry, null);
  assert.equal(b.checkpointId, a.checkpointId + 1n);
  assert.notEqual(b.txHash, a.txHash);
  assert.equal(a.checkpoint.size, 1n);
  assert.equal(a.checkpoint.root, b.checkpoint.root);
  assert(b.checkpoint.issuedAt > a.checkpoint.issuedAt);
  f.evidenceLog.createCheckpoint = async () => ({ hash: f.receipt.hash, wait: async () => f.receipt });
  await assert.rejects(witness.checkpoint(), /UNEXPECTED_ENTRY/);
});

test('leaf commitments use double Keccak over ABI encoding and bind every metadata field', () => {
  const abi = AbiCoder.defaultAbiCoder();
  const encoded = abi.encode(
    ['uint256', 'address', 'uint256', 'uint8', 'address', 'uint256', 'bytes32', 'uint256'],
    [31337n, EVIDENCE_LOG, 0n, 0n, CUSTOMER, 0n, requestEntry.payloadHash, 1011n],
  );
  const expected = keccak256(keccak256(encoded));
  assert.equal(leafHash(requestEntry, context), expected);
  assert.notEqual(expected, keccak256(encoded));
  for (const change of [
    { index: 1n }, { kind: 1n }, { actor: OTHER }, { requestIndex: 1n },
    { payloadHash: digest('changed') }, { recordedAt: 1012n },
  ]) assert.notEqual(leafHash({ ...requestEntry, ...change }, context), expected);
  assert.notEqual(leafHash(requestEntry, { ...context, chainId: 1n }), expected);
  assert.notEqual(leafHash(requestEntry, { ...context, evidenceLogAddress: OTHER }), expected);
  assert.equal(leafHash(disk(requestEntry), disk(context)), expected);
  const max = 2n ** 256n - 1n;
  assert.equal(typeof leafHash({ ...requestEntry, index: max, requestIndex: max, recordedAt: max }, { ...context, chainId: max }), 'string');
  assert.throws(() => leafHash({ ...requestEntry, kind: 256n }, context));
  assert.throws(() => leafHash({ ...requestEntry, index: max + 1n }, context), /out-of-bounds/);
  for (const index of [Number.MAX_SAFE_INTEGER + 1, 1.5, true, null, -1n]) {
    assert.throws(() => leafHash({ ...requestEntry, index }, context));
  }
});

test('depth-six trees preserve leaf order and reject empty positions, overflow and other depths', () => {
  const entries = [requestEntry, decisionEntry, { ...requestEntry, index: 2n, requestIndex: 2n }];
  const [a, b, c] = entries.map(entry => leafHash(entry, context));
  const tree = buildTree(entries, context);
  assert.deepEqual(tree.proof(0n).slice(0, 2), [b, pair(c, ZeroHash)]);
  assert.deepEqual(tree.proof('2').slice(0, 2), [ZeroHash, pair(a, b)]);
  assert.equal(tree.proof(0).length, 6);
  assert.equal(tree.proof(0).reduce(pair, a), tree.root);
  assert.notEqual(buildTree([...entries].reverse(), context).root, tree.root);
  assert.throws(() => tree.proof(3), /INVALID_INDEX/);
  assert.throws(() => tree.proof(2n ** 64n), /overflow/);
  assert.throws(() => tree.proof(-1), /INVALID_INTEGER/);
  assert.throws(() => buildTree([], context).proof(0), /INVALID_INDEX/);
  assert.throws(() => buildTree(Array(65).fill(requestEntry), context), /TREE_CAPACITY_EXCEEDED/);
  for (const depth of [0, 1, 2, 3, 5, 7, 255, 256]) {
    assert.throws(() => buildTree([], { ...context, depth }), /INVALID_DEPTH/);
  }
});

test('OpenZeppelin roots and every proof match a full fixed-depth reference across subtree boundaries', () => {
  const ctx = { ...context, depth: 6 };
  for (const size of [0, 1, 2, 3, 7, 8, 9, 17, 63, 64]) {
    const entries = Array.from({ length: size }, (_, i) => ({
      ...requestEntry, index: BigInt(i), requestIndex: BigInt(i),
    }));
    const levels = [Array.from({ length: 64 }, (_, i) =>
      i < size ? leafHash(entries[i], ctx) : ZeroHash)];
    for (let level = 0; level < ctx.depth; level++) {
      const nodes = levels[level];
      levels.push(Array.from({ length: nodes.length / 2 }, (_, i) => pair(nodes[2 * i], nodes[2 * i + 1])));
    }

    const tree = buildTree(entries, ctx);
    assert.equal(tree.root, levels[ctx.depth][0], `root at size ${size}`);
    for (let index = 0; index < size; index++) {
      const proof = levels.slice(0, ctx.depth).map((nodes, level) => nodes[(index >> level) ^ 1]);
      assert.deepEqual(tree.proof(index), proof, `proof ${index} at size ${size}`);
    }
    assert.throws(() => tree.proof(size), /INVALID_INDEX/);
  }
});

test('numeric normalization accepts ethers integer representations and rejects precision loss', () => {
  for (const [value, expected] of [
    [0, 0], [1n, 1], ['12', 12], ['01', 1], [' 1', 1], ['+1', 1], ['0x01', 1],
    [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
  ]) {
    assert.equal(safeNumber(value), expected);
  }
  for (const value of [true, null, undefined, '', '1.0', '1e2', -1, -1n, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 2n ** 256n]) {
    assert.throws(() => safeNumber(value));
  }
  for (const value of [2n ** 53n, `${2n ** 53n}`, 2n ** 256n - 1n]) {
    assert.throws(() => safeNumber(value), /overflow/);
  }
  const trust = trustFor([requestEntry]);
  for (const depth of [0, 5, 7, 255, 256]) {
    assert.throws(() => checkpointInfo({ ...trust, depth }), /INVALID_DEPTH/);
  }
  assert.throws(() => checkpointInfo({ ...trust, checkpoint: { ...trust.checkpoint, size: 65n } }), /INVALID_CHECKPOINT_SIZE/);
  assert.throws(() => checkpointInfo({ ...trust, checkpoint: { ...trust.checkpoint, root: '0xab' } }), /INVALID_HASH/);
  assert.equal(checkpointInfo({ ...trust, checkpoint: { ...trust.checkpoint, size: 64n } }).checkpoint.size, 64n);
});

test('checkpoint metadata normalizes JSON and hash representations without evaluating policy', () => {
  const trust = trustFor([requestEntry, decisionEntry]);
  const info = checkpointInfo(trust);
  assert.deepEqual(checkpointInfo({ ...disk(trust), policy: { deliberately: 'not a policy' } }), info);
  const upperHash = value => `0x${value.slice(2).toUpperCase()}`;
  assert.deepEqual(checkpointInfo({ ...disk(trust), checkpoint: { ...disk(info.checkpoint), root: upperHash(info.checkpoint.root) } }), info);
  assert.deepEqual(Object.keys(info), ['chainId', 'evidenceLogAddress', 'depth', 'checkpointId', 'checkpoint']);
});

test('complete log checks enforce contract order, actors, links and per-actor request uniqueness', async t => {
  const entries = [requestEntry, decisionEntry];
  const trust = trustFor(entries);
  const result = checkedLog(disk(entries), disk(trust));
  assert.deepEqual(result.entries, entries);
  assert.equal(result.tree.root, trust.checkpoint.root);
  assert.deepEqual(checkedLog([], trustFor([])).entries, []);
  assert.throws(() => checkedLog(null, trust), /LOG_SIZE_MISMATCH/);
  assert.throws(() => checkedLog(entries.slice(0, 1), trust), /LOG_SIZE_MISMATCH/);
  assert.throws(() => checkedLog([...entries].reverse(), trust), /INVALID_LOG_ORDER/);
  assert.throws(() => checkedLog([requestEntry, requestEntry], trust), /INVALID_LOG_ORDER/);
  assert.throws(() => checkedLog(entries, { ...trust, checkpoint: { ...trust.checkpoint, root: digest('bad root') } }), /LOG_ROOT_MISMATCH/);
  for (const [name, list, error] of [
    ['kind', [{ ...requestEntry, kind: 2n }], /INVALID_KIND/],
    ['zero payload', [{ ...requestEntry, payloadHash: ZeroHash }], /ZERO_PAYLOAD_HASH/],
    ['index beyond checkpoint size', [{ ...requestEntry, index: 1n, requestIndex: 1n }], /ENTRY_OUTSIDE_CHECKPOINT/],
    ['time after checkpoint issuance', [{ ...requestEntry, recordedAt: 2001n }], /ENTRY_OUTSIDE_CHECKPOINT/],
    ['request self link', [{ ...requestEntry, requestIndex: 1n }], /REQUEST_LINK_MISMATCH/],
    ['decision actor', [requestEntry, { ...decisionEntry, actor: OTHER }], /ACTOR_MISMATCH/],
    ['decision forward link', [requestEntry, { ...decisionEntry, requestIndex: 1n }], /REQUEST_LINK_MISMATCH/],
    ['time order', [requestEntry, { ...decisionEntry, recordedAt: 1000n }], /INVALID_LOG_ORDER/],
    ['duplicate request hash', [requestEntry, { ...requestEntry, index: 1n, requestIndex: 1n }], /DUPLICATE_REQUEST_HASH/],
    ['duplicate decision', [...entries, { ...decisionEntry, index: 2n }], /INVALID_DECISION_LINK/],
    ['decision links to decision', [...entries, { ...decisionEntry, index: 2n, requestIndex: 1n }], /INVALID_DECISION_LINK/],
  ]) {
    await t.test(name, () => assert.throws(() => checkedLog(list, trustFor(list)), error));
  }
  const otherCustomer = [...entries, { ...requestEntry, index: 2n, requestIndex: 2n, actor: OTHER, recordedAt: 1012n }];
  assert.equal(checkedLog(otherCustomer, trustFor(otherCustomer)).entries.length, 3);
});

test('inclusion verification returns normalized raw entries and rejects checkpoint, actor, metadata and proof tampering', () => {
  const entries = [requestEntry, decisionEntry];
  const trust = trustFor(entries);
  const checkpointId = trust.checkpointId;
  const tree = buildTree(entries, context);
  const item = { entry: requestEntry, proof: tree.proof(0) };
  const decision = { entry: decisionEntry, proof: tree.proof(1) };
  const verified = verifyInclusions(disk([item, decision]), checkpointId.toString(), disk(trust));
  assert.deepEqual(verified.entries, entries);
  assert.deepEqual(verified.checkpointInfo, checkpointInfo(trust));
  for (const change of [
    item => { item.entry.actor = OTHER; }, item => { item.entry.recordedAt = 1010n; },
    item => { item.entry.payloadHash = digest('altered'); }, item => { item.proof.pop(); },
    item => { item.proof.push(ZeroHash); }, item => { item.proof.reverse(); },
    item => { item.proof[0] = digest('altered proof'); }, item => { item.proof[0] = '0xab'; },
  ]) {
    const tampered = structuredClone(item);
    change(tampered);
    assert.throws(() => verifyInclusions([tampered, decision], checkpointId, trust));
  }
  assert.throws(() => verifyInclusions([item, { ...decision, proof: tree.proof(0) }], checkpointId, trust), /INVALID_INCLUSION_PROOF/);
  assert.throws(() => verifyInclusions([item], checkpointId + 1n, trust), /CHECKPOINT_MISMATCH/);
  for (const [change, error] of [
    [{ chainId: 1n }, /INVALID_INCLUSION_PROOF/],
    [{ evidenceLogAddress: OTHER }, /INVALID_INCLUSION_PROOF/],
    [{ depth: 4 }, /INVALID_DEPTH/],
    [{ checkpoint: { ...trust.checkpoint, root: digest('forged root') } }, /INVALID_INCLUSION_PROOF/],
    [{ checkpoint: { ...trust.checkpoint, size: 1n } }, /ENTRY_OUTSIDE_CHECKPOINT/],
    [{ checkpoint: { ...trust.checkpoint, issuedAt: 0n } }, /ENTRY_OUTSIDE_CHECKPOINT/],
  ]) {
    assert.throws(() => verifyInclusions([item, decision], checkpointId, { ...trust, ...change }), error);
  }
  assert.throws(() => verifyInclusions([item], checkpointId, { ...trust, customerAddress: OTHER }), /ACTOR_MISMATCH/);
  assert.throws(
    () => verifyInclusions([decision], checkpointId, { ...trust, institutionAddress: OTHER }),
    /ACTOR_MISMATCH/
  );
  const other = [{ ...requestEntry, actor: OTHER }];
  const otherTrust = trustFor(other);
  assert.equal(checkedLog(other, otherTrust).entries.length, 1);
  assert.throws(() => verifyInclusions([{ entry: other[0], proof: buildTree(other, context).proof(0) }], otherTrust.checkpointId, otherTrust), /ACTOR_MISMATCH/);
  const singleTrust = trustFor([requestEntry]);
  const proof = buildTree([requestEntry], singleTrust).proof(0);
  assert.deepEqual(verifyInclusions([{ entry: requestEntry, proof }], singleTrust.checkpointId, singleTrust).entries, [requestEntry]);
});

test('broadcast lookup failures recover the submitted hash without resending or reusing a previous hash', async () => {
  const f = fixture();
  const contract = f.evidenceLog.connect(f.institutionSigner);
  const register = contract.registerDecision;
  let sentHash;
  contract.registerDecision = async (...args) => {
    const tx = await register.apply(contract, args);
    sentHash = tx.hash;
    throw Object.assign(new Error('POST_SEND_LOOKUP_FAILED'), {
      code: 'NETWORK_ERROR', info: { sendTransactionHash: tx.hash }, txHash: f.receipt.hash,
    });
  };
  f.evidenceLog.connect = () => contract;
  const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
  await assert.rejects(witness.registerDecision(0n, '0xabcd'), error => {
    assert.equal(error.message, 'POST_SEND_LOOKUP_FAILED');
    assert.equal(error.txHash, sentHash);
    assert.notEqual(error.txHash, f.receipt.hash);
    assert.equal(error.registrationStatus, 'UNKNOWN');
    return true;
  });
  assert.equal(f.calls.length, 1);
  assert.deepEqual((await readRecord(contract, sentHash, f.trust)).entry, decisionEntry);
  assert.equal(f.calls.length, 1);
});

test('wait and receipt lookup failures preserve the actual transaction hash', async t => {
  for (const stage of ['wait', 'receipt']) {
    await t.test(stage, async () => {
      const f = fixture();
      const register = f.evidenceLog.createCheckpoint;
      let sentHash;
      f.evidenceLog.createCheckpoint = async () => {
        const tx = await register();
        sentHash = tx.hash;
        if (stage === 'wait') tx.wait = async () => { throw Object.assign(new Error('WAIT_FAILED'), { txHash: f.receipt.hash }); };
        return tx;
      };
      if (stage === 'receipt') f.provider.getTransactionReceipt = async () => { throw new Error('RECEIPT_LOOKUP_FAILED'); };
      const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
      await assert.rejects(witness.checkpoint(), error => {
        assert.equal(error.txHash, sentHash);
        assert.equal(error.registrationStatus, 'UNKNOWN');
        return true;
      });
      assert.equal(f.calls.length, 1);
    });
  }
});

test('only a matching failed receipt in the current block is FAILED', async t => {
  for (const scenario of ['confirmed', 'wrong hash', 'orphaned', 'lookup failed', 'missing block', 'success status', 'no receipt', 'ethers wait']) {
    await t.test(scenario, async () => {
      const f = fixture();
      const txHash = digest('submitted transaction');
      const receipt = { hash: txHash, status: 0, blockNumber: 12, blockHash: digest('failure block'), logs: [] };
      f.provider.getBlock = async () => {
        if (scenario === 'lookup failed') throw new Error('BLOCK_LOOKUP_FAILED');
        if (scenario === 'missing block') return null;
        return { hash: scenario === 'orphaned' ? digest('replacement block') : receipt.blockHash };
      };
      let calls = 0;
      f.evidenceLog.createCheckpoint = async () => {
        calls++;
        if (scenario === 'ethers wait') {
          return new TransactionResponse(
            { hash: txHash, from: CUSTOMER, to: EVIDENCE_LOG },
            { ...f.provider, getTransactionReceipt: async () => receipt }
          );
        }
        return { hash: txHash, wait: async () => {
          throw Object.assign(new Error('REVERTED'), {
            code: 'CALL_EXCEPTION', action: 'sendTransaction',
            receipt: scenario === 'no receipt' ? undefined : {
              ...receipt, hash: scenario === 'wrong hash' ? f.receipt.hash : txHash,
              status: scenario === 'success status' ? 1 : 0,
            },
          });
        } };
      };
      const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
      await assert.rejects(witness.checkpoint(), error => {
        assert.equal(error.txHash, txHash);
        assert.equal(error.registrationStatus, ['confirmed', 'ethers wait'].includes(scenario) ? 'FAILED' : 'UNKNOWN');
        if (scenario === 'ethers wait') {
          assert.equal(error.code, 'CALL_EXCEPTION');
          assert.equal(error.receipt, receipt);
        }
        return true;
      });
      assert.equal(calls, 1);
    });
  }
});

test('unknown no-hash sends stay UNKNOWN; only reliable preflight failures are NOT_SENT', async t => {
  for (const [name, details, status] of [
    ['lost response', { code: 'NETWORK_ERROR' }, 'UNKNOWN'],
    ['unclassified', {}, 'UNKNOWN'],
    ['unrelated previous hash', { code: 'NETWORK_ERROR', txHash: digest('previous') }, 'UNKNOWN'],
    ['send exception', { code: 'CALL_EXCEPTION', action: 'sendTransaction' }, 'UNKNOWN'],
    ['estimate rejection', { code: 'CALL_EXCEPTION', action: 'estimateGas' }, 'NOT_SENT'],
    ['insufficient funds', { code: 'INSUFFICIENT_FUNDS' }, 'NOT_SENT'],
    ['user rejection', { code: 'ACTION_REJECTED' }, 'NOT_SENT'],
  ]) {
    await t.test(name, async () => {
      const f = fixture();
      let sends = 0;
      f.evidenceLog.registerRequest = async () => {
        sends++;
        throw Object.assign(new Error('SEND_FAILED'), details);
      };
      const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
      await assert.rejects(witness.registerRequest(payloadBytes), error => {
        assert.equal(error.txHash, undefined);
        assert.equal(error.registrationStatus, status);
        return true;
      });
      assert.equal(sends, 1);
    });
  }
  for (const details of [
    { code: 'CALL_EXCEPTION', action: 'estimateGas' }, { code: 'INSUFFICIENT_FUNDS' }, { code: 'ACTION_REJECTED' },
  ]) {
    const f = fixture();
    const txHash = digest('known send');
    f.evidenceLog.registerRequest = async () => {
      throw Object.assign(new Error('POST_SEND_ERROR'), details, { info: { sendTransactionHash: txHash } });
    };
    const witness = await createEvmWitness({ ...f, deploymentBlock: 10n });
    await assert.rejects(witness.registerRequest(payloadBytes), error => {
      assert.equal(error.txHash, txHash);
      assert.equal(error.registrationStatus, 'UNKNOWN');
      return true;
    });
  }
});

test('factory checks the connection once, then routes registration and reads without rechecking it', async () => {
  const f = fixture({ seeded: false });
  const witness = await createEvmWitness({ evidenceLog: f.evidenceLog, institutionSigner: f.institutionSigner, deploymentBlock: '10' });
  assert.deepEqual(witness.context, context);
  assert.equal(f.calls.length, 0);
  f.provider.getNetwork = async () => assert.fail('UNEXPECTED_NETWORK_RECHECK');
  f.evidenceLog.getAddress = async () => assert.fail('UNEXPECTED_CONTRACT_RECHECK');
  const request = await witness.registerRequest(payloadBytes);
  const decision = await witness.registerDecision(0n, '0xabcd');
  assert.deepEqual(request.entry, requestEntry);
  assert.deepEqual(decision.entry, decisionEntry);
  assert.equal(f.evidenceLog.runner, f.customerSigner);
  assert.deepEqual(await witness.readRecord(decision.txHash), decision);
  const a = await witness.checkpoint();
  const b = await witness.checkpoint();
  assert.equal(b.checkpointId, a.checkpointId + 1n);
  assert.equal(b.checkpoint.root, a.checkpoint.root);
  assert.deepEqual(f.calls.map(call => call[0]), ['registerRequest', 'registerDecision', 'createCheckpoint', 'createCheckpoint']);
  witness.close();
  assert.deepEqual(await witness.readRecord(request.txHash), request);
});

test('factory checks signer and chain correspondence and propagates setup errors', async t => {
  for (const [name, change, error] of [
    ['institution mismatch', f => { f.evidenceLog.institution = async () => OTHER; }, /SIGNER_MISMATCH/],
    ['institution signer mismatch', f => { f.institutionSigner.getAddress = async () => OTHER; }, /SIGNER_MISMATCH/],
    ['missing institution signer', f => { f.institutionSigner = null; }, TypeError],
    ['provider-only customer', f => { f.evidenceLog.runner = f.provider; }, TypeError],
    ['invalid contract address', f => { f.evidenceLog.getAddress = async () => 'invalid'; }, /invalid address/],
    ['invalid institution address', f => { f.evidenceLog.institution = async () => 'invalid'; }, /invalid address/],
    ['negative chain', f => { f.provider.getNetwork = async () => ({ chainId: -1n }); }, /unsigned/],
    ['institution chain', f => { f.institutionSigner.provider = { getNetwork: async () => ({ chainId: 1n }) }; }, /CHAIN_MISMATCH/],
    ['connected contract address', f => { f.evidenceLog.connect = () => ({ ...f.evidenceLog, getAddress: async () => OTHER }); }, /CONTRACT_MISMATCH/],
  ]) {
    await t.test(name, async () => {
      const f = fixture();
      f.deploymentBlock = 10n;
      change(f);
      await assert.rejects(createEvmWitness(f), error);
      assert.equal(f.calls.length, 0);
    });
  }
  for (const depth of [0n, 5n, 7n, 255n]) {
    const f = fixture();
    f.evidenceLog.depth = async () => depth;
    await assert.rejects(createEvmWitness({ ...f, deploymentBlock: 10n }), /INVALID_DEPTH/);
    assert.equal(f.calls.length, 0);
  }
  const f = fixture();
  const customer = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';
  f.customerSigner.getAddress = async () => customer;
  assert.equal((await createEvmWitness({ ...f, deploymentBlock: 10n })).context.customerAddress, getAddress(customer));
});

test('deployment requires an explicit URL and valid depth before any provider work', async t => {
  t.mock.method(JsonRpcProvider.prototype, '_send', async () => assert.fail('NETWORK_FORBIDDEN'));
  t.mock.method(JsonRpcProvider.prototype, 'getSigner', async () => assert.fail('SIGNER_LOOKUP_FORBIDDEN'));
  for (const rpcUrl of [undefined, null, '', '   ']) await assert.rejects(deployEvmWitness({ rpcUrl }), /RPC_URL_REQUIRED/);
  await assert.rejects(deployEvmWitness(), /RPC_URL_REQUIRED/);
  for (const depth of [0, 5, 7, 255, 256]) {
    await assert.rejects(deployEvmWitness({ rpcUrl: 'http://offline.invalid', depth }), /INVALID_DEPTH/);
  }
  assert.equal(JsonRpcProvider.prototype.getSigner.mock.callCount(), 0);
});

test('deployment uses signer 0/1 and local artifact; owned provider closes on success and setup failure', async t => {
  for (const stage of ['success', 'signers', 'deploy', 'wait', 'unconfirmed', 'factory']) {
    await t.test(stage, async t => {
      const f = fixture({ seeded: false });
      const signers = [];
      let ownedProvider;
      let destroyed = 0;
      t.mock.method(JsonRpcProvider.prototype, '_send', async () => assert.fail('NETWORK_FORBIDDEN'));
      t.mock.method(JsonRpcProvider.prototype, 'getSigner', async function (index) {
        ownedProvider = this;
        signers.push(index);
        if (stage === 'signers') throw new Error('SETUP_FAILED');
        return index === 0 ? f.customerSigner : f.institutionSigner;
      });
      const destroy = JsonRpcProvider.prototype.destroy;
      t.mock.method(JsonRpcProvider.prototype, 'destroy', function () {
        assert.equal(this, ownedProvider);
        destroyed++;
        return destroy.call(this);
      });
      t.mock.method(ContractFactory.prototype, 'deploy', async function (institution, depth) {
        assert.equal(institution, INSTITUTION);
        assert.equal(depth, 6);
        assert.equal(this.runner, f.customerSigner);
        assert.equal(this.interface.getEvent('EntryRecorded').topicHash, iface.getEvent('EntryRecorded').topicHash);
        assert.equal(this.bytecode, artifact.bytecode.object);
        if (stage === 'deploy') throw new Error('SETUP_FAILED');
        f.evidenceLog.depth = async () => 6n;
        f.evidenceLog.deploymentTransaction = () => ({ wait: async () => {
          if (stage === 'wait') throw new Error('SETUP_FAILED');
          if (stage === 'unconfirmed') return { ...f.deployment, status: null };
          return f.deployment;
        } });
        if (stage === 'factory') f.evidenceLog.institution = async () => OTHER;
        return f.evidenceLog;
      });
      if (stage === 'success') {
        const witness = await deployEvmWitness({ rpcUrl: 'http://offline.invalid' });
        assert.deepEqual(witness.context, { ...context, depth: 6 });
        assert.equal(destroyed, 0);
        witness.close();
        assert.equal(destroyed, 1);
      } else {
        await assert.rejects(
          deployEvmWitness({ rpcUrl: 'http://offline.invalid' }),
          stage === 'unconfirmed' ? /DEPLOYMENT_NOT_CONFIRMED/ : /SETUP_FAILED|SIGNER_MISMATCH/
        );
        assert.equal(destroyed, 1);
      }
      assert.deepEqual(signers, [0, 1]);
      assert.equal(JsonRpcProvider.prototype._send.mock.callCount(), 0);
    });
  }
});
