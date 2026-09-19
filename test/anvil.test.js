import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AbiCoder, Contract, ContractFactory, FetchRequest, JsonRpcProvider, ZeroHash,
  concat, getAddress, hexlify, keccak256, makeError, toUtf8Bytes,
} from 'ethers';
import {
  audit, canonical, createSystem, decodePayload, encodePayload, expectedDecision,
  hash, sign, verifyReceipt, verifySingle,
} from '../src/evidence.js';
import {
  buildTree, checkedLog, checkpointInfo, createEvmWitness, leafHash, payloadHash,
} from '../src/evm.js';

// Explicitly run with: node --test test/anvil.test.js
// Requires the installed Anvil/ethers and an already compiled EvidenceLog artifact.
// This file never installs dependencies, compiles contracts, or uses an external RPC.
const root = fileURLToPath(new URL('../', import.meta.url));
const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const artifactPath = fileURLToPath(new URL('../contracts/out/EvidenceLog.sol/EvidenceLog.json', import.meta.url));
const temporaryParent = tmpdir();
const gasLimit = 1_000_000n;
const json = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2);
const bytes = text => hexlify(toUtf8Bytes(text));
const clone = value => structuredClone(value);
const pairHash = (left, right) => keccak256(concat(left < right ? [left, right] : [right, left]));

async function bounded(promise, label, timeout = 10_000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`TIMEOUT: ${label}`)), timeout);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function rejected(action, pattern) {
  let caught;
  await assert.rejects(action, error => {
    caught = error;
    if (pattern) assert.match(error.message, pattern);
    return true;
  });
  return caught;
}

function refuses(action) {
  let result;
  try { result = action(); } catch { return; }
  assert.equal(result?.ok, false, 'invalid evidence must throw or return ok: false');
}

async function availablePort() {
  const server = createServer();
  try {
    await bounded(new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    }), 'reserve loopback port');
    return server.address().port;
  } finally {
    if (server.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

async function startAnvil(temp) {
  const port = await availablePort();
  const url = `http://127.0.0.1:${port}`;
  const child = spawn('anvil', [
    '--host', '127.0.0.1', '--port', String(port), '--chain-id', '31337',
    '--timestamp', '1900000000', '--silent',
  ], { cwd: temp, env: { ...process.env, TMPDIR: temp }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  let spawnError;
  const capture = chunk => { output = (output + chunk.toString()).slice(-16_384); };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);
  child.on('error', error => { spawnError = error; });
  const closed = new Promise(resolve => child.once('close', resolve));
  const alive = () => child.pid !== undefined && child.exitCode === null && child.signalCode === null;
  // Only this exact child is owned; never kill a process by port or process name.
  const exitCleanup = () => { if (alive()) child.kill('SIGKILL'); };
  process.once('exit', exitCleanup);
  let stopped = false;
  async function stop() {
    if (stopped) return;
    if (alive()) child.kill('SIGTERM');
    try {
      await bounded(closed, 'Anvil SIGTERM', 2_000);
    } catch {
      if (alive()) child.kill('SIGKILL');
      await bounded(closed, 'Anvil SIGKILL', 2_000);
    } finally {
      if (!alive()) {
        stopped = true;
        process.removeListener('exit', exitCleanup);
      }
    }
  }
  try {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      if (spawnError) throw spawnError;
      if (!alive()) throw new Error(`Anvil exited before readiness: ${output}`);
      try {
        const response = await fetch(url, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
          signal: AbortSignal.timeout(500),
        });
        const reply = await response.json();
        if (reply.result === '0x7a69') return { url, child, stop };
      } catch {
        // The only wall-clock backoff in the harness is bounded process readiness.
      }
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    throw new Error(`Anvil readiness timed out: ${output}`);
  } catch (error) {
    await stop();
    throw error;
  }
}

function signerWithSend(signer, send) {
  return new Proxy(signer, {
    get(target, property) {
      if (property === 'sendTransaction') return transaction => send(transaction, target);
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

function requestEnvelope(system, id, amount) {
  return sign('request', {
    version: 1, id, customer: 'demo-customer', institution: system.policy.institution,
    amount, currency: 'KRW', policyHash: hash(system.policy),
  }, system.keys.customer.privateKey);
}

function decisionEnvelope(system, request, overrides = {}) {
  const envelope = decodePayload(request.payloadBytes, request.record);
  return sign('decision', {
    version: 1, requestHash: hash(envelope), policyHash: hash(system.policy),
    ...expectedDecision(envelope.payload), ...overrides,
  }, system.keys.institution.privateKey);
}

// Adversarial registrations deliberately bypass createSystem's business checks.
// These entries still describe real mined EVM records, not invented trust anchors.
function view(registration, envelope) {
  const record = registration.entry;
  return {
    payloadBytes: encodePayload(envelope),
    record: clone(record), txHash: registration.txHash,
  };
}

function evidenceFrom(entries, trust, requestIndex, decisionIndex) {
  const tree = buildTree(entries.map(entry => entry.record), trust);
  const item = index => ({ entry: clone(entries[index]), proof: tree.proof(index) });
  return {
    checkpointId: trust.checkpointId, request: item(requestIndex),
    ...(decisionIndex === undefined ? {} : { decision: item(decisionIndex) }),
  };
}

// Independently compute the full padded tree to check the library-backed builder.
function referenceTree(entries, context) {
  const abi = AbiCoder.defaultAbiCoder();
  const leaves = entries.map(entry => keccak256(keccak256(abi.encode(
    ['uint256', 'address', 'uint256', 'uint8', 'address', 'uint256', 'bytes32', 'uint256'],
    [context.chainId, context.evidenceLogAddress, entry.index, entry.kind, entry.actor,
      entry.requestIndex, entry.payloadHash, entry.recordedAt],
  ))));
  let level = [...leaves, ...Array(2 ** Number(context.depth) - leaves.length).fill(ZeroHash)];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(pairHash(level[i], level[i + 1]));
    level = next;
  }
  return { root: level[0], leaves };
}

test('src API against a dedicated local Anvil, including offline CLI recovery', { timeout: 240_000, concurrency: false }, async t => {
  const temp = await mkdtemp(join(temporaryParent, 'trust404-anvil-'));
  let anvil;
  let provider;
  let cleanupPromise;
  function cleanup() {
    cleanupPromise ??= (async () => {
      provider?.destroy();
      try { await anvil?.stop(); } finally { await rm(temp, { recursive: true, force: true }); }
    })();
    return cleanupPromise;
  }
  // The test-runner hook also covers cancellation by the suite's timeout.
  t.after(cleanup);
  const offlineCases = [];
  let fatalError;
  const rpcTrace = [];
  let lastBroadcast;
  let lastBlockPoll;
  try {
    const artifact = JSON.parse(await readFile(artifactPath, 'utf8'));
    const bytecode = artifact.bytecode.object.startsWith('0x') ? artifact.bytecode.object : `0x${artifact.bytecode.object}`;
    assert.notEqual(bytecode, '0x', 'compile EvidenceLog offline before running this test');
    anvil = await startAnvil(temp);
    t.diagnostic(`Anvil: ${anvil.url} (PID ${anvil.child.pid})`);
    const connection = new FetchRequest(anvil.url);
    connection.timeout = 5_000;
    provider = new JsonRpcProvider(connection, 31337, {
      cacheTimeout: -1, batchMaxCount: 1, pollingInterval: 20, staticNetwork: true,
    });
    provider.on('debug', event => {
      if (event.action === 'sendRpcPayload') {
        for (const payload of [event.payload].flat()) {
          if (payload.method === 'eth_blockNumber') {
            lastBlockPoll = { id: payload.id, method: payload.method };
            continue;
          }
          rpcTrace.push({ id: payload.id, method: payload.method, params: payload.params });
        }
      } else if (event.action === 'receiveRpcResult') {
        for (const result of event.result) {
          if (result.id === lastBlockPoll?.id) lastBlockPoll.result = result.error ?? result.result;
          const request = rpcTrace.find(item => item.id === result.id);
          if (request) {
            request.result = result.error ?? result.result;
            if (request.method === 'eth_sendTransaction' && !result.error) lastBroadcast = result.result;
          }
        }
      }
      if (rpcTrace.length > 30) rpcTrace.splice(0, rpcTrace.length - 30);
    });
    // Automatic blocks advance one second irrespective of test-machine speed.
    await provider.send('anvil_setBlockTimestampInterval', [1]);
    const [customer, institution, outsider] = await Promise.all([0, 1, 2].map(index => provider.getSigner(index)));
    // ethers' block poller bootstraps without emitting its first observed block.
    // Keep it alive between serial sends: otherwise a newly mined block can be
    // mistaken for that baseline after the receipt subscriber just saw null.
    await provider.on('block', () => {});

    async function operation(label, action, timeout = 8_000) {
      if (fatalError) throw fatalError;
      try {
        return await bounded(Promise.resolve().then(action), label, timeout);
      } catch (error) {
        if (error.message.startsWith('TIMEOUT:') || error.code === 'TIMEOUT') {
          const trace = json({ lastBlockPoll, requests: rpcTrace });
          let receipt;
          try {
            receipt = lastBroadcast && await bounded(provider.send('eth_getTransactionReceipt', [lastBroadcast]), 'timeout receipt diagnosis', 1_000);
          } catch (diagnosticError) { receipt = diagnosticError.message; }
          fatalError = new Error(`${error.message}\nLast broadcast: ${lastBroadcast}\nReceipt: ${json(receipt)}\nRecent RPC: ${trace}`, { cause: error });
          // Promise.race cannot cancel the underlying ethers wait. Stop its actual
          // provider and chain, and do not start another scenario on that chain.
          provider.destroy();
          await anvil.stop();
          throw fatalError;
        }
        throw error;
      }
    }

    async function scenario(name, options, body) {
      if (fatalError) throw fatalError;
      await t.test(name, options, async subtest => {
        const abort = () => {
          fatalError ??= new Error(`SCENARIO_CANCELLED: ${name}`);
          provider?.destroy();
          void anvil.stop().catch(() => {});
        };
        subtest.signal.addEventListener('abort', abort, { once: true });
        try { await body(subtest); } finally { subtest.signal.removeEventListener('abort', abort); }
      });
      if (fatalError) throw fatalError;
    }

    async function save(name, value) {
      const path = join(temp, `${name}.json`);
      await writeFile(path, `${json(value)}\n`, { flag: 'wx' });
      return path;
    }

    async function offlineCase(name, command, value, trust, status, check) {
      const file = await save(`${name}-evidence`, value);
      const anchor = await save(`${name}-trust`, trust);
      offlineCases.push({ name, command, file, anchor, status, check });
    }

    async function fixture({ depth = 6, customerSigner = customer, institutionSigner = institution, systemOptions = {} } = {}) {
      const factory = new ContractFactory(artifact.abi, bytecode, customer);
      const deployed = await bounded(factory.deploy(await institution.getAddress(), depth, { gasLimit: 5_000_000n }), 'deploy EvidenceLog');
      const receipt = await bounded(deployed.deploymentTransaction().wait(), 'deployment receipt');
      assert.equal(receipt.status, 1);
      const address = await deployed.getAddress();
      const contract = new Contract(address, artifact.abi, customerSigner);
      const witness = await createEvmWitness({ evidenceLog: contract, institutionSigner, deploymentBlock: receipt.blockNumber });
      const system = createSystem({ witness, ...systemOptions });
      return {
        contract, witness, system, deploymentBlock: receipt.blockNumber,
        institutionLog: contract.connect(institution), outsiderLog: contract.connect(outsider),
      };
    }

    async function state(f) {
      const [size, rootHash, checkpoints, entries, publications] = await Promise.all([
        f.contract.size(), f.contract.root(), f.contract.checkpointCount(),
        f.contract.queryFilter(f.contract.filters.EntryRecorded(), f.deploymentBlock, 'latest'),
        f.contract.queryFilter(f.contract.filters.CheckpointPublished(), f.deploymentBlock, 'latest'),
      ]);
      return { size, root: rootHash, checkpoints, entries: entries.length, publications: publications.length };
    }

    async function minedFailure(f, send) {
      const before = await state(f);
      const transaction = await bounded(send(), 'broadcast intentionally reverting call');
      const error = await rejected(() => bounded(transaction.wait(), 'reverting receipt'));
      assert.equal(error.receipt?.status, 0, 'this must be an actual mined failure, not an estimate or injected error');
      const receipt = await provider.getTransactionReceipt(transaction.hash);
      assert.equal(receipt.status, 0);
      assert.equal(receipt.logs.length, 0);
      assert.deepEqual(await state(f), before, 'revert must roll back size/root/checkpoints/events');
      await assert.rejects(() => f.witness.readRecord(transaction.hash));
      return receipt;
    }

    async function metadata(entry, kind, actor) {
      const receipt = await provider.getTransactionReceipt(entry.txHash);
      const block = await provider.getBlock(receipt.blockNumber);
      assert.equal(receipt.status, 1);
      assert.deepEqual(Object.keys(entry).sort(), ['payloadBytes', 'record', 'txHash']);
      assert.equal(entry.record.recordedAt, BigInt(block.timestamp));
      for (const field of ['index', 'kind', 'requestIndex', 'recordedAt']) assert.equal(typeof entry.record[field], 'bigint');
      assert.equal(entry.record.kind, BigInt(kind));
      assert.equal(getAddress(entry.record.actor), getAddress(await actor.getAddress()));
      assert.equal(entry.record.payloadHash, payloadHash(entry.payloadBytes));
      assert.equal(payloadHash(entry.payloadBytes), keccak256(entry.payloadBytes));
      assert.equal(entry.payloadBytes, bytes(canonical(decodePayload(entry.payloadBytes, entry.record))));
      if (kind === 0) {
        assert.equal(entry.record.requestIndex, entry.record.index);
      }
    }

    function runCli(args, expected, online = false, timeout = 10_000) {
      const env = { ...process.env, TMPDIR: temp };
      delete env.RPC_URL;
      if (online) env.RPC_URL = anvil.url;
      const result = spawnSync(process.execPath, [cli, ...args], {
        cwd: root, env, encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024,
      });
      assert.ifError(result.error);
      assert.equal(result.signal, null, `CLI was killed: ${args.join(' ')}`);
      assert.equal(result.status, expected, `${args.join(' ')}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`);
      const output = result.stdout.trim() || result.stderr.trim();
      const value = JSON.parse(output);
      assert.equal(value.ok, expected === 0);
      return value;
    }

    await scenario('sequential source workflow, boundary amounts, pre-decision receipts and duplicate rejection', { timeout: 30_000 }, async () => {
      const f = await fixture();
      assert.equal(BigInt(f.witness.context.chainId), 31337n);
      assert.equal(getAddress(f.witness.context.evidenceLogAddress), getAddress(await f.contract.getAddress()));
      assert.equal(Number(f.witness.context.depth), 6);
      assert.equal(Number(f.witness.context.deploymentBlock), f.deploymentBlock);
      assert.equal(getAddress(f.witness.context.customerAddress), getAddress(await customer.getAddress()));
      assert.equal(getAddress(f.witness.context.institutionAddress), getAddress(await institution.getAddress()));
      await assert.rejects(() => createEvmWitness({
        evidenceLog: f.contract, institutionSigner: outsider, deploymentBlock: f.deploymentBlock,
      }));
      const order = [];
      let reads = 0;
      const witness = {
        ...f.witness,
        async registerRequest(payload) {
          assert.equal(order.at(-1).event, 'payload');
          assert.equal(order.at(-1).bytes, payload);
          const registration = await f.witness.registerRequest(payload);
          order.push({ event: 'mined', registration });
          return registration;
        },
        async registerDecision(index, payload) {
          assert.equal(order.at(-1).event, 'payload');
          assert.equal(order.at(-1).bytes, payload);
          const registration = await f.witness.registerDecision(index, payload);
          order.push({ event: 'mined', registration });
          return registration;
        },
        async readRecord(txHash) { reads++; return f.witness.readRecord(txHash); },
      };
      const system = createSystem({
        witness,
        onPayload(payload, envelope) {
          assert.equal(payload, encodePayload(envelope));
          order.push({ event: 'payload', bytes: payload });
        },
        onAppend(entries) {
          assert.equal(order.at(-1).event, 'mined');
          assert.equal(entries.at(-1).txHash, order.at(-1).registration.txHash);
          order.push({ event: 'stored' });
        },
      });
      assert.equal(system.then, undefined, 'createSystem is a synchronous factory');
      assert.equal(system.keys.witness, undefined);
      const pairs = [];
      let firstReceipt;
      let firstTrust;
      for (const [i, amount] of [999_999, 1_000_000, 1_000_001].entries()) {
        const request = await system.submit(`boundary-${amount}`, amount);
        assert.equal(request.record.index, BigInt(i * 2));
        await metadata(request, 0, customer);
        const trust = await system.trust(request.txHash);
        const receipt = system.bundle(request, undefined, trust);
        assert.equal(receipt.decision, undefined);
        assert.equal(verifyReceipt(receipt, trust).ok, true);
        // Actual files are persisted while the request still has no decision.
        const path = await save(`receipt-before-decision-${i}`, receipt);
        await save(`receipt-before-decision-trust-${i}`, trust);
        assert.equal((await f.contract.size()), BigInt(i * 2 + 1));
        assert.equal(verifyReceipt(JSON.parse(await readFile(path, 'utf8')), JSON.parse(json(trust))).ok, true);
        if (i === 0) { firstReceipt = receipt; firstTrust = trust; }
        for (const alteration of [
          { record: { ...request.record, index: request.record.index + 1n } },
          { payloadBytes: encodePayload(requestEnvelope(system, `boundary-${amount}`, amount + 10)) },
          { payloadBytes: bytes('{}') },
          { record: { ...request.record, recordedAt: request.record.recordedAt + 1n } },
        ]) {
          await assert.rejects(() => system.decide({ ...clone(request), ...alteration }));
        }
        const readsBefore = reads;
        const decision = await system.decide(request);
        await assert.rejects(() => system.decide(clone(request)), /DUPLICATE_DECISION/);
        assert(reads > readsBefore, 'the service must reread the actual request registration');
        assert.equal(await f.contract.size(), BigInt(i * 2 + 2));
        assert.equal(decision.record.index, BigInt(i * 2 + 1));
        assert.equal(decision.record.requestIndex, request.record.index);
        await metadata(decision, 1, institution);
        pairs.push({ request, decision });
      }
      const trust = await system.trust();
      for (const field of ['entry', 'txHash', 'blockNumber', 'blockHash', 'deploymentBlock']) {
        assert.equal(Object.hasOwn(trust, field), false);
      }
      assert.equal(trust.checkpoint.size, 6n);
      assert.equal(trust.customerKey.includes('PUBLIC KEY'), true);
      assert.equal(trust.institutionKey.includes('PUBLIC KEY'), true);
      for (const { request, decision } of pairs) {
        const bundle = system.bundle(request, decision, trust);
        const envelope = decodePayload(request.payloadBytes, request.record);
        assert.deepEqual(verifySingle(bundle, trust), {
          ok: true, requestId: envelope.payload.id, amount: envelope.payload.amount,
          ...expectedDecision(envelope.payload),
        });
        const changed = clone(bundle);
        envelope.payload.amount++;
        changed.request.entry.payloadBytes = encodePayload(envelope);
        assert.notEqual(changed.request.entry.payloadBytes, request.payloadBytes);
        refuses(() => verifySingle(changed, trust));
      }
      const report = audit(system.entries, trust);
      assert.equal(report.ok, true);
      assert.equal(report.requests, 3);
      assert.equal(report.decisions, 3);
      for (const field of ['pending', 'overdue']) assert.deepEqual(report[field], []);
      assert.equal(verifyReceipt(firstReceipt, firstTrust).ok, true, 'old receipt survives later appends');
      refuses(() => verifyReceipt(firstReceipt, trust));
      const size = await f.contract.size();
      for (const amount of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
        await assert.rejects(() => system.submit('invalid-amount', amount));
      }
      assert.equal(await f.contract.size(), size);
      const bundle = system.bundle(pairs[0].request, pairs[0].decision, trust);
      for (const mutate of [
        value => { value.request.proof.pop(); },
        value => { value.request.proof.push(ZeroHash); },
        value => { value.request.proof[0] = ZeroHash; },
        value => { value.checkpointId++; },
        value => { delete value.checkpointId; },
      ]) {
        const modified = clone(bundle);
        mutate(modified);
        refuses(() => verifySingle(modified, trust));
      }
      for (const mutate of [
        value => { value.chainId = 1n; },
        value => { value.evidenceLogAddress = outsider.address; },
        value => { value.depth++; },
        value => { value.checkpoint.size = 1n; },
        value => { value.checkpoint.issuedAt = 0n; },
        value => { value.checkpoint.root = ZeroHash; },
      ]) {
        const modified = clone(trust);
        mutate(modified);
        refuses(() => verifySingle(bundle, modified));
      }
      const missing = clone(bundle);
      missing.decision.entry.payloadBytes = null;
      await offlineCase('missing-single-payload', 'verify', missing, trust, 1);
      await offlineCase('old-receipt', 'receipt', firstReceipt, firstTrust, 0);
      await offlineCase('checkpoint-mismatch', 'receipt', firstReceipt, trust, 1);
    });

    await scenario('full-tree reference, all proofs, old checkpoints and real overcapacity at depth 6', { timeout: 60_000 }, async () => {
      const label = 'tree depth=6';
      const f = await operation(`${label} deploy`, () => fixture());
      const capacity = 64;
      const sizes = new Set([0, 1, 2, 3, 7, 8, 9, 17, 63, 64]);
      let registration = await operation(`${label} size=0 checkpoint`, () => f.witness.checkpoint());
      const entries = [];
      let old;
      for (let size = 0; size <= capacity; size++) {
        if (size) {
          registration = await operation(`${label} size=${size} append request`, () => f.witness.registerRequest(bytes(`depth-6-request-${size}`)));
          entries.push(registration.entry);
        }
        if (!sizes.has(size)) continue;
        const trust = { ...f.witness.context, ...registration };
        assert.equal(entries.length, size);
        const tree = buildTree(entries, trust);
        const reference = referenceTree(entries, trust);
        assert.equal(tree.root, reference.root);
        assert.equal(tree.root, await operation(`${label} size=${size} read root`, () => f.contract.root()));
        assert.equal(tree.root, registration.checkpoint.root);
        assert.equal(registration.checkpoint.size, BigInt(size));
        assert.equal(checkedLog(entries, trust).tree.root, tree.root);
        for (let index = 0; index < size; index++) {
          const proof = tree.proof(index);
          assert.equal(proof.length, 6);
          assert.equal(leafHash(entries[index], trust), reference.leaves[index]);
          assert.equal(proof.reduce(pairHash, reference.leaves[index]), reference.root);
        }
        assert.throws(() => tree.proof(size));
        assert.throws(() => tree.proof(-1));
        if (size === 3) old = { trust: clone(trust), entries: clone(entries), proof: clone(tree.proof(0)) };
      }
      const oldCheckpointInfo = clone(checkpointInfo(old.trust));
      assert.deepEqual(entries.slice(0, Number(old.trust.checkpoint.size)), old.entries);
      assert.deepEqual(buildTree(old.entries, old.trust).proof(0), old.proof);
      const stored = await operation(`${label} read old checkpoint`, () => f.contract.getCheckpoint(old.trust.checkpointId));
      assert.equal(stored.root, old.trust.checkpoint.root);
      assert.equal(stored.size, old.trust.checkpoint.size);
      assert.equal(stored.issuedAt, old.trust.checkpoint.issuedAt);
      await operation(`${label} overcapacity request`, () => minedFailure(f, () => f.contract.registerRequest(payloadHash(bytes('overflow')), { gasLimit })));
      await operation(`${label} overcapacity decision`, () => minedFailure(f, () => f.institutionLog.registerDecision(0, payloadHash(bytes('overflow-decision')), { gasLimit })));
      assert.throws(() => buildTree([...entries, entries[0]], f.witness.context));
      const checkpoint = await operation(`${label} full checkpoint`, () => f.witness.checkpoint());
      assert.equal(checkpoint.checkpoint.size, BigInt(capacity));
      assert.equal(checkpoint.checkpoint.root, registration.checkpoint.root);
      assert.deepEqual(checkpointInfo(old.trust), oldCheckpointInfo);
    });

    await scenario('59 pending, 60 overdue, and later decisions without real waits', { timeout: 20_000 }, async () => {
      const f = await fixture();
      const request = await f.system.submit('unanswered', 1_500_000);
      const acceptedAt = Number(request.record.recordedAt);
      const deadline = acceptedAt + f.system.policy.decisionWindow;
      await provider.send('evm_setNextBlockTimestamp', [acceptedAt + 59]);
      const before = await f.system.trust();
      const pending = audit(f.system.entries, before);
      assert.equal(Number(before.checkpoint.issuedAt), acceptedAt + 59);
      assert.equal(pending.ok, true);
      assert.deepEqual(pending.pending, ['unanswered']);
      assert.deepEqual(pending.overdue, []);
      await provider.send('evm_setNextBlockTimestamp', [deadline]);
      const due = await f.system.trust();
      const overdue = audit(f.system.entries, due);
      assert.equal(Number(due.checkpoint.issuedAt), deadline);
      assert.equal(overdue.ok, false);
      assert.deepEqual(overdue.overdue, ['unanswered']);
      assert.deepEqual(overdue.pending, []);
      assert.equal(audit(f.system.entries, before).ok, true, 'later time does not change an earlier checkpoint');
      await offlineCase('overdue', 'audit', f.system.entries, due, 1, report => assert.deepEqual(report.overdue, ['unanswered']));
      await offlineCase('pending', 'audit', f.system.entries, before, 0);
      for (const elapsed of [60, 61]) {
        const g = await fixture();
        const r = await g.system.submit(`elapsed-${elapsed}`, 1_000_001);
        await provider.send('evm_setNextBlockTimestamp', [Number(r.record.recordedAt) + elapsed]);
        const d = await g.system.decide(r);
        assert.equal(d.record.recordedAt, r.record.recordedAt + BigInt(elapsed));
        const trust = await g.system.trust(d.txHash);
        const bundle = g.system.bundle(r, d, trust);
        const verified = verifySingle(bundle, trust);
        assert.equal(verified.ok, true);
        const report = audit(g.system.entries, trust);
        assert.equal(report.ok, true);
        assert.deepEqual(report.overdue, []);
        await offlineCase(`timing-${elapsed}`, 'verify', bundle, trust, 0);
        if (elapsed === 61) await offlineCase('later-decision-audit', 'audit', g.system.entries, trust, 0);
      }
    });

    await scenario('same-block checkpoints precede a decision by sender nonce and preserve checkpoint cutoff', { timeout: 20_000 }, async () => {
      const f = await fixture();
      const request = await f.system.submit('same-block', 123);
      const deadline = Number(request.record.recordedAt) + f.system.policy.decisionWindow;
      const envelope = decisionEnvelope(f.system, request);
      const nonce = await institution.getNonce('pending');
      let first;
      let second;
      let decisionTx;
      await provider.send('evm_setAutomine', [false]);
      try {
        // Await only broadcasts here. Waiting for a receipt before evm_mine deadlocks.
        first = await bounded(f.institutionLog.createCheckpoint({ nonce, gasLimit }), 'first pending checkpoint');
        second = await bounded(f.institutionLog.createCheckpoint({ nonce: nonce + 1, gasLimit }), 'second pending checkpoint');
        decisionTx = await bounded(f.institutionLog.registerDecision(request.record.index, payloadHash(encodePayload(envelope)), {
          nonce: nonce + 2, gasLimit,
        }), 'pending decision');
        assert.equal(await provider.getTransactionReceipt(decisionTx.hash), null);
        await provider.send('evm_setNextBlockTimestamp', [deadline]);
        await provider.send('evm_mine', []);
      } finally {
        await provider.send('evm_setAutomine', [true]);
      }
      const receipts = await bounded(Promise.all([first, second, decisionTx].map(tx => tx.wait())), 'same-block receipts');
      assert(receipts.every(receipt => receipt.status === 1 && receipt.blockHash === receipts[0].blockHash));
      assert(receipts[0].index < receipts[1].index && receipts[1].index < receipts[2].index);
      const early = await f.system.trust(first.hash);
      const earlyRegistration = await f.witness.readRecord(first.hash);
      const earlyEntries = clone(f.system.entries);
      const earlyReceipt = f.system.bundle(request, undefined, early);
      const other = await f.system.trust(second.hash);
      assert.deepEqual(early.checkpoint, other.checkpoint);
      assert.notEqual(early.checkpointId, other.checkpointId);
      refuses(() => verifyReceipt(earlyReceipt, other));
      const final = await f.system.trust(decisionTx.hash);
      const finalRegistration = await f.witness.readRecord(decisionTx.hash);
      assert.equal(finalRegistration.blockHash, earlyRegistration.blockHash);
      assert.equal(final.checkpoint.issuedAt, early.checkpoint.issuedAt);
      assert.equal(Number(early.checkpoint.issuedAt), deadline);
      assert.equal(early.checkpoint.size, 1n);
      assert.equal(final.checkpoint.size, 2n);
      assert.equal(finalRegistration.entry.requestIndex, request.record.index);
      const decision = view(finalRegistration, envelope);
      const entries = [...f.system.entries, decision];
      const before = audit(earlyEntries, early);
      assert.equal(before.ok, false);
      assert.deepEqual(before.overdue, ['same-block']);
      const after = audit(entries, final);
      assert.equal(after.ok, true);
      assert.equal(verifySingle(evidenceFrom(entries, final, request.record.index, decision.record.index), final).ok, true);
      assert.equal(verifyReceipt(earlyReceipt, early).ok, true);
      f.system.entries.push(decision);
      await f.system.trust(first.hash);
      assert.equal(f.system.entries.length, 2, 'reading an old checkpoint must not replace the local log');
      refuses(() => audit(entries, early));
    });

    await scenario('real unauthorized, duplicate, zero-hash and invalid-link reverts leave all state and events unchanged', { timeout: 25_000 }, async () => {
      const f = await fixture();
      await assert.rejects(() => f.contract.getCheckpoint(999));
      const request = await f.system.submit('reverts', 10);
      const someHash = payloadHash(bytes('decision'));
      await minedFailure(f, () => f.outsiderLog.registerDecision(request.record.index, someHash, { gasLimit }));
      await minedFailure(f, () => f.contract.registerRequest(request.record.payloadHash, { gasLimit }));
      await minedFailure(f, () => f.contract.registerRequest(ZeroHash, { gasLimit }));
      await minedFailure(f, () => f.institutionLog.registerDecision(request.record.index, ZeroHash, { gasLimit }));
      await minedFailure(f, () => f.institutionLog.registerDecision(999, someHash, { gasLimit }));
      const decision = await f.system.decide(request);
      await minedFailure(f, () => f.institutionLog.registerDecision(request.record.index, someHash, { gasLimit }));
      await minedFailure(f, () => f.institutionLog.registerDecision(decision.record.index, someHash, { gasLimit }));
      const trust = await f.system.trust();
      assert.equal(audit(f.system.entries, trust).ok, true);
    });

    await scenario('another account cannot reserve a customer hash, and foreign entries cannot disappear from audit', { timeout: 15_000 }, async () => {
      const f = await fixture();
      const envelope = requestEnvelope(f.system, 'shared-hash', 500);
      const foreignTx = await f.outsiderLog.registerRequest(payloadHash(encodePayload(envelope)), { gasLimit });
      await bounded(foreignTx.wait(), 'foreign request receipt');
      const foreign = view(await f.witness.readRecord(foreignTx.hash), envelope);
      await assert.rejects(() => f.system.decide(foreign));
      const owner = await f.system.submit('shared-hash', 500);
      assert.equal(owner.record.payloadHash, foreign.record.payloadHash);
      assert.equal(owner.record.index, 1n);
      assert.notEqual(owner.record.actor, foreign.record.actor);
      const decision = await f.system.decide(owner);
      const trust = await f.system.trust(decision.txHash);
      assert.deepEqual(f.system.entries, [owner, decision]);
      assert.throws(() => audit(f.system.entries, trust), /LOG_SIZE_MISMATCH/);
      assert.throws(() => f.system.bundle(owner, decision, trust), /LOG_SIZE_MISMATCH/);
      const entries = [foreign, owner, decision];
      assert.throws(() => audit(entries, trust), /ACTOR_MISMATCH/);
      assert.equal(verifySingle(evidenceFrom(entries, trust, owner.record.index, decision.record.index), trust).ok, true);
      refuses(() => audit([...entries.slice(1), entries[0]], trust));
      await offlineCase('foreign-audit', 'audit', entries, trust, 1);
    });

    await scenario('a different registration with the same business ID is refused by the service and audit', { timeout: 15_000 }, async () => {
      const f = await fixture();
      const first = await f.system.submit('duplicate-id', 100);
      await f.system.decide(first);
      const envelope = requestEnvelope(f.system, 'duplicate-id', 101);
      const registration = await f.witness.registerRequest(encodePayload(envelope));
      const other = view(registration, envelope);
      assert.notEqual(first.record.payloadHash, other.record.payloadHash);
      await assert.rejects(() => f.system.decide(other));
      assert.equal(await f.contract.size(), 3n);
      const trust = await f.system.trust(registration.txHash);
      assert.throws(() => audit([...f.system.entries, other], trust), /DUPLICATE_REQUEST/);
    });

    await scenario('registered false institutional decisions and missing originals remain visible but invalid', { timeout: 15_000 }, async () => {
      const f = await fixture();
      const request = await f.system.submit('false-approval', 1_500_000);
      const envelope = decisionEnvelope(f.system, request, { outcome: 'APPROVED', reason: 'WITHIN_LIMIT' });
      const registration = await f.witness.registerDecision(request.record.index, encodePayload(envelope));
      const trust = await f.system.trust(registration.txHash);
      assert.equal(registration.entry.kind, 1n);
      assert.equal(registration.entry.actor, await institution.getAddress());
      assert.equal(f.system.entries.length, 1);
      assert.throws(() => audit(f.system.entries, trust), /LOG_SIZE_MISMATCH/);
      const decision = view(registration, envelope);
      const entries = [...f.system.entries, decision];
      const missingPayload = clone(entries);
      missingPayload[1].payloadBytes = null;
      assert.throws(() => audit(missingPayload, trust), /MISSING_PAYLOAD/);
      await offlineCase('missing-audit-payload', 'audit', missingPayload, trust, 1);
      const bundle = evidenceFrom(entries, trust, request.record.index, decision.record.index);
      assert.deepEqual(decodePayload(decision.payloadBytes, decision.record), envelope);
      refuses(() => verifySingle(bundle, trust));
      assert.throws(() => audit(entries, trust), /POLICY_MISMATCH/);
      await assert.rejects(() => f.system.decide(request));
      assert.equal(await f.contract.size(), 2n);
      const noRequest = clone(entries);
      noRequest[0].payloadBytes = null;
      assert.throws(() => audit(noRequest, trust), /MISSING_PAYLOAD/);
      await offlineCase('false-signed-decision', 'verify', bundle, trust, 1);
      await offlineCase('false-signed-audit', 'audit', entries, trust, 1);
    });

    await scenario('actually registered malformed envelopes, schema and signatures are refused before service', { timeout: 15_000 }, async () => {
      const f = await fixture();
      const originals = [];
      for (const variant of ['envelope', 'schema', 'signature']) {
        const valid = requestEnvelope(f.system, `invalid-${variant}`, 10);
        const envelope = variant === 'envelope' ? { ...valid, extra: true }
          : variant === 'schema' ? sign('request', { ...valid.payload, extra: true }, f.system.keys.customer.privateKey)
            : sign('request', valid.payload, f.system.keys.institution.privateKey);
        const registration = await f.witness.registerRequest(encodePayload(envelope));
        const request = view(registration, envelope);
        originals.push(request);
        await assert.rejects(() => f.system.decide(request));
        assert.equal(await f.contract.size(), BigInt(originals.length));
        const trust = await f.system.trust(registration.txHash);
        const entries = clone(originals);
        const bundle = evidenceFrom(entries, trust, request.record.index);
        refuses(() => verifyReceipt(bundle, trust));
        assert.throws(() => audit(entries, trust));
        if (variant === 'envelope') {
          assert.throws(() => decodePayload(request.payloadBytes, request.record));
          await offlineCase('invalid-envelope', 'receipt', bundle, trust, 1);
        }
      }
    });

    await scenario('pending transactions and snapshot-orphaned records are refused by online reads', { timeout: 20_000 }, async () => {
      const f = await fixture();
      const envelope = requestEnvelope(f.system, 'pending-registration', 1);
      let transaction;
      await provider.send('evm_setAutomine', [false]);
      try {
        transaction = await bounded(f.contract.registerRequest(payloadHash(encodePayload(envelope)), { gasLimit }), 'pending request broadcast');
        assert.equal(await provider.getTransactionReceipt(transaction.hash), null);
        await assert.rejects(() => f.witness.readRecord(transaction.hash));
        const block = await provider.getBlock('latest');
        const pendingView = view({ txHash: transaction.hash, entry: {
          index: 0n, kind: 0n, requestIndex: 0n, actor: await customer.getAddress(),
          payloadHash: payloadHash(encodePayload(envelope)), recordedAt: BigInt(block.timestamp + 1),
        } }, envelope);
        await assert.rejects(() => f.system.decide(pendingView));
        assert.equal(await f.contract.size(), 0n);
      } finally {
        // Drain the owned pending transaction before restoring automatic mining.
        await provider.send('evm_mine', []);
        await provider.send('evm_setAutomine', [true]);
      }
      assert.equal((await bounded(transaction.wait(), 'formerly pending receipt')).status, 1);
      assert.equal((await f.witness.readRecord(transaction.hash)).entry.index, 0n);
      const g = await fixture();
      const snapshot = await provider.send('evm_snapshot', []);
      const request = await g.system.submit('orphaned', 2);
      const trust = await g.system.trust(request.txHash);
      const receipt = g.system.bundle(request, undefined, trust);
      assert.equal(verifyReceipt(receipt, trust).ok, true);
      assert.equal(await provider.send('evm_revert', [snapshot]), true);
      await provider.send('evm_mine', []);
      await assert.rejects(() => g.witness.readRecord(request.txHash));
      await assert.rejects(() => g.system.decide(request));
      assert.equal(await g.contract.size(), 0n);
      // Offline proof checking cannot discover a reorg of a previously trusted anchor.
      assert.equal(verifyReceipt(receipt, trust).ok, true);
    });

    await scenario('repeated decisions are rejected after reorganization without reusing old acknowledgements', { timeout: 20_000 }, async () => {
      const f = await fixture();
      const request = await f.system.submit('cached-decision', 1);
      const beforeDecision = await provider.send('evm_snapshot', []);
      const decision = await f.system.decide(request);
      assert.equal(await f.contract.size(), 2n);
      assert.equal(await provider.send('evm_revert', [beforeDecision]), true);
      assert.equal(await provider.getTransactionReceipt(decision.txHash), null);
      await assert.rejects(() => f.system.decide(request), /DUPLICATE_DECISION/);
      assert.equal(await f.contract.size(), 1n, 'a locally recorded decision is not automatically resubmitted');

      const g = await fixture();
      const beforeRequest = await provider.send('evm_snapshot', []);
      const original = await g.system.submit('replaced-request', 10);
      await g.system.decide(original);
      assert.equal(await provider.send('evm_revert', [beforeRequest]), true);
      const envelope = requestEnvelope(g.system, 'replaced-request', 20);
      const replacement = view(await g.witness.registerRequest(encodePayload(envelope)), envelope);
      assert.equal(replacement.record.index, original.record.index);
      assert.notEqual(replacement.record.payloadHash, original.record.payloadHash);
      await assert.rejects(() => g.system.decide(replacement), /DUPLICATE_DECISION/);
      assert.equal(await g.contract.size(), 1n);
    });

    await scenario('actual mined low-gas failures permit corrected retries through createSystem', { timeout: 20_000 }, async () => {
      const controls = { customer: { low: true, sends: 0 }, institution: { low: true, sends: 0 } };
      const controlled = (signer, control) => signerWithSend(signer, (transaction, target) => {
        control.sends++;
        return target.sendTransaction(control.low ? { ...transaction, gasLimit: 30_000n } : transaction);
      });
      const f = await fixture({
        customerSigner: controlled(customer, controls.customer), institutionSigner: controlled(institution, controls.institution),
      });
      const before = await state(f);
      const error = await rejected(() => f.system.submit('gas-retry', 100));
      assert.match(error.txHash, /^0x[0-9a-f]{64}$/i);
      const receipt = await provider.getTransactionReceipt(error.txHash);
      assert.equal(receipt.status, 0, 'gas injection changes a real broadcast, not the reported receipt');
      assert.equal(receipt.gasUsed, 30_000n);
      assert.deepEqual(await state(f), before);
      controls.customer.low = false;
      const request = await f.system.submit('gas-retry', 100);
      assert.notEqual(request.txHash, error.txHash);
      assert.equal(controls.customer.sends, 2);
      const beforeDecision = await state(f);
      const decisionError = await rejected(() => f.system.decide(request));
      assert.match(decisionError.txHash, /^0x[0-9a-f]{64}$/i);
      assert.equal((await provider.getTransactionReceipt(decisionError.txHash)).status, 0);
      assert.deepEqual(await state(f), beforeDecision);
      controls.institution.low = false;
      const decision = await f.system.decide(request);
      assert.equal(controls.institution.sends, 2);
      const trust = await f.system.trust(decision.txHash);
      assert.equal(verifySingle(f.system.bundle(request, decision, trust), trust).ok, true);
      assert.equal(audit(f.system.entries, trust).ok, true);
    });

    await scenario('injected post-broadcast lookup failure can be recovered by reading the saved hash', { timeout: 20_000 }, async () => {
      let savedEnvelope;
      const f = await fixture({ systemOptions: {
        onPayload(_bytes, envelope) { savedEnvelope = envelope; },
      } });
      const originalSend = provider.send;
      const originalGet = provider.getTransaction;
      const broadcasts = [];
      let lookupFailures = 0;
      let inject = true;
      let mined = false;
      await provider.send('evm_setAutomine', [false]);
      provider.send = async function (method, params) {
        const result = await originalSend.call(this, method, params);
        if (method === 'eth_sendTransaction') broadcasts.push(result);
        return result;
      };
      provider.getTransaction = async function (txHash) {
        if (inject && broadcasts.includes(txHash)) {
          lookupFailures++;
          // Deliberately fail ethers' lookup AFTER eth_sendTransaction returned its hash.
          // BAD_DATA is a fatal lookup error, avoiding ethers' missing-transaction retries.
          throw makeError('INJECTED_GET_TRANSACTION_FAILURE', 'BAD_DATA', { value: txHash });
        }
        return originalGet.call(this, txHash);
      };
      try {
        const error = await rejected(() => bounded(f.system.submit('lookup-failure', 200), 'injected lookup failure'));
        assert(lookupFailures > 0, 'the actual post-broadcast lookup boundary must be reached');
        assert.equal(broadcasts.length, 1);
        assert.equal(error.txHash, broadcasts[0]);
        assert.equal(await provider.getTransactionReceipt(error.txHash), null, 'broadcast acceptance does not imply mining');
        inject = false;
        await operation('lookup failure: mine the original broadcast', () => provider.send('evm_mine', []));
        mined = true;
        const receipt = await operation('lookup failure: read mined receipt', () => provider.getTransactionReceipt(error.txHash));
        assert.equal(receipt?.status, 1, 'EVM execution really succeeded');
        assert.equal(await f.contract.size(), 1n);
        const registration = await f.witness.readRecord(error.txHash);
        assert.equal(registration.txHash, error.txHash);
        const trust = await f.system.trust(error.txHash);
        assert.equal(f.system.entries.length, 0);
        f.system.entries.push(view(registration, savedEnvelope));
        assert.equal(verifyReceipt(f.system.bundle(f.system.entries[0], undefined, trust), trust).ok, true);
        assert.equal(broadcasts.length, 1, 'recovery reads must not register again');
      } finally {
        provider.send = originalSend;
        provider.getTransaction = originalGet;
        try {
          if (!mined && broadcasts.length) await provider.send('evm_mine', []);
        } finally {
          await provider.send('evm_setAutomine', [true]);
        }
      }
    });

    await scenario('injected onAppend storage failure preserves a mined record and recovers by its hash', { timeout: 15_000 }, async () => {
      let failStorage = true;
      let stored;
      const f = await fixture({ systemOptions: {
        onAppend(entries) {
          stored = clone(entries);
          if (failStorage) throw new Error('INJECTED_ON_APPEND_STORAGE_FAILURE');
        },
      } });
      const error = await rejected(() => f.system.submit('storage-recovery', 300), /INJECTED_ON_APPEND_STORAGE_FAILURE/);
      assert.match(error.txHash, /^0x[0-9a-f]{64}$/i);
      assert.equal((await provider.getTransactionReceipt(error.txHash)).status, 1);
      assert.equal(stored[0].txHash, error.txHash);
      assert.equal(await f.contract.size(), 1n);
      failStorage = false;
      const trust = await f.system.trust(error.txHash);
      assert.equal(f.system.entries.length, 0);
      const recovered = {
        record: (await f.witness.readRecord(error.txHash)).entry,
        payloadBytes: stored[0].payloadBytes,
        txHash: error.txHash,
      };
      f.system.entries.push(recovered);
      assert.equal(recovered.txHash, error.txHash);
      assert.equal(recovered.payloadBytes, stored[0].payloadBytes);
      const receipt = f.system.bundle(recovered, undefined, trust);
      assert.equal(verifyReceipt(receipt, trust).ok, true);
      assert.equal(await f.contract.size(), 1n);
      const decision = await f.system.decide(recovered);
      const final = await f.system.trust(decision.txHash);
      assert.equal(audit(f.system.entries, final).ok, true);
      await offlineCase('recovered-storage-receipt', 'receipt', receipt, trust, 0);
    });

    await scenario('CLI demo persists independent trust; all verification runs after Anvil and institution storage are unavailable', { timeout: 90_000 }, async () => {
      const out = join(temp, 'cli-demo');
      runCli(['demo', out], 0, true, 60_000);
      const trustPath = join(out, 'auditor/trust.json');
      const receiptTrustPath = join(out, 'customer/receipt-trust.json');
      const persistedTrust = await readFile(trustPath, 'utf8');
      const trust = JSON.parse(persistedTrust);
      const context = JSON.parse(await readFile(join(out, 'context.json'), 'utf8'));
      assert.equal(BigInt(trust.chainId), 31337n);
      assert.equal(getAddress(context.evidenceLogAddress), getAddress(trust.evidenceLogAddress));
      assert.equal(typeof trust.checkpoint.size, 'string', 'bigints persist as decimal strings');
      assert.match(trust.checkpoint.size, /^(0|[1-9][0-9]*)$/);
      const savedLog = JSON.parse(await readFile(join(out, 'witness/log.json'), 'utf8'));
      assert.equal(Array.isArray(savedLog), true);
      assert.equal(Array.isArray(JSON.parse(await readFile(join(out, 'institution/decisions.json'), 'utf8'))), true);
      assert(!persistedTrust.includes('PRIVATE KEY'));
      const receiptTrust = JSON.parse(await readFile(receiptTrustPath, 'utf8'));
      assert.equal(BigInt(receiptTrust.checkpoint.size), 1n);
      const receipt = JSON.parse(await readFile(join(out, 'customer/receipt.json'), 'utf8'));
      assert.equal(receipt.decision, undefined);
      assert.equal(verifyReceipt(receipt, receiptTrust).ok, true);
      // Independently check the persisted anchors against this process's own RPC
      // connection before making the later CLI calls entirely offline.
      const demoContract = new Contract(trust.evidenceLogAddress, artifact.abi, await provider.getSigner(trust.customerAddress));
      const demoWitness = await createEvmWitness({
        evidenceLog: demoContract,
        institutionSigner: await provider.getSigner(trust.institutionAddress),
        deploymentBlock: context.deploymentBlock,
      });
      for (const anchor of [trust, receiptTrust]) {
        const events = await demoContract.queryFilter(
          demoContract.filters.CheckpointPublished(anchor.checkpointId),
          Number(context.deploymentBlock),
          'latest'
        );
        assert.equal(events.length, 1);
        const observed = await demoWitness.readRecord(events[0].transactionHash);
        assert.deepEqual(checkpointInfo({ ...demoWitness.context, ...observed }), checkpointInfo(anchor));
        const entries = savedLog.map(entry => entry.record)
          .filter(entry => BigInt(entry.index) < BigInt(anchor.checkpoint.size));
        checkedLog(entries, anchor);
        assert.equal(BigInt(entries.length), BigInt(anchor.checkpoint.size));
        assert.equal(buildTree(entries, demoWitness.context).root, anchor.checkpoint.root);
      }
      provider.destroy();
      provider = undefined;
      await anvil.stop();
      assert(anvil.child.exitCode !== null || anvil.child.signalCode !== null);
      await rename(join(out, 'institution'), join(temp, 'institution-unavailable'));
      runCli(['receipt', join(out, 'customer/receipt.json'), receiptTrustPath], 0);
      runCli(['verify', join(out, 'customer/rejection.json'), trustPath], 0);
      runCli(['verify', join(out, 'customer/approval.json'), trustPath], 0);
      const report = runCli(['audit', join(out, 'witness/log.json'), trustPath], 0);
      assert.equal(report.requests, 2);
      assert.equal(report.decisions, 2);
      for (const name of ['tampered', 'forged-signature']) {
        runCli(['verify', join(out, `attacks/${name}.json`), trustPath], 1);
      }
      runCli(['audit', join(out, 'attacks/deleted-log.json'), trustPath], 1);
      runCli(['verify', join(out, 'does-not-exist.json'), trustPath], 1);
      for (const item of offlineCases) {
        const result = runCli([item.command, item.file, item.anchor], item.status);
        item.check?.(result);
      }
      assert.equal(await readFile(trustPath, 'utf8'), persistedTrust, 'verification does not rewrite independent trust');
    });
  } finally {
    await cleanup();
  }
});
