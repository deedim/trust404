import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, createWalletClient, http, keccak256 } from 'viem';
import { mnemonicToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { ChainReader, jsonRpc } from '../../src/v3/chain.js';
import { Archive, EvidenceStore } from '../../src/v3/store.js';
import { createEvidenceServer } from '../../src/v3/server.js';
import { auditAll, verifyOne } from '../../src/v3/verify.js';
import { canonical, hash, sign } from '../../src/v3/crypto.js';
import { scope, requestRecord } from '../../src/v3/policy.js';
import { buildTree } from '../../src/v3/merkle.js';
import { fixture } from '../v3/fixtures.js';

const artifact = name => JSON.parse(readFileSync(new URL(`../../out/${name}.sol/${name === 'RecordAnchor.t' ? 'TestToken' : name}.json`, import.meta.url), 'utf8'));
async function freePort() {
  const s = createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening');
  const port = s.address().port; await new Promise(r => s.close(r)); return port;
}
test('HTTP → SQLite/archive → deployed anchor → independent RPC audit detects attacks', { timeout: 30000 }, async t => {
  const port = await freePort(), url = `http://127.0.0.1:${port}`;
  const anvil = spawn('anvil', ['--host', '127.0.0.1', '--port', String(port), '--silent'], { stdio: 'ignore' });
  t.after(async () => { if (anvil.exitCode === null) { anvil.kill(); await once(anvil, 'exit'); } });
  const rpc = jsonRpc(url, { timeoutMs: 500 });
  let started = false;
  for (let i = 0; i < 100; i++) { try { await rpc('eth_chainId', []); started = true; break; } catch { await new Promise(r => setTimeout(r, 50)); } }
  assert(started, 'local chain started');
  const account = mnemonicToAccount('test test test test test test test test test test test junk'); // Public Anvil account only.
  const wallet = createWalletClient({ account, chain: foundry, transport: http(url) });
  const client = createPublicClient({ chain: foundry, transport: http(url) });
  const send = async tx => client.waitForTransactionReceipt({ hash: await wallet.sendTransaction(tx) });
  const deploy = async (a, args = []) => {
    const receipt = await client.waitForTransactionReceipt({ hash: await wallet.deployContract({ abi: a.abi, bytecode: a.bytecode.object, args }) });
    assert.equal(receipt.status, 'success'); return receipt.contractAddress.toLowerCase();
  };
  const anchor = artifact('RecordAnchor'), tokenArtifact = artifact('RecordAnchor.t');
  const anchorAddress = await deploy(anchor, [account.address]), token = await deploy(tokenArtifact);
  const setBalance = async balance => client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: token, abi: tokenArtifact.abi,
    functionName: 'setBalance', args: [account.address, balance] }) });
  await setBalance(120000000n);
  const f = fixture(), p = f.trust.policy;
  Object.assign(p, { anchorAddress, token, treasury: account.address.toLowerCase() });
  f.trust.policyHash = hash('policy-v3', p); f.trust.publisher = account.address.toLowerCase();
  f.trust.codeHash = keccak256(await client.getCode({ address: anchorAddress }));
  let balanceCalls = 0;
  const reader = new ChainReader(async (method, params) => {
    if (method === 'eth_call' && params[0].to === token) {
      balanceCalls++; assert.equal(params[1].requireCanonical, true); assert.match(params[1].blockHash, /^0x[0-9a-f]{64}$/);
    }
    return rpc(method, params);
  }, f.trust);
  const dir = mkdtempSync(join(tmpdir(), 'trust404-chain-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const archive = new Archive(join(dir, 'archive')), store = new EvidenceStore(join(dir, 'records.sqlite'), archive, f.trust);
  const server = createEvidenceServer({ store, reader, writeToken: 'b'.repeat(32), signer: { keyId: 'company', privateKey: f.institution.privateKey } });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  let closed = false;
  t.after(async () => { if (!closed) { await new Promise(r => server.close(r)); store.close(); } });
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = async (path, data = {}) => {
    const response = await fetch(`${base}/v3${path}`, { method: 'POST', headers: { authorization: `Bearer ${'b'.repeat(32)}` }, body: canonical(data) });
    const body = await response.json(); assert.equal(response.status, 200, canonical(body)); return body;
  };
  const request = created => requestRecord({ ...scope(p), requesterId: 'alice', institutionId: p.institutionId,
    token, treasury: p.treasury, recipient: p.treasury, amountAtomic: '50000000', createdAtMs: created,
    policyHash: f.trust.policyHash }, 'alice', f.requester.privateKey);
  const r1 = request('1'), r2 = request('2');
  await post('/requests', r1); await post('/requests', r2);
  const register = async () => {
    const batch = await post('/batches/prepare');
    const tx = batch.transaction;
    const receipt = await send({ to: tx.to, data: tx.data, value: BigInt(tx.value) }); assert.equal(receipt.status, 'success');
    return batch;
  };
  await register();
  await post(`/requests/${r1.requestId}/evaluate`); await post(`/requests/${r2.requestId}/evaluate`);
  assert.equal(balanceCalls, 1, 'same pinned balance is read once for two requests');
  await register();
  const bundle = await (await fetch(`${base}/v3/requests/${r1.requestId}/evidence`)).json();
  await setBalance(200000000n);
  // A new reader is the independent auditor: it cannot use the institution's cached balance.
  const auditor = new ChainReader(rpc, f.trust), view = await auditor.at('latest');
  assert.equal((await verifyOne(bundle, f.trust, view)).reason, 'RESERVE_FLOOR');
  assert.equal((await auditAll(archive, f.trust, view)).ok, true);
  let failOnce = true;
  const flakyReader = new ChainReader(async (method, params) => {
    if (method === 'eth_call' && params[0].to === token && failOnce) { failOnce = false; throw Error('RPC_UNAVAILABLE'); }
    return rpc(method, params);
  }, f.trust);
  const flakyView = await flakyReader.at('latest');
  await assert.rejects(verifyOne(bundle, f.trust, flakyView), /RPC_UNAVAILABLE/);
  assert.equal((await verifyOne(bundle, f.trust, flakyView)).ok, true, 'failed RPC results are not cached');
  // Stop the service and remove the working DB: the archived evidence remains sufficient.
  await new Promise(r => server.close(r)); store.close(); closed = true;
  unlinkSync(join(dir, 'records.sqlite'));
  assert.equal((await auditAll(archive, f.trust, await auditor.at('latest'))).ok, true);
  const original = readFileSync(archive.path('batch', '2'), 'utf8');
  writeFileSync(archive.path('batch', '2'), canonical([]));
  assert((await auditAll(archive, f.trust, view)).issues.some(i => i.code === 'TAMPERED_EXPORT'));
  unlinkSync(archive.path('batch', '2'));
  const unavailable = await auditAll(archive, f.trust, view); assert.equal(unavailable.complete, false);
  assert(unavailable.requests.every(r => r.timing === 'UNKNOWN'));
  writeFileSync(archive.path('batch', '2'), original);
  // A dishonest publisher commits a valid signature on a wrong decision.
  const wrong = structuredClone(bundle.decision.record);
  wrong.decision = sign('decision-v3', 'company', { ...wrong.decision.payload, outcome: 'APPROVED', reason: 'POLICY_SATISFIED' }, f.institution.privateKey);
  const tree = buildTree([wrong]); archive.put('batch', '3', [wrong]);
  await client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: anchorAddress, abi: anchor.abi, functionName: 'anchorBatch', args: [3n, tree.root, 1n] }) });
  const conflict = await auditAll(archive, f.trust, await auditor.at('latest'));
  assert(conflict.issues.some(i => i.code === 'POLICY_MISMATCH')); assert(conflict.issues.some(i => i.code === 'CONFLICTING_DECISIONS'));
  const missing = request('3'); archive.put('batch', '4', [missing]);
  await client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: anchorAddress, abi: anchor.abi, functionName: 'anchorBatch', args: [4n, buildTree([missing]).root, 1n] }) });
  await rpc('evm_increaseTime', [91]); await rpc('evm_mine', []);
  const expired = await auditAll(archive, f.trust, await auditor.at('latest'));
  assert.equal(expired.requests.find(r => r.requestId === missing.requestId).timing, 'MISSING_AS_OF_H');
});
