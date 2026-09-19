import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createSystem, decodePayload, encodePayload, hash, sign } from '../src/evidence.js';
import { createTestWitness, entryView, receiptFor, alterPayload, fixture, json } from './helpers.js';

const cli = new URL('../src/cli.js', import.meta.url).pathname;
const run = (...args) => spawnSync(process.execPath, [cli, ...args], {
  encoding: 'utf8', timeout: 5000, env: { ...process.env, RPC_URL: '' },
});

test('R7,R8: saved evidence verifies offline without institution files', async t => {
  const { s, request, trust, bundle } = await fixture();
  const directory = mkdtempSync(join(tmpdir(), 'trust404-cli-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(join(directory, 'institution'));
  const file = join(directory, 'evidence.json'); const trustFile = join(directory, 'trust.json');
  writeFileSync(trustFile, json(trust));
  writeFileSync(file, json(bundle));
  assert.equal(run('verify', file, trustFile).status, 0);
  rmSync(join(directory, 'institution'), { recursive: true });
  const result = run('verify', file, trustFile);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).reason, 'LIMIT_EXCEEDED');
  writeFileSync(file, json(s.bundle(request, undefined, trust)));
  assert.equal(run('receipt', file, trustFile).status, 0);
  assert.equal(run('verify', file, trustFile).status, 1);
  writeFileSync(file, json(s.entries));
  assert.equal(run('audit', file, trustFile).status, 0);
});

test('R8: CLI distinguishes tampering, incomplete audit and deadline outcomes', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'trust404-cli-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = join(directory, 'evidence.json'); const trustFile = join(directory, 'trust.json');
  const { s, trust, bundle } = await fixture();
  function check(command, value, anchor = trust) {
    writeFileSync(file, json(value)); writeFileSync(trustFile, json(anchor));
    return run(command, file, trustFile);
  }
  const tampered = structuredClone(bundle); alterPayload(tampered.decision.entry, e => e.payload.reason = 'OTHER');
  assert.equal(check('verify', tampered).status, 1);
  assert.equal(check('audit', s.entries.slice(1)).status, 1);
  const incomplete = structuredClone(s.entries); incomplete[1].payloadBytes = null;
  const missing = check('audit', incomplete);
  assert.equal(missing.status, 1);
  assert.equal(JSON.parse(missing.stderr).error, 'MISSING_PAYLOAD');
  const witness = createTestWitness(); const pending = createSystem({ witness });
  const request = await pending.submit('unanswered', 1);
  for (const [time, code, field] of [[1059, 0, 'pending'], [1060, 1, 'overdue']]) {
    witness.time = time;
    const anchor = await pending.trust();
    const output = check('audit', pending.entries, anchor);
    assert.equal(output.status, code, output.stderr);
    assert.deepEqual(JSON.parse(output.stdout)[field], ['unanswered']);
  }
  witness.time = 1061;
  const decision = await pending.decide(await receiptFor(pending, request)); const anchor = await pending.trust();
  const late = check('verify', pending.bundle(request, decision, anchor), anchor);
  assert.equal(late.status, 0);
  assert.equal(JSON.parse(late.stdout).outcome, 'APPROVED');
});

test('CLI rejects correctly signed and registered decisions that contradict policy', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'trust404-wrong-policy-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = join(directory, 'evidence.json');
  const trustFile = join(directory, 'trust.json');

  for (const [amount, outcome, reason] of [
    [1500000, 'APPROVED', 'WITHIN_LIMIT'],
    [500000, 'REJECTED', 'LIMIT_EXCEEDED'],
    [1500000, 'REJECTED', 'WITHIN_LIMIT'],
  ]) {
    const witness = createTestWitness();
    const s = createSystem({ witness });
    const request = await s.submit('wrong-policy', amount);
    const envelope = sign('decision', {
      version: 1,
      requestHash: hash(decodePayload(request.payloadBytes, request.record)),
      policyHash: hash(s.policy),
      outcome,
      reason,
    }, s.keys.institution.privateKey);
    const bytes = encodePayload(envelope);
    const decision = entryView(await witness.registerDecision(request.record.index, bytes), bytes);
    s.entries.push(decision);
    const trust = await s.trust();
    writeFileSync(trustFile, json(trust));

    writeFileSync(file, json(s.bundle(request, undefined, trust)));
    const receipt = run('receipt', file, trustFile);
    assert.equal(receipt.status, 0, receipt.stderr);

    for (const [command, evidence] of [
      ['verify', s.bundle(request, decision, trust)],
      ['audit', s.entries],
    ]) {
      writeFileSync(file, json(evidence));
      const result = run(command, file, trustFile);
      assert.equal(result.status, 1);
      assert.equal(JSON.parse(result.stderr).error, 'POLICY_MISMATCH');
    }
  }
});

test('CLI validates policy when loading external trust for each verification command', async t => {
  const { s, request, trust, bundle } = await fixture();
  const directory = mkdtempSync(join(tmpdir(), 'trust404-policy-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = join(directory, 'evidence.json');
  const trustFile = join(directory, 'trust.json');
  for (const [command, evidence] of [
    ['receipt', s.bundle(request, undefined, trust)],
    ['verify', bundle],
    ['audit', s.entries],
  ]) {
    writeFileSync(file, json(evidence));
    writeFileSync(trustFile, json({ ...trust, policy: { ...trust.policy, limit: 500000 } }));
    const result = run(command, file, trustFile);
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stderr).error, 'UNSUPPORTED_POLICY');
    writeFileSync(trustFile, json(trust));
    assert.equal(run(command, file, trustFile).status, 0);
  }
});

test('demo emits overdue and policy-violating evidence and keeps normal evidence verifiable offline', t => {
  const directory = mkdtempSync(join(tmpdir(), 'trust404-demo-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const out = join(directory, 'output');
  const mockWitness = `
    import assert from 'node:assert/strict';
    import { createTestWitness } from ${JSON.stringify(new URL('./helpers.js', import.meta.url).href)};
    const witness = createTestWitness();
    export async function deployEvmWitness() {
      return { ...witness, close() {} };
    }
    export class JsonRpcProvider {
      async send(method, params) {
        assert.equal(method, 'evm_increaseTime');
        assert.deepEqual(params, [60]);
        witness.time += params[0];
      }
      destroy() {}
    }
  `;
  const mockUrl = `data:text/javascript,${encodeURIComponent(mockWitness)}`;
  const hooks = `
    export function resolve(specifier, context, nextResolve) {
      if (['./evm.js', 'ethers'].includes(specifier) && context.parentURL === ${JSON.stringify(new URL('../src/cli.js', import.meta.url).href)}) {
        return { url: ${JSON.stringify(mockUrl)}, shortCircuit: true };
      }
      return nextResolve(specifier, context);
    }
  `;
  const preload = `import { register } from 'node:module'; register(${JSON.stringify(`data:text/javascript,${encodeURIComponent(hooks)}`)});`;
  const demo = spawnSync(process.execPath, [
    '--import', `data:text/javascript,${encodeURIComponent(preload)}`, cli, 'demo', out,
  ], { encoding: 'utf8', timeout: 5000, env: { ...process.env, RPC_URL: 'offline-test' } });
  assert.equal(demo.status, 0, demo.stderr);
  const checks = JSON.parse(demo.stdout).checks;
  assert.equal(checks.length, 8);
  assert.deepEqual(checks.slice(-2), [
    { name: '접수 후 판단 누락', result: 'DETECTED' },
    { name: '정책 위반 판단', result: 'DETECTED' },
  ]);

  const normalTrust = JSON.parse(readFileSync(join(out, 'auditor/trust.json'), 'utf8'));
  const missingTrust = JSON.parse(readFileSync(join(out, 'attacks/missing-trust.json'), 'utf8'));
  const missingLog = JSON.parse(readFileSync(join(out, 'attacks/missing-log.json'), 'utf8'));
  for (const entry of missingLog) {
    assert.deepEqual(Object.keys(entry).sort(), ['checkpointId', 'payloadBytes', 'record']);
  }
  const wrongPolicyTrust = JSON.parse(readFileSync(join(out, 'attacks/wrong-policy-trust.json'), 'utf8'));
  assert.deepEqual(wrongPolicyTrust.policy, normalTrust.policy);
  assert.equal(normalTrust.checkpoint.size, '4');
  assert.equal(missingTrust.checkpoint.size, '5');
  assert.equal(wrongPolicyTrust.checkpoint.size, '7');
  const unanswered = missingLog.at(-1);
  assert.equal(unanswered.record.kind, '0');
  assert.equal(decodePayload(unanswered.payloadBytes, unanswered.record).payload.id, 'unanswered');
  assert.equal(BigInt(missingTrust.checkpoint.issuedAt) - BigInt(unanswered.record.recordedAt), 60n);

  const missing = run('audit', join(out, 'attacks/missing-log.json'), join(out, 'attacks/missing-trust.json'));
  assert.equal(missing.status, 1);
  assert.equal(missing.stderr, '');
  assert.deepEqual(JSON.parse(missing.stdout), {
    ok: false, requests: 3, decisions: 2, pending: [], overdue: ['unanswered'],
  });

  for (const [command, file, trust, error] of [
    ['receipt', 'customer/receipt.json', 'customer/receipt-trust.json'],
    ['verify', 'customer/rejection.json', 'auditor/trust.json'],
    ['verify', 'customer/approval.json', 'auditor/trust.json'],
    ['audit', 'witness/log.json', 'auditor/trust.json'],
    ['verify', 'attacks/tampered.json', 'auditor/trust.json', 'PAYLOAD_HASH_MISMATCH'],
    ['verify', 'attacks/forged-signature.json', 'auditor/trust.json', 'PAYLOAD_HASH_MISMATCH'],
    ['audit', 'attacks/deleted-log.json', 'auditor/trust.json', 'LOG_SIZE_MISMATCH'],
    ['verify', 'attacks/wrong-policy-result.json', 'attacks/wrong-policy-trust.json', 'POLICY_MISMATCH'],
  ]) {
    assert.equal(readFileSync(join(out, file), 'utf8').includes('"txHash"'), false, file);
    const result = run(command, join(out, file), join(out, trust));
    assert.equal(result.status, error ? 1 : 0, result.stderr);
    if (error) assert.equal(JSON.parse(result.stderr).error, error);
    else assert.equal(JSON.parse(result.stdout).ok, true);
  }
});

test('CLI rejects invalid arguments and demo requires explicit RPC configuration', async t => {
  assert.equal(run('unknown').status, 1);
  assert.equal(run('verify').status, 1);
  assert.equal(run('audit', 'absent.json', 'absent-trust.json').status, 1);
  assert.equal(run('verify', 'a', 'b', 'extra').status, 1);
  const withoutRpc = run('demo');
  assert.equal(withoutRpc.status, 1);
  assert.equal(JSON.parse(withoutRpc.stderr).error, 'RPC_URL_REQUIRED');
  const directory = mkdtempSync(join(tmpdir(), 'trust404-existing-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const existing = spawnSync(process.execPath, [cli, 'demo', directory], {
    encoding: 'utf8', timeout: 5000, env: { ...process.env, RPC_URL: 'http://127.0.0.1:1' },
  });
  assert.equal(existing.status, 1);
  assert.match(JSON.parse(existing.stderr).error, /EEXIST/);
});
