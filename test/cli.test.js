import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createSystem } from '../src/evidence.js';
import { createTestWitness, alterPayload, fixture, json } from './helpers.js';

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
  const decision = await pending.decide(request); const anchor = await pending.trust();
  const late = check('verify', pending.bundle(request, decision, anchor), anchor);
  assert.equal(late.status, 0);
  assert.equal(JSON.parse(late.stdout).outcome, 'APPROVED');
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
