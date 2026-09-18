import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
const cli = new URL('../src/cli.js', import.meta.url).pathname;
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
test('R7,R8: demo, offline verification, deletion and CLI failures', () => {
  const temp = mkdtempSync(join(tmpdir(), 'trust404-test-'));
  try {
    const out = join(temp, 'demo');
    const demo = run('demo', out);
    assert.equal(demo.status, 0, demo.stderr);
    const trust = join(out, 'auditor/trust.json');
    const bundle = join(out, 'customer/rejection.json');
    assert.equal(run('verify', bundle, trust).status, 0);
    rmSync(join(out, 'institution'), { recursive: true });
    assert.equal(run('verify', bundle, trust).status, 0);
    assert.equal(run('audit', join(out, 'witness/log.json'), trust).status, 0);
    for (const name of ['tampered', 'forged-signature', 'wrong-policy-result']) {
      const anchor = name === 'wrong-policy-result' ? join(out, 'attacks/wrong-policy-trust.json') : trust;
      assert.equal(run('verify', join(out, `attacks/${name}.json`), anchor).status, 1, name);
    }
    assert.equal(run('audit', join(out, 'attacks/deleted-log.json'), trust).status, 1);
    const missing = run('audit', join(out, 'attacks/missing-log.json'), join(out, 'attacks/missing-trust.json'));
    assert.equal(missing.status, 1); assert.deepEqual(JSON.parse(missing.stdout).overdue, ['unanswered']);
    const receipt = JSON.parse(readFileSync(join(out, 'customer/receipt.json')));
    assert.equal(receipt.checkpoint.payload.size, 1);
    assert.equal(existsSync(join(out, 'README.txt')), true);
    assert.equal(run('demo', out).status, 1, 'existing evidence must not be overwritten');
    assert.equal(run('verify', join(out, 'absent.json'), trust).status, 1);
    assert.equal(run('unknown').status, 1);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
