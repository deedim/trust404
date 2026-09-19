import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Archive, EvidenceStore } from '../../src/v3/store.js';
import { createEvidenceServer } from '../../src/v3/server.js';
import { canonical } from '../../src/v3/crypto.js';
import { verifyOne, auditAll } from '../../src/v3/verify.js';
import { fixture, FakeChain } from './fixtures.js';

test('SQLite restart preserves idempotency, frozen batches and independent archive', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'trust404-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const f = fixture(), chain = new FakeChain(), archive = new Archive(join(dir, 'archive')), db = join(dir, 'records.sqlite');
  let store = new EvidenceStore(db, archive, f.trust);
  const request = f.request(); store.submit(request);
  const first = await store.prepare(chain); store.close();
  store = new EvidenceStore(db, archive, f.trust);
  assert.equal(store.submit(request).duplicate, true); assert.deepEqual(await store.prepare(chain), first);
  await assert.rejects(store.decide(request.requestId, chain, 'company', f.institution.privateKey), /BATCH_UNAVAILABLE/);
  chain.add(archive.batch('1'));
  await assert.rejects(store.decide(request.requestId, chain, 'company', f.requester.privateKey), /INVALID_SIGNATURE/);
  const decision = await store.decide(request.requestId, chain, 'company', f.institution.privateKey);
  assert.deepEqual(await store.decide(request.requestId, chain, 'company', f.institution.privateKey), decision);
  await store.prepare(chain); chain.add(archive.batch('2'), 110);
  assert.equal((await verifyOne(store.bundle(request.requestId), f.trust, chain)).ok, true);
  store.close(); assert.equal((await auditAll(archive, f.trust, chain)).ok, true);
});
test('HTTP writes require authentication and canonical payloads', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'trust404-http-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const f = fixture(), store = new EvidenceStore(join(dir, 'records.sqlite'), new Archive(join(dir, 'archive')), f.trust);
  const token = 'a'.repeat(32), server = createEvidenceServer({ store, reader: {}, writeToken: token });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); store.close(); });
  const url = `http://127.0.0.1:${server.address().port}/v3/requests`, record = f.request();
  assert.equal((await fetch(url, { method: 'POST', body: canonical(record) })).status, 401);
  const headers = { authorization: `Bearer ${token}` };
  assert.equal((await fetch(url, { method: 'POST', headers, body: canonical(record) })).status, 200);
  assert.equal((await fetch(url, { method: 'POST', headers, body: JSON.stringify(record, null, 2) })).status, 400);
});

test('publisher mismatch after a fork blocks subsequent batch preparation', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'trust404-fork-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const f = fixture(), chain = new FakeChain(), archive = new Archive(join(dir, 'archive'));
  const store = new EvidenceStore(join(dir, 'records.sqlite'), archive, f.trust); t.after(() => store.close());
  store.submit(f.request()); await store.prepare(chain);
  chain.add([f.request('70000000')]);
  store.submit(f.request('50000000', '2'));
  await assert.rejects(store.prepare(chain), /ANCHOR_MISMATCH/);
});
