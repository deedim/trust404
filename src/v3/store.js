import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { canonical, parseWire, check, hash, hashShape, integer } from './crypto.js';
import { buildTree } from './merkle.js';
import { validateRequest, makeDecision, receiptRef } from './policy.js';
import { anchorCall } from './chain.js';

export class Archive {
  constructor(directory) { this.directory = directory; mkdirSync(directory, { recursive: true }); }
  path(kind, id) {
    check(kind === 'batch' ? /^[1-9][0-9]*$/.test(String(id)) : hashShape(id), 'INVALID_ARCHIVE_ID');
    return join(this.directory, `${kind}-${id}.json`);
  }
  put(kind, id, value) {
    const path = this.path(kind, id), bytes = canonical(value);
    if (existsSync(path)) { check(readFileSync(path, 'utf8') === bytes, 'ARCHIVE_CONFLICT'); return; }
    const temp = `${path}.tmp`;
    writeFileSync(temp, bytes, { mode: 0o600, flush: true }); renameSync(temp, path);
  }
  batch(id) { return parseWire(readFileSync(this.path('batch', id), 'utf8')); }
  blob(id) { return parseWire(readFileSync(this.path('blob', id), 'utf8')); }
}

export class EvidenceStore {
  constructor(filename, archive, trust) {
    this.trees = new Map();
    this.db = new DatabaseSync(filename); this.archive = archive; this.trust = structuredClone(trust);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, record TEXT NOT NULL, unique_key TEXT UNIQUE NOT NULL,
        request_id TEXT NOT NULL, kind TEXT NOT NULL, batch_id TEXT);
      CREATE TABLE IF NOT EXISTS batches (id TEXT PRIMARY KEY, records TEXT NOT NULL, root TEXT NOT NULL, count INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS blobs (hash TEXT PRIMARY KEY, value TEXT NOT NULL);`);
    const config = canonical(trust), previous = this.db.prepare('SELECT value FROM config WHERE id=1').get();
    check(!previous || previous.value === config, 'STORE_CONTEXT_MISMATCH');
    if (!previous) this.db.prepare('INSERT INTO config VALUES (1,?)').run(config);
  }
  close() { this.db.close(); }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.db.exec('COMMIT'); return result; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  submit(record) {
    validateRequest(record, this.trust);
    const key = `request:${record.requestId}`, bytes = canonical(record);
    const existing = this.db.prepare('SELECT record FROM entries WHERE unique_key=?').get(key);
    if (existing) { check(existing.record === bytes, 'REQUEST_CONFLICT'); return { requestId: record.requestId, duplicate: true }; }
    this.db.prepare('INSERT INTO entries(record,unique_key,request_id,kind) VALUES (?,?,?,?)')
      .run(bytes, key, record.requestId, 'REQUEST');
    return { requestId: record.requestId, duplicate: false };
  }
  exportBatch(id) {
    integer(String(id), true);
    const b = this.db.prepare('SELECT * FROM batches WHERE id=?').get(String(id));
    check(b, 'BATCH_UNAVAILABLE');
    const records = parseWire(b.records);
    for (const record of records) {
      const h = record.decision?.payload.stateHash;
      if (h) this.archive.put('blob', h, parseWire(this.db.prepare('SELECT value FROM blobs WHERE hash=?').get(h).value));
    }
    this.archive.put('batch', id, records);
    return { batchId: String(id), root: b.root, count: b.count };
  }
  async prepare(chain) {
    await chain.assertCanonical();
    const count = BigInt(await chain.count());
    const id = (count + 1n).toString();
    // Existing on-chain IDs must still commit our frozen bytes before progressing.
    for (const local of this.db.prepare('SELECT id,root,count FROM batches').all()) {
      if (BigInt(local.id) > count) continue;
      const registered = await chain.batch(local.id);
      check(registered.root === local.root && registered.count === local.count, 'ANCHOR_MISMATCH');
    }
    // Resume a frozen batch after a restart, instead of assigning different records to its ID.
    if (!this.db.prepare('SELECT id FROM batches WHERE id=?').get(id)) {
      this.transaction(() => {
        const rows = this.db.prepare('SELECT seq,record FROM entries WHERE batch_id IS NULL ORDER BY seq LIMIT 32').all();
        check(rows.length, 'NO_PENDING_RECORDS');
        const records = rows.map(r => parseWire(r.record)), tree = buildTree(records);
        this.db.prepare('INSERT INTO batches VALUES (?,?,?,?)').run(id, canonical(records), tree.root, tree.count);
        const update = this.db.prepare('UPDATE entries SET batch_id=? WHERE seq=?');
        for (const row of rows) update.run(id, row.seq);
      });
    }
    const batch = this.exportBatch(id);
    await chain.assertCanonical();
    return { ...batch, transaction: anchorCall(batch, this.trust) };
  }
  item(requestId, kind) {
    check(hashShape(requestId), 'INVALID_REQUEST_ID');
    const row = this.db.prepare('SELECT * FROM entries WHERE request_id=? AND kind=? ORDER BY seq LIMIT 1').get(requestId, kind);
    check(row?.batch_id, 'RECORD_NOT_BATCHED');
    const batch = this.db.prepare('SELECT records,root FROM batches WHERE id=?').get(row.batch_id);
    const records = parseWire(batch.records), index = records.findIndex(r => canonical(r) === row.record);
    let tree = this.trees.get(batch.root);
    if (!tree) {
      tree = buildTree(records);
      check(tree.root === batch.root, 'LOCAL_DATA_CORRUPTION');
      if (this.trees.size >= 128) this.trees.delete(this.trees.keys().next().value);
      this.trees.set(batch.root, tree);
    }
    return { batchId: row.batch_id, record: parseWire(row.record), count: tree.count, index, proof: tree.proof(index) };
  }
  async decide(requestId, chain, keyId, privateKey) {
    const item = this.item(requestId, 'REQUEST'), meta = await chain.batch(item.batchId);
    const local = this.exportBatch(item.batchId);
    check(meta.root === local.root && meta.count === local.count, 'ANCHOR_MISMATCH');
    const ref = receiptRef(meta, item.index), key = `decision:${requestId}:${hash('receipt-v3', ref)}`;
    const old = this.db.prepare('SELECT record FROM entries WHERE unique_key=?').get(key);
    if (old) return parseWire(old.record);
    const { record, snapshot } = await makeDecision(item.record, ref, this.trust, chain, keyId, privateKey);
    await chain.assertCanonical();
    this.transaction(() => {
      if (snapshot) this.db.prepare('INSERT OR IGNORE INTO blobs VALUES (?,?)').run(record.decision.payload.stateHash, canonical(snapshot));
      this.db.prepare('INSERT OR IGNORE INTO entries(record,unique_key,request_id,kind) VALUES (?,?,?,?)')
        .run(canonical(record), key, requestId, 'DECISION');
    });
    return parseWire(this.db.prepare('SELECT record FROM entries WHERE unique_key=?').get(key).record);
  }
  bundle(requestId) {
    const request = this.item(requestId, 'REQUEST'), decision = this.item(requestId, 'DECISION');
    const stateHash = decision.record.decision.payload.stateHash;
    return { request, decision, snapshot: stateHash ? parseWire(this.db.prepare('SELECT value FROM blobs WHERE hash=?').get(stateHash).value) : null };
  }
}
