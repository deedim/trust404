import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { canonical, parseWire, check } from './crypto.js';

export function createEvidenceServer({ store, reader, writeToken, signer }) {
  check(typeof writeToken === 'string' && writeToken.length >= 32, 'WRITE_TOKEN_REQUIRED');
  const credential = Buffer.from(`Bearer ${writeToken}`);
  // All mutations share one queue: batch assignment and signing cannot race.
  let queue = Promise.resolve();
  const mutate = fn => { const job = queue.then(fn); queue = job.catch(() => {}); return job; };
  return createServer(async (req, res) => {
    try {
      const path = new URL(req.url, 'http://localhost').pathname;
      let value;
      if (req.method === 'GET') {
        let match;
        if ((match = path.match(/^\/v3\/requests\/(0x[0-9a-f]{64})\/evidence$/))) value = store.bundle(match[1]);
        else if ((match = path.match(/^\/v3\/batches\/([1-9][0-9]*)$/))) value = store.archive.batch(match[1]);
        else if ((match = path.match(/^\/v3\/blobs\/(0x[0-9a-f]{64})$/))) value = store.archive.blob(match[1]);
        else { res.writeHead(404).end(); return; }
      } else if (req.method === 'POST') {
        const provided = Buffer.from(req.headers.authorization ?? '');
        if (provided.length !== credential.length || !timingSafeEqual(provided, credential)) { res.writeHead(401).end(); return; }
        let size = 0; const chunks = [];
        for await (const chunk of req) { size += chunk.length; check(size <= 1024 * 1024, 'BODY_TOO_LARGE'); chunks.push(chunk); }
        const body = parseWire(Buffer.concat(chunks).toString('utf8'));
        value = await mutate(async () => {
          if (path === '/v3/requests') return store.submit(body);
          if (path === '/v3/batches/prepare') return store.prepare(await reader.at('latest'));
          const match = path.match(/^\/v3\/requests\/(0x[0-9a-f]{64})\/evaluate$/);
          if (match) { check(signer, 'SIGNER_UNAVAILABLE'); return store.decide(match[1], await reader.at('latest'), signer.keyId, signer.privateKey); }
          throw new Error('NOT_FOUND');
        });
      } else { res.writeHead(405).end(); return; }
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(canonical(value));
    } catch (e) {
      // Never return filesystem paths, RPC credentials, or signing material.
      const code = /^[A-Z][A-Z_]+$/.test(e.message) ? e.message : 'DATA_UNAVAILABLE';
      res.writeHead(code === 'BODY_TOO_LARGE' ? 413 : 400, { 'content-type': 'application/json' }).end(canonical({ error: code }));
    }
  });
}
