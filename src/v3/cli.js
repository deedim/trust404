import { readFileSync } from 'node:fs';
import { Archive, EvidenceStore } from './store.js';
import { ChainReader, jsonRpc } from './chain.js';
import { createEvidenceServer } from './server.js';
import { auditAll, verifyOne } from './verify.js';
import { check, parseWire } from './crypto.js';

async function main() {
  const [command, configFile, target, block = 'finalized'] = process.argv.slice(2);
  check(['serve', 'verify', 'audit'].includes(command) && configFile, 'INVALID_ARGUMENTS');
  const config = JSON.parse(readFileSync(configFile, 'utf8'));
  const trust = JSON.parse(readFileSync(config.trustFile, 'utf8'));
  const reader = new ChainReader(jsonRpc(config.rpcUrl), trust);
  if (command === 'serve') {
    const store = new EvidenceStore(config.databaseFile, new Archive(config.archiveDirectory), trust);
    const signer = config.signerKeyFile ? { keyId: config.signerKeyId, privateKey: readFileSync(config.signerKeyFile, 'utf8') } : undefined;
    const server = createEvidenceServer({ store, reader, signer, writeToken: process.env.EVIDENCE_WRITE_TOKEN });
    server.listen(config.port ?? 4040, '127.0.0.1', () => console.log(`Evidence API listening on 127.0.0.1:${server.address().port}`));
    const shutdown = () => server.close(() => { store.close(); process.exit(0); });
    process.once('SIGINT', shutdown); process.once('SIGTERM', shutdown);
    return;
  }
  const chain = await reader.at(block);
  const result = command === 'verify'
    ? await verifyOne(parseWire(readFileSync(target, 'utf8')), trust, chain)
    : await auditAll(new Archive(target ?? config.archiveDirectory), trust, chain);
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exitCode = 1;
}
main().catch(e => { console.error(/^[A-Z][A-Z_]+$/.test(e.message) ? e.message : 'OPERATION_FAILED'); process.exitCode = 1; });
