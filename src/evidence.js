import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify
} from 'node:crypto';
import {
  verifyInclusions,
  checkedLog,
  leafHash,
  payloadHash,
  safeNumber
} from './evm.js';

function requireThat(condition, code) {
  if (!condition) throw new Error(code);
}

export function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);

  if (typeof value === 'string') {
    requireThat(value === value.normalize('NFC'), 'NON_CANONICAL_STRING');
    return JSON.stringify(value);
  }

  if (typeof value === 'number') {
    requireThat(Number.isSafeInteger(value) && !Object.is(value, -0), 'INVALID_NUMBER');
    return String(value);
  }

  if (Array.isArray(value)) {
    const elements = value.map(canonical);
    return `[${elements.join(',')}]`;
  }

  requireThat(value && Object.getPrototypeOf(value) === Object.prototype, 'INVALID_JSON_VALUE');
  const sortedKeys = Object.keys(value).sort();
  const properties = sortedKeys.map(k => {
    const encodedKey = canonical(k);
    const encodedValue = canonical(value[k]);
    return `${encodedKey}:${encodedValue}`;
  });
  return `{${properties.join(',')}}`;
}

export const hash = value => {
  const digest = createHash('sha256');
  const bytes = Buffer.from(canonical(value));
  return digest.update(bytes).digest('hex');
};

export function sign(domain, payload, key) {
  const bytes = Buffer.from(canonical({ domain, payload }));
  const rawSignature = cryptoSign(null, bytes, key);
  return {
    domain,
    payload,
    signature: rawSignature.toString('base64')
  };
}

function signature(envelope, domain, key) {
  requireThat(
    envelope?.domain === domain && typeof envelope.signature === 'string',
    'INVALID_ENVELOPE'
  );
  const envelopeFields = Object.keys(envelope).sort().join(',');
  requireThat(envelopeFields === 'domain,payload,signature', 'INVALID_ENVELOPE');

  const raw = Buffer.from(envelope.signature, 'base64');
  requireThat(
    raw.length === 64 && raw.toString('base64') === envelope.signature,
    'INVALID_SIGNATURE_ENCODING'
  );
  const signedBytes = Buffer.from(canonical({ domain, payload: envelope.payload }));
  const validSignature = cryptoVerify(null, signedBytes, key, raw);
  requireThat(validSignature, 'INVALID_SIGNATURE');

  return envelope.payload;
}

function fields(object, keys) {
  requireThat(
    object && Object.getPrototypeOf(object) === Object.prototype,
    'INVALID_SCHEMA'
  );
  const actualFields = canonical(Object.keys(object).sort());
  const expectedFields = canonical([...keys].sort());
  requireThat(actualFields === expectedFields, 'INVALID_SCHEMA');
}

export function validatePolicy(policy) {
  fields(policy, ['version', 'id', 'institution', 'currency', 'limit', 'decisionWindow']);
  requireThat(
    policy.version === 1
    && policy.id === 'per-transfer-limit-v1'
    && policy.institution === 'demo-bank'
    && policy.currency === 'KRW'
    && policy.limit === 1000000
    && policy.decisionWindow === 60,
    'UNSUPPORTED_POLICY'
  );
}

export function requestPayload(envelope, trust) {
  const r = signature(envelope, 'request', trust.customerKey);
  fields(r, ['version', 'id', 'customer', 'institution', 'amount', 'currency', 'policyHash']);
  requireThat(
    r.version === 1
    && typeof r.id === 'string'
    && /^[a-zA-Z0-9_-]{1,100}$/.test(r.id),
    'INVALID_REQUEST'
  );
  requireThat(
    r.customer === 'demo-customer'
    && r.institution === trust.policy.institution
    && r.currency === 'KRW'
    && r.policyHash === hash(trust.policy),
    'REQUEST_CONTEXT_MISMATCH'
  );
  requireThat(Number.isSafeInteger(r.amount) && r.amount > 0, 'INVALID_AMOUNT');

  return r;
}

export function expectedDecision(r) {
  return r.amount > 1000000
    ? { outcome: 'REJECTED', reason: 'LIMIT_EXCEEDED' }
    : { outcome: 'APPROVED', reason: 'WITHIN_LIMIT' };
}

export function decisionPayload(envelope, request, trust) {
  const d = signature(envelope, 'decision', trust.institutionKey);
  fields(d, ['version', 'requestHash', 'policyHash', 'outcome', 'reason']);
  requireThat(
    d.version === 1
    && d.requestHash === hash(request)
    && d.policyHash === hash(trust.policy),
    'DECISION_CONTEXT_MISMATCH'
  );

  const expected = expectedDecision(request.payload);
  requireThat(d.outcome === expected.outcome && d.reason === expected.reason, 'POLICY_MISMATCH');
  return d;
}

export const encodePayload = envelope => {
  const bytes = Buffer.from(canonical(envelope), 'utf8');
  return `0x${bytes.toString('hex')}`;
};

export function decodePayload(bytes, record) {
  requireThat(bytes !== null && bytes !== undefined, 'MISSING_PAYLOAD');
  requireThat(payloadHash(bytes) === record.payloadHash.toLowerCase(), 'PAYLOAD_HASH_MISMATCH');

  let envelope;

  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const payloadBytes = Buffer.from(bytes.slice(2), 'hex');
    const json = decoder.decode(payloadBytes);
    envelope = JSON.parse(json);
  } catch {
    throw new Error('INVALID_PAYLOAD');
  }

  requireThat(envelope && typeof envelope === 'object', 'INVALID_ENVELOPE');
  const envelopeFields = Object.keys(envelope).sort().join(',');
  requireThat(envelopeFields === 'domain,payload,signature', 'INVALID_ENVELOPE');
  return envelope;
}

function receiptPayload(bundle, trust) {
  requireThat(bundle?.request, 'MISSING_EVIDENCE');
  const inclusion = {
    entry: bundle.request.entry?.record,
    proof: bundle.request.proof
  };
  const { entries: records } = verifyInclusions([inclusion], bundle.checkpointId, trust);
  const [record] = records;
  requireThat(record.kind === 0n, 'EXPECTED_REQUEST');
  const envelope = decodePayload(bundle.request.entry.payloadBytes, record);
  const r = requestPayload(envelope, trust);
  return { record, envelope, request: r };
}

export function verifyReceipt(bundle, trust) {
  const { record, request: r } = receiptPayload(bundle, trust);
  return { ok: true, requestId: r.id, index: safeNumber(record.index) };
}

export function verifySingle(bundle, trust) {
  requireThat(bundle?.request && bundle.decision, 'MISSING_EVIDENCE');
  const items = [bundle.request, bundle.decision];
  const inclusions = items.map(item => ({ entry: item.entry?.record, proof: item.proof }));
  const { entries: records } = verifyInclusions(inclusions, bundle.checkpointId, trust);
  const [requestRecord, decisionRecord] = records;
  const [requestEnvelope, decisionEnvelope] = items.map((item, index) =>
    decodePayload(item.entry.payloadBytes, records[index]));

  requireThat(
    requestRecord.kind === 0n
    && decisionRecord.kind === 1n
    && decisionRecord.requestIndex === requestRecord.index,
    'DECISION_LINK_MISMATCH'
  );

  const r = requestPayload(requestEnvelope, trust);
  const d = decisionPayload(decisionEnvelope, requestEnvelope, trust);
  requireThat(
    requestRecord.recordedAt <= decisionRecord.recordedAt,
    'INVALID_EVENT_ORDER'
  );

  return {
    ok: true,
    requestId: r.id,
    amount: r.amount,
    outcome: d.outcome,
    reason: d.reason
  };
}

export function audit(entries, trust) {
  requireThat(Array.isArray(entries), 'LOG_SIZE_MISMATCH');
  const rawRecords = entries.map(entry => entry.record);
  const { checkpointInfo: info, entries: records } = checkedLog(rawRecords, trust);

  const requests = new Map();
  const reqIds = new Set();
  const decisions = new Set();

  entries.forEach((entry, index) => {
    const record = records[index];
    const envelope = decodePayload(entry.payloadBytes, record);

    if (record.kind === 0n) {
      requireThat(record.actor.toLowerCase() === trust.customerAddress.toLowerCase(), 'ACTOR_MISMATCH');
      const r = requestPayload(envelope, trust);
      requireThat(!reqIds.has(r.id), 'DUPLICATE_REQUEST');
      reqIds.add(r.id);
      requests.set(record.index, { record, envelope });
    } else {
      const key = record.requestIndex;
      decisionPayload(envelope, requests.get(key).envelope, trust);
      decisions.add(key);
    }
  });

  const pending = [];
  const overdue = [];
  for (const [key, request] of requests) {
    if (decisions.has(key)) continue;

    const deadline = request.record.recordedAt + BigInt(trust.policy.decisionWindow);
    const id = request.envelope.payload.id;
    if (info.checkpoint.issuedAt >= deadline) {
      overdue.push(id);
    } else {
      pending.push(id);
    }
  }

  return {
    ok: overdue.length === 0,
    requests: requests.size,
    decisions: decisions.size,
    pending,
    overdue
  };
}

export function createSystem({
  witness,
  onPayload = () => { },
  onAppend = () => { },
  keys = {
    customer: generateKeyPairSync('ed25519'),
    institution: generateKeyPairSync('ed25519')
  }
} = {}) {
  const policy = {
    version: 1,
    id: 'per-transfer-limit-v1',
    institution: 'demo-bank',
    currency: 'KRW',
    limit: 1000000,
    decisionWindow: 60
  };
  const entries = [];
  const baseTrust = {
    chainId: witness.context.chainId,
    evidenceLogAddress: witness.context.evidenceLogAddress,
    depth: witness.context.depth,
    customerAddress: witness.context.customerAddress,
    institutionAddress: witness.context.institutionAddress,
    policy,
    customerKey: keys.customer.publicKey.export({ type: 'spki', format: 'pem' }),
    institutionKey: keys.institution.publicKey.export({ type: 'spki', format: 'pem' })
  };

  async function register(evidence, send) {
    const bytes = encodePayload(evidence);
    const envelopeSnapshot = structuredClone(evidence);
    await onPayload(bytes, envelopeSnapshot);

    const registration = await send(bytes);
    try {
      const record = registration.entry;
      const entry = {
        payloadBytes: bytes,
        record,
        checkpointId: registration.checkpointId
      };
      const updatedEntries = [...entries, entry];
      const entriesSnapshot = structuredClone(updatedEntries);
      await onAppend(entriesSnapshot);
      entries.push(entry);
      return entry;
    } catch (error) {
      error.txHash = registration.txHash;
      error.registration = registration;
      throw error;
    }
  }

  async function submit(id, amount) {
    const payload = {
      version: 1,
      id,
      customer: 'demo-customer',
      institution: policy.institution,
      amount,
      currency: 'KRW',
      policyHash: hash(policy)
    };
    const envelope = sign('request', payload, keys.customer.privateKey);
    requestPayload(envelope, baseTrust);

    const hasDuplicateRequest = entries.some(e => {
      if (BigInt(e.record.kind) !== 0n) return false;
      if (e.record.actor.toLowerCase() !== baseTrust.customerAddress.toLowerCase()) return false;

      const existingEnvelope = decodePayload(e.payloadBytes, e.record);
      return existingEnvelope.payload.id === id;
    });
    requireThat(!hasDuplicateRequest, 'DUPLICATE_REQUEST');
    return register(envelope, bytes => witness.registerRequest(bytes));
  }

  async function decide(receipt) {
    requireThat(
      receipt?.request && receipt.checkpointId !== undefined && receipt.checkpointId !== null,
      'MISSING_EVIDENCE'
    );
    const evidence = structuredClone(receipt);
    const anchor = await trust(evidence.checkpointId);
    const { record, envelope, request: r } = receiptPayload(evidence, anchor);

    const hasDuplicateRequest = entries.some(e => {
      if (BigInt(e.record.kind) !== 0n) return false;
      if (e.record.actor.toLowerCase() !== baseTrust.customerAddress.toLowerCase()) return false;

      const existingEnvelope = decodePayload(e.payloadBytes, e.record);
      if (existingEnvelope.payload.id !== r.id) return false;

      return BigInt(e.record.index) !== BigInt(record.index);
    });
    requireThat(!hasDuplicateRequest, 'DUPLICATE_REQUEST');

    const hasDuplicateDecision = entries.some(e => {
      if (BigInt(e.record.kind) !== 1n) return false;
      return BigInt(e.record.requestIndex) === BigInt(record.index);
    });
    requireThat(!hasDuplicateDecision, 'DUPLICATE_DECISION');

    const payload = {
      version: 1,
      requestHash: hash(envelope),
      policyHash: hash(policy),
      ...expectedDecision(r)
    };
    const decision = sign('decision', payload, keys.institution.privateKey);
    return register(decision, bytes => witness.registerDecision(record.index, bytes));
  }

  async function trust(checkpointId) {
    if (checkpointId === undefined) {
      checkpointId = (await witness.checkpoint()).checkpointId;
    }
    const anchor = await witness.readCheckpoint(checkpointId);
    return {
      ...baseTrust,
      checkpointId: anchor.checkpointId,
      checkpoint: anchor.checkpoint
    };
  }

  const bundle = (request, decision, trust) => {
    const list = entries.slice(0, safeNumber(trust.checkpoint.size));
    const rawRecords = list.map(entry => entry.record);
    const { checkpointInfo: info, tree } = checkedLog(rawRecords, trust);
    const item = (candidate, kind) => {
      requireThat(candidate?.record, 'MISSING_EVIDENCE');
      const index = safeNumber(candidate.record.index);
      const entry = list[index];
      requireThat(
        entry && BigInt(entry.record.kind) === kind,
        'EVIDENCE_NOT_IN_CHECKPOINT'
      );
      const candidateHash = leafHash(candidate.record, baseTrust);
      const storedHash = leafHash(entry.record, baseTrust);
      requireThat(candidateHash === storedHash, 'EVIDENCE_NOT_IN_CHECKPOINT');
      const { payloadBytes, record, checkpointId } = entry;
      return { entry: { payloadBytes, record, checkpointId }, proof: tree.proof(index) };
    };

    const result = {
      checkpointId: info.checkpointId,
      request: item(request, 0n)
    };
    if (decision !== undefined) {
      result.decision = item(decision, 1n);
    }

    return structuredClone(result);
  };

  return {
    keys,
    entries,
    policy,
    submit,
    decide,
    trust,
    bundle,
  };
}
