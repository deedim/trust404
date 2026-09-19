import { mkdirSync, writeFileSync, readFileSync, renameSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createSystem, validatePolicy, verifyReceipt, verifySingle, audit, decodePayload, encodePayload } from './evidence.js';
import { deployEvmWitness } from './evm.js';

const read = path => JSON.parse(readFileSync(path, 'utf8'));
function readTrust(path) {
  const trust = read(path);
  validatePolicy(trust.policy);
  return trust;
}

const json = value => JSON.stringify(
  value,
  (_, item) => typeof item === 'bigint' ? item.toString() : item,
  2
);

function write(path, value) {
  writeFileSync(`${path}.tmp`, json(value) + '\n', { flag: 'wx', flush: true });
  renameSync(`${path}.tmp`, path);
}

async function demo(destination) {
  if (!process.env.RPC_URL) throw new Error('RPC_URL_REQUIRED');

  const out = resolve(destination ?? `demo-output-${Date.now()}`);
  // A fresh directory prevents accidental replacement of an auditor's trust anchor.
  mkdirSync(out);
  for (const dir of ['customer', 'institution', 'witness', 'auditor', 'attacks'])
    mkdirSync(join(out, dir));

  const witness = await deployEvmWitness({ rpcUrl: process.env.RPC_URL });

  try {
    const system = createSystem({
      witness,
      onPayload: (bytes, envelope) => write(
        join(
          out,
          envelope.domain === 'request'
            ? `customer/${envelope.payload.id}-request.json`
            : `institution/${envelope.payload.requestHash}-decision.json`
        ),
        bytes
      ),
      onAppend: entries => write(join(out, 'witness/log.json'), entries)
    });
    write(join(out, 'context.json'), witness.context);

    const request = await system.submit('transfer-rejected', 1500000);

    const receiptTrust = await system.trust(request.checkpointId);
    const receipt = system.bundle(request, undefined, receiptTrust);

    write(join(out, 'customer/receipt.json'), receipt);
    write(join(out, 'customer/receipt-trust.json'), receiptTrust);
    write(join(out, 'institution/transfer-rejected-request.json'), request.payloadBytes);

    const decision = await system.decide(receipt);

    const approvedRequest = await system.submit('transfer-approved', 500000);
    write(join(out, 'institution/transfer-approved-request.json'), approvedRequest.payloadBytes);

    const approvalTrust = await system.trust(approvedRequest.checkpointId);
    const approvalReceipt = system.bundle(approvedRequest, undefined, approvalTrust);
    const approval = await system.decide(approvalReceipt);

    const trust = await system.trust();
    const rejection = system.bundle(request, decision, trust);

    write(join(out, 'auditor/trust.json'), trust);
    write(join(out, 'witness/checkpoint.json'), trust.checkpoint);
    write(join(out, 'customer/rejection.json'), rejection);
    write(join(out, 'customer/approval.json'), system.bundle(approvedRequest, approval, trust));
    write(join(out, 'institution/decisions.json'), [decision, approval]);

    const tampered = structuredClone(rejection);
    const altered = decodePayload(decision.payloadBytes, decision.record);
    altered.payload.reason = 'CHANGED_LATER';
    tampered.decision.entry.payloadBytes = encodePayload(altered);
    write(join(out, 'attacks/tampered.json'), tampered);

    const forged = structuredClone(rejection);
    const unsigned = decodePayload(decision.payloadBytes, decision.record);
    unsigned.signature = 'AAAA';
    forged.decision.entry.payloadBytes = encodePayload(unsigned);
    write(join(out, 'attacks/forged-signature.json'), forged);
    write(
      join(out, 'attacks/deleted-log.json'),
      system.entries.filter(e => e.record.index !== decision.record.index)
    );

    writeFileSync(
      join(out, 'README.txt'),
      '송금 판단 검증 시연: 실제 송금 없이 EVM 체인의 EvidenceLog 계약에 요청·판단 해시를 등록합니다.\ncustomer: 고객 보관 증거\nauditor/trust.json: 사전 전달된 신뢰 기준 역할\nwitness: 외부 기록 주체의 계약 기록과 원문을 보관하는 로컬 저장소 역할\ninstitution: 기관 저장소 역할 (검증기는 읽지 않음)\nattacks: 공격별 독립 시연 파일\n시각과 순번은 계약 기록을 사용합니다.\n실제 운영에서는 각 역할을 별도 환경에서 운영하고 공개키·체크포인트를 독립 경로로 전달해야 합니다.\n'
    );

    const checks = [];
    const check = (name, fn, expected) => {
      let actual;

      try {
        actual = fn().ok ? 'PASS' : 'DETECTED';
      } catch {
        actual = 'DETECTED';
      }

      if (actual !== expected) throw new Error(`DEMO_FAILED: ${name}`);
      checks.push({ name, result: actual });
    };

    check(
      '거절 단건 독립 검증',
      () => verifySingle(
        read(join(out, 'customer/rejection.json')),
        readTrust(join(out, 'auditor/trust.json'))
      ),
      'PASS'
    );
    check(
      '승인 단건 검증',
      () => verifySingle(system.bundle(approvedRequest, approval, trust), trust),
      'PASS'
    );
    check('전체 범위 감사', () => audit(system.entries, trust), 'PASS');
    check('사유 변조', () => verifySingle(tampered, trust), 'DETECTED');
    check('서명 위조', () => verifySingle(forged, trust), 'DETECTED');
    check(
      '목록 삭제',
      () => audit(read(join(out, 'attacks/deleted-log.json')), trust),
      'DETECTED'
    );

    return { ok: true, output: out, checks };
  } finally {
    witness.close();
  }
}

try {
  const [command, file, trustFile, ...extra] = process.argv.slice(2);
  if (extra.length || (command === 'demo' && trustFile)) throw new Error('INVALID_ARGUMENTS');

  let result;

  if (command === 'demo')
    result = await demo(file);
  else if (command === 'receipt' && file && trustFile)
    result = verifyReceipt(read(file), readTrust(trustFile));
  else if (command === 'verify' && file && trustFile)
    result = verifySingle(read(file), readTrust(trustFile));
  else if (command === 'audit' && file && trustFile)
    result = audit(read(file), readTrust(trustFile));
  else
    throw new Error(
      'Usage: node src/cli.js demo [new-directory] | receipt|verify <bundle.json> <trust.json> | audit <log.json> <trust.json>'
    );

  console.log(json(result));
  process.exitCode = result.ok ? 0 : 1;
} catch (error) {
  console.error(json({
    ok: false,
    error: error.message.split('\n')[0],
    txHash: error.txHash,
    registrationStatus: error.registrationStatus
  }));
  process.exitCode = 1;
}
