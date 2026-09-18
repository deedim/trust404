import { mkdirSync, writeFileSync, readFileSync, renameSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createSystem, verifySingle, audit, proof, sign } from './evidence.js';

const read = path => JSON.parse(readFileSync(path, 'utf8'));
function write(path, value) {
  writeFileSync(`${path}.tmp`, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', flush: true });
  renameSync(`${path}.tmp`, path);
}
function demo(destination) {
  const out = resolve(destination ?? `demo-output-${Date.now()}`);
  // A fresh directory prevents accidental replacement of an auditor's trust anchor.
  mkdirSync(out);
  for (const dir of ['customer', 'institution', 'witness', 'auditor', 'attacks']) mkdirSync(join(out, dir));
  const system = createSystem({ onAppend: entries => write(join(out, 'witness/log.json'), entries) });
  const now = Math.floor(Date.now() / 1000);
  const request = system.submit('transfer-rejected', 1500000, now);
  const receiptTrust = system.trust(now);
  write(join(out, 'customer/receipt.json'), { entry: request, proof: proof(system.entries, 0), checkpoint: receiptTrust.checkpoint });
  write(join(out, 'customer/receipt-trust.json'), receiptTrust);
  const decision = system.decide(request, now + 1);
  const approvedRequest = system.submit('transfer-approved', 500000, now + 2);
  const approval = system.decide(approvedRequest, now + 3);
  const trust = system.trust(now + 4);
  const rejection = system.bundle(request, decision, trust);
  write(join(out, 'auditor/trust.json'), trust);
  write(join(out, 'witness/checkpoint.json'), trust.checkpoint);
  write(join(out, 'customer/rejection.json'), rejection);
  write(join(out, 'customer/approval.json'), system.bundle(approvedRequest, approval, trust));
  write(join(out, 'institution/decisions.json'), [decision, approval]);

  const tampered = structuredClone(rejection); tampered.decision.entry.evidence.payload.reason = 'CHANGED_LATER';
  write(join(out, 'attacks/tampered.json'), tampered);
  const forged = structuredClone(rejection); forged.decision.entry.evidence.signature = 'AAAA';
  write(join(out, 'attacks/forged-signature.json'), forged);
  write(join(out, 'attacks/deleted-log.json'), system.entries.filter(e => e.index !== decision.index));

  const missing = createSystem(); missing.submit('unanswered', 1500000, now);
  write(join(out, 'attacks/missing-log.json'), missing.entries);
  write(join(out, 'attacks/missing-trust.json'), missing.trust(now + 60));

  // Separate adversarial fixture: the institution signs a false outcome and the witness logs it.
  const liar = createSystem(); const lr = liar.submit('false-approval', 1500000, now); const ld = liar.decide(lr, now + 1);
  ld.evidence = sign('decision', { ...ld.evidence.payload, outcome: 'APPROVED', reason: 'WITHIN_LIMIT' }, liar.keys.institution.privateKey);
  const liarTrust = liar.trust(now + 2);
  write(join(out, 'attacks/wrong-policy-result.json'), liar.bundle(lr, ld, liarTrust));
  write(join(out, 'attacks/wrong-policy-trust.json'), liarTrust);
  writeFileSync(join(out, 'README.txt'), '로컬 모의 시연: 실제 송금 및 온체인 연동 없음.\ncustomer: 고객 보관 증거\nauditor/trust.json: 사전 전달된 신뢰 기준 역할\nwitness: 외부 기록 주체 역할\ninstitution: 기관 저장소 역할 (검증기는 읽지 않음)\nattacks: 공격별 독립 시연 파일\n시각은 진행을 보여주기 위해 몇 초씩 증가시킨 모의 시계입니다.\n실제 운영에서는 각 역할을 별도 환경에서 운영하고 공개키·체크포인트를 독립 경로로 전달해야 합니다.\n');
  const checks = [];
  const check = (name, fn, expected) => {
    let actual;
    try { actual = fn().ok ? 'PASS' : 'DETECTED'; } catch { actual = 'DETECTED'; }
    if (actual !== expected) throw new Error(`DEMO_FAILED: ${name}`);
    checks.push({ name, result: actual });
  };
  check('거절 단건 독립 검증', () => verifySingle(read(join(out, 'customer/rejection.json')), read(join(out, 'auditor/trust.json'))), 'PASS');
  check('승인 단건 검증', () => verifySingle(system.bundle(approvedRequest, approval, trust), trust), 'PASS');
  check('전체 범위 감사', () => audit(system.entries, trust), 'PASS');
  check('사유 변조', () => verifySingle(tampered, trust), 'DETECTED');
  check('서명 위조', () => verifySingle(forged, trust), 'DETECTED');
  check('목록 삭제', () => audit(read(join(out, 'attacks/deleted-log.json')), trust), 'DETECTED');
  check('접수 후 판단 누락', () => audit(missing.entries, missing.trust(now + 60)), 'DETECTED');
  check('기관이 서명한 허위 사유', () => verifySingle(liar.bundle(lr, ld, liarTrust), liarTrust), 'DETECTED');
  return { ok: true, output: out, checks };
}
try {
  const [command, file, trustFile, ...extra] = process.argv.slice(2);
  if (extra.length || (command === 'demo' && trustFile)) throw new Error('INVALID_ARGUMENTS');
  let result;
  if (command === 'demo') result = demo(file);
  else if (command === 'verify' && file && trustFile) result = verifySingle(read(file), read(trustFile));
  else if (command === 'audit' && file && trustFile) result = audit(read(file), read(trustFile));
  else throw new Error('Usage: node src/cli.js demo [new-directory] | verify <bundle.json> <trust.json> | audit <log.json> <trust.json>');
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.ok ? 0 : 1;
} catch (error) {
  console.error(JSON.stringify({ ok: false, error: error.message })); process.exitCode = 1;
}
