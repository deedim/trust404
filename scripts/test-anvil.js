import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit' });

  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

try {
  console.log('[1/2] 계약 빌드');
  run('forge', ['build', '--offline'], join(root, 'contracts'));

  console.log('[2/2] 실제 Anvil 실행 및 통합 테스트');
  run(process.execPath, [
    '--test',
    '--test-reporter=spec',
    '--test-concurrency=1',
    'test/anvil.test.js',
  ]);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
