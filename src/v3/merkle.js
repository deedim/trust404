import { canonical, sha, check, hashShape } from './crypto.js';

const leaf = value => sha(Buffer.concat([Buffer.from([0]), Buffer.from(canonical(value))]));
const branch = (l, r) => sha(Buffer.concat([Buffer.from([1]), Buffer.from(l.slice(2), 'hex'), Buffer.from(r.slice(2), 'hex')]));
const split = n => 2 ** Math.floor(Math.log2(n - 1));

export function buildTree(records) {
  check(Array.isArray(records) && records.length > 0 && records.length <= 32, 'INVALID_BATCH_SIZE');
  const frozen = JSON.parse(canonical(records));
  function build(start, size) {
    if (size === 1) return { hash: leaf(frozen[start]), start, size };
    const k = split(size), left = build(start, k), right = build(start + k, size - k);
    return { hash: branch(left.hash, right.hash), start, size, left, right };
  }
  const tree = build(0, frozen.length);
  return {
    root: tree.hash, count: frozen.length,
    proof(index) {
      check(Number.isInteger(index) && index >= 0 && index < frozen.length, 'INVALID_INDEX');
      function walk(node) {
        if (node.size === 1) return [];
        return index < node.right.start
          ? [...walk(node.left), { side: 'right', hash: node.right.hash }]
          : [...walk(node.right), { side: 'left', hash: node.left.hash }];
      }
      return walk(tree);
    },
  };
}
export function verifyProof(record, index, count, proof, root) {
  check(Number.isInteger(count) && count > 0 && count <= 32 && Number.isInteger(index) && index >= 0 && index < count,
    'INVALID_INCLUSION');
  check(Array.isArray(proof) && hashShape(root), 'INVALID_INCLUSION');
  function directions(i, n) {
    if (n === 1) return [];
    const k = split(n);
    return i < k ? [...directions(i, k), 'right'] : [...directions(i - k, n - k), 'left'];
  }
  const sides = directions(index, count);
  check(proof.length === sides.length, 'INVALID_INCLUSION');
  let h = leaf(record);
  for (let i = 0; i < proof.length; i++) {
    const p = proof[i];
    check(p && p.side === sides[i] && hashShape(p.hash), 'INVALID_INCLUSION');
    h = p.side === 'left' ? branch(p.hash, h) : branch(h, p.hash);
  }
  check(h === root, 'INVALID_INCLUSION');
}
