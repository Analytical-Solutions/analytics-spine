import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../', import.meta.url)));
const runGit = args => {
  const result = spawnSync('git', args, { cwd: root, windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('SCAN_GIT_FAILED');
  return result.stdout;
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
// Patterns are assembled so the policy can scan its own source without exemptions.
const rules = [
  ['private-key', ['-----BEGIN ', '(?:[A-Z0-9]+ )*PRIVATE KEY-----'].join('')],
  ['github-token', ['\\bgh', '[opusr]_[A-Za-z0-9]{20,}\\b'].join('')],
  ['github-fine-token', ['github_', 'pat_[A-Za-z0-9_]{20,}'].join('')],
  ['cloud-access-key', ['\\b(?:AK', 'IA|ASIA)[A-Z0-9]{16}\\b'].join('')],
  ['service-token', ['\\b(?:sk', '-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,})\\b'].join('')],
  ['credential-url', ['https?://[^\\s/:]+:', '[^\\s/@]+@'].join('')],
  ['credential-assignment', ['(?:password|api[_-]?key|access[_-]?token|client[_-]?secret)\\s*[=:]\\s*["\x27]', '[^"\x27\\r\\n]{8,}["\x27]'].join('')],
  ['signed-token', ['\\beyJ[A-Za-z0-9_-]{8,}\\.', '[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b'].join('')],
  ['private-repository-path', ['(?:agent', '-skills|analytical[ -]ants[\\\\/])'].join('')],
  ['private-workspace', ['(?:[A-Z]:[\\\\/](?:Users|t3|Temp)[\\\\/]|/', 'home/[^/\\s]+/|/', 'Users/[^/\\s]+/)'].join('')],
  ['internal-host', ['\\b(?:[A-Za-z0-9-]+\\.)+', '(?:internal|corp|local)\\b'].join('')],
  ['sensitive-data-field', ['["\x27](?:tenant[_-]?id|customer[_-]?id|customerValues|rowValues|valueRows)', '["\x27]\\s*:'].join('')],
].map(([id, pattern]) => [id, new RegExp(pattern, 'i')]);
const findings = [];
let checked = 0;
const scan = (bytes, surface) => {
  checked++;
  const text = bytes.toString('utf8');
  for (const [rule, pattern] of rules) if (pattern.test(text)) findings.push({ rule, surface, sha256: hash(bytes) });
  // This source-only repository has no binary assets. Permit Git's path separators
  // in metadata, but fail unexpected binary content instead of silently ignoring it.
  if (!surface.endsWith('-paths') && bytes.includes(0)) findings.push({ rule: 'binary-content', surface, sha256: hash(bytes) });
};

try {
  const visit = async dir => {
    for (const name of (await readdir(dir)).sort()) {
      if (dir === root && ['.git', 'node_modules', '.scan-receipt.json'].includes(name)) continue;
      const full = path.join(dir, name);
      const stat = await lstat(full);
      scan(Buffer.from(path.relative(root, full).replaceAll('\\', '/')), 'tree-paths');
      if (stat.isSymbolicLink() || !stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1)) throw new Error('SCAN_UNSAFE_PATH');
      if (stat.isDirectory()) await visit(full);
      else scan(await readFile(full), 'working-tree');
    }
  };
  // Normalize trailing separator, so exclusions apply on every platform.
  await visit(path.resolve(root));
  const refs = runGit(['for-each-ref', '--format=%(refname)']);
  scan(refs, 'git-ref-paths');
  const inventory = runGit(['rev-list', '--objects', '--all']).toString('utf8').trim().split(/\r?\n/).filter(Boolean);
  scan(Buffer.from(inventory.map(row => row.slice(row.indexOf(' ') + 1)).join('\n')), 'git-object-paths');
  let blobs = 0, metadata = 0;
  for (const row of inventory) {
    const oid = row.split(' ')[0];
    const type = runGit(['cat-file', '-t', oid]).toString('utf8').trim();
    if (type === 'blob') { scan(runGit(['cat-file', 'blob', oid]), 'git-blob'); blobs++; }
    if (type === 'commit' || type === 'tag') { scan(runGit(['cat-file', '-p', oid]), 'git-metadata'); metadata++; }
  }
  const result = { result: findings.length ? 'FAIL' : 'PASS', checked, reachableBlobs: blobs, metadataObjects: metadata, findings };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = findings.length ? 1 : 0;
} catch {
  process.stderr.write('SCAN_INCOMPLETE\n');
  process.exitCode = 2;
}
