#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { PackError, refuse } from './errors.js';
import { validatePack, verifyPack } from './index.js';

try {
  const [command, dir, ...args] = process.argv.slice(2);
  if (!dir || dir.startsWith('-')) refuse('PACK_USAGE');
  let result;
  if (command === 'validate' && args.length === 0) result = await validatePack(dir);
  else if (command === 'verify' && args.length === 2 && args[0] === '--key' && args[1] && !args[1].startsWith('-')) {
    const key = await readFile(args[1]).catch(() => refuse('PACK_PUBLISHER_UNTRUSTED'));
    result = await verifyPack(dir, key);
  } else refuse('PACK_USAGE');
  process.stdout.write(`${JSON.stringify({ valid: true, manifestDigest: result.manifestDigest })}\n`);
} catch (error) {
  const safe = error instanceof PackError ? error : new PackError('PACK_SCHEMA_INVALID');
  process.stderr.write(`${safe.code}\n`);
  process.exitCode = safe.exitCode;
}
