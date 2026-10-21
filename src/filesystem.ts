import { lstat, open, readdir, realpath } from 'node:fs/promises';
import type { BigIntStats } from 'node:fs';
import path from 'node:path';
import { PackError, refuse } from './errors.js';

const identity = (stat: BigIntStats): string => [stat.dev, stat.ino, stat.mode, stat.size, stat.mtimeNs, stat.ctimeNs, stat.nlink].join(':');
const fold = (value: string): string => process.platform === 'win32' ? value.toLowerCase() : value;

export function relativePath(value: string): void {
  if (!value || value.length > 2048 || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)
    || value.split('/').length > 64 || value.split('/').some(part => !/^[A-Za-z0-9._-]+$/.test(part)
      || part === '.' || part === '..' || /[.]$/.test(part) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) refuse('PACK_PATH_INVALID');
}

/** Inspect every ancestor, so a symlink/junction outside the pack is refused too. */
async function inspect(file: string): Promise<{ absolute: string; stat: BigIntStats; chain: string[] }> {
  try {
    const absolute = path.resolve(file);
    const root = path.parse(absolute).root;
    let current = root;
    const parts = path.relative(root, absolute).split(path.sep).filter(Boolean);
    const chain: string[] = [];
    let stat = await lstat(root, { bigint: true });
    for (const part of parts) {
      const names = await readdir(current);
      if (!names.includes(part) || names.filter(name => name.toLowerCase() === part.toLowerCase()).length !== 1) refuse('PACK_PATH_INVALID');
      current = path.join(current, part);
      stat = await lstat(current, { bigint: true });
      if (stat.isSymbolicLink() || !stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1n)) refuse('PACK_PATH_INVALID');
      chain.push(`${stat.dev}:${stat.ino}`);
    }
    if (fold(await realpath(absolute)) !== fold(absolute)) refuse('PACK_PATH_INVALID');
    return { absolute, stat, chain };
  } catch (error) {
    if (error instanceof PackError) throw error;
    refuse('PACK_PATH_INVALID');
  }
}

export async function rootPath(dir: string): Promise<string> {
  const result = await inspect(dir);
  if (!result.stat.isDirectory()) refuse('PACK_PATH_INVALID');
  return result.absolute;
}

export async function readBounded(file: string, maximum = 16 * 1024 * 1024): Promise<Buffer> {
  const before = await inspect(file);
  if (!before.stat.isFile() || before.stat.size > BigInt(maximum)) refuse('PACK_PATH_INVALID');
  const expected = identity(before.stat);
  const handle = await open(before.absolute, 'r').catch(() => refuse('PACK_PATH_INVALID'));
  try {
    if (identity(await handle.stat({ bigint: true })) !== expected) refuse('PACK_PLAN_CHANGED');
    const size = Number(before.stat.size);
    const bytes = Buffer.alloc(size + 1);
    let count = 0;
    while (count < bytes.length) {
      const read = await handle.read(bytes, count, bytes.length - count, count);
      if (!read.bytesRead) break;
      count += read.bytesRead;
    }
    const after = await inspect(file);
    if (count !== size || identity(await handle.stat({ bigint: true })) !== expected || identity(after.stat) !== expected
      || before.chain.join('/') !== after.chain.join('/')) refuse('PACK_PLAN_CHANGED');
    return bytes.subarray(0, count);
  } catch (error) {
    if (error instanceof PackError) throw error;
    refuse('PACK_PATH_INVALID');
  } finally { await handle.close(); }
}

export interface Tree {
  files: string[];
  directories: string[];
  snapshot: string;
}
export async function treeFiles(root: string): Promise<Tree> {
  const files: string[] = [], directories: string[] = [], rows: string[] = [];
  let count = 0;
  const walk = async (dir: string, prefix: string, depth: number): Promise<void> => {
    if (depth > 64) refuse('PACK_PATH_INVALID');
    const parent = await inspect(dir);
    rows.push(`${prefix}:${identity(parent.stat)}`);
    const entries = await readdir(dir);
    const aliases = new Set<string>();
    for (const name of entries.sort()) {
      if (++count > 8192) refuse('PACK_STRUCTURE_INVALID');
      relativePath(name);
      const alias = name.toLowerCase();
      if (aliases.has(alias)) refuse('PACK_PATH_INVALID');
      aliases.add(alias);
      const relative = prefix ? `${prefix}/${name}` : name;
      relativePath(relative);
      const full = path.join(dir, name);
      const { stat } = await inspect(full);
      if (stat.isDirectory()) {
        directories.push(relative);
        await walk(full, relative, depth + 1);
      } else {
        if (stat.size > 16n * 1024n * 1024n) refuse('PACK_STRUCTURE_INVALID');
        files.push(relative);
        rows.push(`${relative}:${identity(stat)}`);
      }
    }
  };
  await walk(root, '', 0);
  return { files: files.sort(), directories: directories.sort(), snapshot: rows.join('\0') };
}
