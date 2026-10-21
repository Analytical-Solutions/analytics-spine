import { createHash } from 'node:crypto';
import path from 'node:path';
import { refuse } from './errors.js';

export function rawDigest(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

const textExtensions = new Set(['.json', '.md', '.sql', '.py', '.tmdl', '.pbir', '.pbism', '.pbip', '.platform', '.dax', '.csv', '.txt', '.html', '.mjs', '.js', '.ipynb', '.yml', '.yaml', '.toml', '.xml', '.svg']);
export function isTextPath(file: string): boolean {
  const name = path.posix.basename(file).toLowerCase();
  return textExtensions.has(path.posix.extname(name) || (name.startsWith('.') ? name : ''));
}
export function fileDigest(file: string, input: Uint8Array): string {
  const bytes = Buffer.from(input);
  return isTextPath(file)
    ? rawDigest(Buffer.from(bytes.toString('latin1').replaceAll('\r\n', '\n'), 'latin1')).replace('sha256:', 'sha256-lf:')
    : rawDigest(bytes);
}

export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) refuse('PACK_SCHEMA_INVALID');
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map(key => `${canonical(key)}:${canonical(object[key])}`).join(',')}}`;
  }
  if (typeof value === 'string' && /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) refuse('PACK_SCHEMA_INVALID');
  if (typeof value === 'number' && !Number.isFinite(value)) refuse('PACK_SCHEMA_INVALID');
  if (value !== null && !['string', 'number', 'boolean'].includes(typeof value)) refuse('PACK_SCHEMA_INVALID');
  return JSON.stringify(value);
}

/** Ordinal object keys, preserved arrays, UTF-8, exactly one terminal LF. */
export function serialize(value: unknown): Buffer {
  return Buffer.from(`${canonical(value)}\n`, 'utf8');
}

/** JSON.parse checks syntax; the token walk additionally rejects decoded duplicate keys. */
export function parseJson(bytes: Uint8Array, versioned = true): unknown {
  try {
    if (bytes.byteLength > 4 * 1024 * 1024) refuse('PACK_SCHEMA_INVALID');
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const value: unknown = JSON.parse(text);
    const tokens = text.match(/"(?:\\.|[^"\\])*"|[{}\[\]:,]|[^\s{}\[\]:,]+/g) ?? [];
    let index = 0;
    const visit = (depth: number): void => {
      if (depth > 64) refuse('PACK_SCHEMA_INVALID');
      const token = tokens[index++];
      if (token === '{') {
        const keys = new Set<string>();
        while (tokens[index] !== '}') {
          const key: string = JSON.parse(tokens[index++]!);
          if (keys.has(key)) refuse('PACK_SCHEMA_INVALID');
          keys.add(key);
          index++;
          if (versioned && key === 'schemaVersion' && tokens[index] !== '1') refuse('PACK_SCHEMA_INVALID');
          visit(depth + 1);
          if (tokens[index] === ',') index++;
        }
        index++;
      } else if (token === '[') {
        while (tokens[index] !== ']') {
          visit(depth + 1);
          if (tokens[index] === ',') index++;
        }
        index++;
      }
    };
    visit(0);
    canonical(value);
    return value;
  } catch { refuse('PACK_SCHEMA_INVALID'); }
}

export function utc(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 19) === value.slice(0, 19);
}

export function semver(value: string): number[] {
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) refuse('PACK_SCHEMA_INVALID');
  const tuple = value.split('.').map(Number);
  if (!tuple.every(Number.isSafeInteger)) refuse('PACK_SCHEMA_INVALID');
  return tuple;
}
export function compareVersion(a: number[], b: number[]): number {
  return a[0]! - b[0]! || a[1]! - b[1]! || a[2]! - b[2]!;
}
