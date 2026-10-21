import { readFile } from 'node:fs/promises';
import { canonical, parseJson, utc } from './json.js';
import { refuse } from './errors.js';

interface Schema {
  type?: string;
  const?: unknown;
  enum?: unknown[];
  required?: string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean;
  items?: Schema;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
}

// Implements exactly the vocabulary used by the three bundled, closed schemas.
// This is not an API for evaluating arbitrary third-party schemas.
function check(schema: Schema, value: unknown): void {
  if (Object.hasOwn(schema, 'const') && canonical(schema.const) !== canonical(value)) refuse('PACK_SCHEMA_INVALID');
  if (schema.enum && !schema.enum.includes(value)) refuse('PACK_SCHEMA_INVALID');
  if (schema.type === 'object') {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse('PACK_SCHEMA_INVALID');
    const object = value as Record<string, unknown>;
    if (schema.required?.some(key => !Object.hasOwn(object, key))) refuse('PACK_SCHEMA_INVALID');
    for (const key of Object.keys(object)) {
      if (schema.additionalProperties === false && !Object.hasOwn(schema.properties ?? {}, key)) refuse('PACK_SCHEMA_INVALID');
      if (schema.properties?.[key]) check(schema.properties[key], object[key]);
    }
  } else if (schema.type === 'array') {
    if (!Array.isArray(value) || value.length < (schema.minItems ?? 0) || value.length > (schema.maxItems ?? Infinity)) refuse('PACK_SCHEMA_INVALID');
    if (schema.uniqueItems && new Set(value.map(canonical)).size !== value.length) refuse('PACK_SCHEMA_INVALID');
    for (const item of value) check(schema.items ?? {}, item);
  } else if (schema.type === 'string') {
    if (typeof value !== 'string' || [...value].length < (schema.minLength ?? 0) || [...value].length > (schema.maxLength ?? Infinity)
      || schema.pattern && !new RegExp(schema.pattern, 'u').test(value) || schema.format === 'date-time' && !utc(value)) refuse('PACK_SCHEMA_INVALID');
  } else if (schema.type === 'integer') {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity)) refuse('PACK_SCHEMA_INVALID');
  }
}

export async function validateSchema<T>(name: 'pack-manifest' | 'pack-signature' | 'publisher-trust', value: unknown): Promise<T> {
  const bytes = await readFile(new URL(`../schemas/${name}.schema.json`, import.meta.url));
  check(parseJson(bytes, false) as Schema, value);
  return value as T;
}
