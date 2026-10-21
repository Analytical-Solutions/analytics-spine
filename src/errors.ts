export type PackErrorCode =
  | 'PACK_USAGE'
  | 'PACK_SCHEMA_INVALID'
  | 'PACK_PATH_INVALID'
  | 'PACK_STRUCTURE_INVALID'
  | 'PACK_DIGEST_MISMATCH'
  | 'PACK_PLAN_CHANGED'
  | 'PACK_ENGINE_INCOMPATIBLE'
  | 'PACK_SIGNATURE_INVALID'
  | 'PACK_PUBLISHER_UNTRUSTED'
  | 'PACK_KEY_REVOKED';

export class PackError extends Error {
  readonly exitCode: 1 | 2;
  constructor(readonly code: PackErrorCode) {
    super(code);
    this.name = 'PackError';
    this.stack = code;
    this.exitCode = ['PACK_SIGNATURE_INVALID', 'PACK_PUBLISHER_UNTRUSTED', 'PACK_KEY_REVOKED'].includes(code) ? 1 : 2;
  }
}

export function refuse(code: PackErrorCode): never {
  throw new PackError(code);
}
