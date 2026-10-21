import path from 'node:path';
import { createPublicKey, KeyObject, verify } from 'node:crypto';
import { PackError, refuse } from './errors.js';
import { compareVersion, fileDigest, isTextPath, parseJson, rawDigest, semver, serialize, utc } from './json.js';
import { readBounded, relativePath, rootPath, treeFiles } from './filesystem.js';
import { validateSchema } from './schema.js';
import type { Manifest, PackSignature, PublicKey, PublisherTrust, ValidateOptions, ValidatedPack, VerifiedPack, VerifyOptions } from './types.js';

export { PackError } from './errors.js';
export type { PackErrorCode } from './errors.js';
export { canonical, fileDigest, rawDigest, serialize } from './json.js';
export type * from './types.js';

function validateManifest(manifest: Manifest, options: ValidateOptions): void {
  const mode = options.mode ?? 'production';
  if (!['production', 'test'].includes(mode) || mode === 'production' && manifest.classification !== 'curated-commercial') refuse('PACK_SCHEMA_INVALID');
  relativePath(manifest.id);
  semver(manifest.version);
  const low = semver(manifest.engine.minimumVersion), high = semver(manifest.engine.maximumExclusiveVersion);
  if (compareVersion(low, high) >= 0) refuse('PACK_SCHEMA_INVALID');
  if (options.engineVersion !== undefined) {
    const engine = semver(options.engineVersion);
    if (compareVersion(engine, low) < 0 || compareVersion(engine, high) >= 0) refuse('PACK_ENGINE_INCOMPATIBLE');
  }
  let total = 0, previous = '';
  const aliases = new Set<string>();
  for (const file of manifest.files) {
    relativePath(file.path);
    if (aliases.has(file.path.toLowerCase())) refuse('PACK_PATH_INVALID');
    if (file.path <= previous || file.sha256.startsWith('sha256-lf:') !== isTextPath(file.path)) refuse('PACK_SCHEMA_INVALID');
    previous = file.path;
    aliases.add(file.path.toLowerCase());
    total += file.bytes;
  }
  if (total > 64 * 1024 * 1024 || new Set(manifest.claims.map(claim => claim.id)).size !== manifest.claims.length) refuse('PACK_SCHEMA_INVALID');
  for (const notice of manifest.licence.noticePaths) {
    relativePath(notice);
    if (!manifest.files.some(file => file.path === notice && file.role === 'notice')) refuse('PACK_SCHEMA_INVALID');
  }
  if (manifest.files.find(file => file.path === manifest.licence.noticePaths[0])?.sha256 !== manifest.licence.documentDigest) refuse('PACK_SCHEMA_INVALID');
  const references = [
    { digest: manifest.erp.sourceSchemaDigest, role: 'source-map' },
    { digest: manifest.provenance.reviewDigest, role: 'proof-reference' },
    ...Object.entries(manifest.proof).filter(([key]) => key !== 'sourceHead').map(([, digest]) => ({ digest, role: 'proof-reference' })),
  ];
  if (references.some(ref => !manifest.files.some(file => file.sha256 === ref.digest && file.role === ref.role))) refuse('PACK_SCHEMA_INVALID');
}

async function readPack(options: ValidateOptions) {
  try {
    const root = await rootPath(options.packDir);
    const before = await treeFiles(root);
    const manifestBytes = await readBounded(path.join(root, 'manifest.json'), 4 * 1024 * 1024);
    const manifest = await validateSchema<Manifest>('pack-manifest', parseJson(manifestBytes));
    validateManifest(manifest, options);
    // One byte representation makes canonical and hosted raw-byte commitments equal.
    if (!manifestBytes.equals(serialize(manifest))) refuse('PACK_SCHEMA_INVALID');
    const signatureBytes = await readBounded(path.join(root, 'pack-signature.json'), 4 * 1024 * 1024);
    const signature = await validateSchema<PackSignature>('pack-signature', parseJson(signatureBytes));
    if (!signatureBytes.equals(serialize(signature))) refuse('PACK_SCHEMA_INVALID');
    const expected = ['manifest.json', 'pack-signature.json', ...manifest.files.map(file => `payload/${file.path}`)].sort();
    const directories = new Set(['payload']);
    for (const file of manifest.files) {
      let dir = path.posix.dirname(`payload/${file.path}`);
      while (dir !== '.') { directories.add(dir); dir = path.posix.dirname(dir); }
    }
    if (before.files.join('\0') !== expected.join('\0') || before.directories.some(dir => !directories.has(dir))) refuse('PACK_STRUCTURE_INVALID');
    for (const file of manifest.files) {
      const bytes = await readBounded(path.join(root, 'payload', ...file.path.split('/')));
      if (bytes.length !== file.bytes || fileDigest(file.path, bytes) !== file.sha256) refuse('PACK_DIGEST_MISMATCH');
    }
    if ((await treeFiles(root)).snapshot !== before.snapshot) refuse('PACK_PLAN_CHANGED');
    return { manifest, signature, manifestDigest: rawDigest(manifestBytes), signatureDigest: rawDigest(signatureBytes), files: manifest.files };
  } catch (error) {
    if (error instanceof PackError) throw error;
    refuse('PACK_SCHEMA_INVALID');
  }
}

/** Validate a signed distribution's envelope and payload; does not authenticate its publisher. */
export async function validatePack(input: string | ValidateOptions): Promise<ValidatedPack> {
  const result = await readPack(typeof input === 'string' ? { packDir: input } : input);
  return { manifest: result.manifest, manifestDigest: result.manifestDigest, files: result.files };
}

/** Domain-separated, NUL-joined Ed25519 signing message; never a bare digest signature. */
export function signatureMessage(signature: PackSignature): Buffer {
  return Buffer.from(['analytics-spine/domain-pack/v1', signature.manifestDigest, signature.proof.keyId, signature.signedAt].join('\0'), 'utf8');
}

function publicKey(input: PublicKey): KeyObject {
  try {
    if (input instanceof KeyObject) {
      if (input.type !== 'public' || input.asymmetricKeyType !== 'ed25519') refuse('PACK_PUBLISHER_UNTRUSTED');
      return input;
    }
    if (Buffer.from(input).toString('utf8').includes('PRIVATE KEY')) refuse('PACK_PUBLISHER_UNTRUSTED');
    let key: KeyObject;
    if (Buffer.isBuffer(input) && !input.toString('utf8').startsWith('-----BEGIN')) key = createPublicKey({ key: input, type: 'spki', format: 'der' });
    else key = createPublicKey(input);
    if (key.asymmetricKeyType !== 'ed25519') refuse('PACK_PUBLISHER_UNTRUSTED');
    return key;
  } catch { refuse('PACK_PUBLISHER_UNTRUSTED'); }
}

async function trustedKey(trust: unknown, keyId: string, signedAt: string): Promise<KeyObject> {
  const checked = await validateSchema<PublisherTrust>('publisher-trust', trust);
  const keys = new Map<string, { entry: PublisherTrust['keys'][number]; key: KeyObject }>();
  for (const entry of checked.keys) {
    if (keys.has(entry.keyId) || Date.parse(entry.notBefore) >= Date.parse(entry.notAfter)) refuse('PACK_SCHEMA_INVALID');
    const bytes = Buffer.from(entry.publicKeySpki, 'base64');
    if (bytes.toString('base64') !== entry.publicKeySpki || rawDigest(bytes) !== entry.keyId) refuse('PACK_SCHEMA_INVALID');
    const key = publicKey(bytes);
    if (!key.export({ type: 'spki', format: 'der' }).equals(bytes)) refuse('PACK_SCHEMA_INVALID');
    keys.set(entry.keyId, { entry, key });
  }
  const selected = keys.get(keyId);
  if (!selected) refuse('PACK_PUBLISHER_UNTRUSTED');
  if (selected.entry.state === 'revoked') refuse('PACK_KEY_REVOKED');
  if (Date.parse(signedAt) < Date.parse(selected.entry.notBefore) || Date.parse(signedAt) >= Date.parse(selected.entry.notAfter)) refuse('PACK_SIGNATURE_INVALID');
  return selected.key;
}

export function verifyPack(dir: string, publicKey: PublicKey): Promise<VerifiedPack>;
export function verifyPack(options: VerifyOptions): Promise<VerifiedPack>;
export async function verifyPack(input: string | VerifyOptions, keyInput?: PublicKey): Promise<VerifiedPack> {
  try {
    const options = typeof input === 'string' ? { packDir: input } : input;
    const result = await readPack(options);
    const { signature } = result;
    const now = typeof input === 'string' ? new Date().toISOString() : input.now;
    if (!utc(now)) refuse('PACK_SCHEMA_INVALID');
    if (signature.manifestDigest !== result.manifestDigest || Date.parse(signature.signedAt) > Date.parse(now)) refuse('PACK_SIGNATURE_INVALID');
    let key: KeyObject;
    if (typeof input === 'string') {
      if (keyInput === undefined) refuse('PACK_PUBLISHER_UNTRUSTED');
      key = publicKey(keyInput);
      if (rawDigest(key.export({ type: 'spki', format: 'der' })) !== signature.proof.keyId) refuse('PACK_PUBLISHER_UNTRUSTED');
    } else key = await trustedKey(input.trust, signature.proof.keyId, signature.signedAt);
    const proof = Buffer.from(signature.proof.proofBytes, 'base64');
    if (proof.length !== 64 || proof.toString('base64') !== signature.proof.proofBytes || !verify(null, signatureMessage(signature), key, proof)) refuse('PACK_SIGNATURE_INVALID');
    return result;
  } catch (error) {
    if (error instanceof PackError) throw error;
    refuse('PACK_SIGNATURE_INVALID');
  }
}
