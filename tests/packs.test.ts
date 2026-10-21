import { generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { cp, link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fileDigest, PackError, rawDigest, serialize, signatureMessage, validatePack, verifyPack } from '../src/index.js';
import type { Manifest, PackSignature, PublisherTrust } from '../src/index.js';

const fixtureDir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const repo = fileURLToPath(new URL('../', import.meta.url));
const negative = JSON.parse(await readFile(path.join(fixtureDir, 'negative-cases.json'), 'utf8')) as {
  tamperedPayload: string; unsafePaths: string[]; badSignature: string; unknownField: string;
  symlinkName: string; unknownKeyResult: string; duplicateKeyJson: string; escapedDuplicateKeyJson: string;
};
const now = '2026-02-01T00:00:00Z';

describe('offline pack boundary', () => {
  let temp: string, dir: string, manifest: Manifest, signature: PackSignature, trust: PublisherTrust;
  let keys: ReturnType<typeof generateKeyPairSync>;

  beforeEach(async () => {
    temp = await mkdtemp(path.join(tmpdir(), 'spine-pack-test-'));
    dir = path.join(temp, 'pack');
    await cp(path.join(fixtureDir, 'valid'), dir, { recursive: true });
    manifest = JSON.parse(await readFile(path.join(dir, 'manifest.json'), 'utf8')) as Manifest;
    // Disposable keys stay in memory. Only public SPKI and signature bytes reach disk.
    keys = generateKeyPairSync('ed25519');
    const publicDer = keys.publicKey.export({ type: 'spki', format: 'der' });
    signature = JSON.parse(await readFile(path.join(fixtureDir, 'signature-template.json'), 'utf8')) as PackSignature;
    signature.manifestDigest = rawDigest(await readFile(path.join(dir, 'manifest.json')));
    signature.proof.keyId = rawDigest(publicDer);
    signature.proof.proofBytes = sign(null, signatureMessage(signature), keys.privateKey).toString('base64');
    await writeFile(path.join(dir, 'pack-signature.json'), serialize(signature));
    trust = { kind: 'analytics-spine-pack-publisher-trust', schemaVersion: 1, keys: [{
      keyId: signature.proof.keyId, publicKeySpki: publicDer.toString('base64'), notBefore: '2025-01-01T00:00:00Z',
      notAfter: '2027-01-01T00:00:00Z', state: 'active',
    }] };
  });
  afterEach(async () => { await rm(temp, { recursive: true, force: true }); });

  const options = () => ({ packDir: dir, engineVersion: '2.0.0', mode: 'production' as const });
  const verification = () => ({ ...options(), trust, now });
  const writeManifest = async () => { await writeFile(path.join(dir, 'manifest.json'), serialize(manifest)); };
  const writeSignature = async () => { await writeFile(path.join(dir, 'pack-signature.json'), serialize(signature)); };

  it('validates literal fixture digests and verifies a runtime signature through both APIs', async () => {
    const validated = await validatePack(dir);
    expect(validated.manifest).toEqual(manifest);
    expect(validated.manifestDigest).toBe(rawDigest(await readFile(path.join(dir, 'manifest.json'))));
    const direct = await verifyPack(dir, keys.publicKey);
    const hosted = await verifyPack(verification());
    expect(hosted).toEqual(direct);
    expect(hosted.files.map(file => file.path)).toEqual(['notice.txt', 'proof.json', 'source.json']);
    expect(hosted.signatureDigest).toBe(rawDigest(await readFile(path.join(dir, 'pack-signature.json'))));
    expect(await validatePack(options())).toEqual(validated);
    // Consumer contract, expressed independently without importing any host code.
    const loader: {
      fileDigest: (file: string, bytes: Buffer) => string;
      validatePack: (input: { packDir: string; engineVersion: string; mode: 'production' | 'test' }) => Promise<{ manifest: { id: string; version: string }; manifestDigest: string; files: { path: string; sha256: string; bytes: number; role: string }[] }>;
      verifyPack: (input: { packDir: string; engineVersion: string; mode: 'production' | 'test'; trust: unknown; now: string }) => Promise<{ manifestDigest: string; signatureDigest: string }>;
    } = { fileDigest, validatePack, verifyPack };
    expect((await loader.verifyPack(verification())).manifestDigest).toBe(validated.manifestDigest);
  });

  it.each(['DER', 'PEM string', 'PEM Buffer', 'PEM with surrounding whitespace', 'PEM Buffer with CRLF and whitespace'] as const)('accepts one complete Ed25519 public key: %s', async encoding => {
    const der = keys.publicKey.export({ type: 'spki', format: 'der' });
    const pem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const inputs = {
      DER: der,
      'PEM string': pem,
      'PEM Buffer': Buffer.from(pem),
      'PEM with surrounding whitespace': ' \t\r\n' + pem + '\r\n \t',
      'PEM Buffer with CRLF and whitespace': Buffer.from(' \t\r\n' + pem.replaceAll('\n', '\r\n') + '\r\n \t'),
    };
    expect((await verifyPack(dir, inputs[encoding])).manifest.version).toBe('1.0.0');
  });

  it.each([
    'DER followed by junk', 'concatenated DER keys', 'PEM followed by junk', 'PEM Buffer followed by junk',
    'PEM preceded by junk', 'concatenated PEM keys', 'PEM containing DER followed by junk',
    'PEM containing concatenated DER keys', 'PEM with invalid base64', 'PEM with a missing end marker', 'raw 32-byte key',
  ] as const)('refuses incomplete or multiple public-key encodings: %s', async encoding => {
    const der = keys.publicKey.export({ type: 'spki', format: 'der' });
    const pem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const secondDer = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });
    const wrap = (bytes: Buffer) => '-----BEGIN PUBLIC KEY-----\n' + bytes.toString('base64') + '\n-----END PUBLIC KEY-----\n';
    const inputs = {
      'DER followed by junk': Buffer.concat([der, Buffer.from('junk')]),
      'concatenated DER keys': Buffer.concat([der, secondDer]),
      'PEM followed by junk': pem + 'junk',
      'PEM Buffer followed by junk': Buffer.from(pem + 'junk'),
      'PEM preceded by junk': 'junk\n' + pem,
      'concatenated PEM keys': pem + pem,
      'PEM containing DER followed by junk': wrap(Buffer.concat([der, Buffer.from('junk')])),
      'PEM containing concatenated DER keys': wrap(Buffer.concat([der, secondDer])),
      'PEM with invalid base64': pem.replace('\n', '\n!'),
      'PEM with a missing end marker': pem.replace('-----END PUBLIC KEY-----', ''),
      'raw 32-byte key': der.subarray(-32),
    };
    await expect(verifyPack(dir, inputs[encoding])).rejects.toMatchObject({
      code: 'PACK_PUBLISHER_UNTRUSTED', message: 'PACK_PUBLISHER_UNTRUSTED', stack: 'PACK_PUBLISHER_UNTRUSTED', exitCode: 1,
    });
  });

  it.each(['junk', 'second key'] as const)('refuses trailing trust-key DER bytes with the existing schema error: %s', async suffix => {
    const der = keys.publicKey.export({ type: 'spki', format: 'der' });
    const bytes = Buffer.concat([der, suffix === 'junk' ? Buffer.from('junk') : der]);
    trust.keys[0]!.publicKeySpki = bytes.toString('base64');
    trust.keys[0]!.keyId = rawDigest(bytes);
    await expect(verifyPack(verification())).rejects.toMatchObject({
      code: 'PACK_SCHEMA_INVALID', message: 'PACK_SCHEMA_INVALID', stack: 'PACK_SCHEMA_INVALID', exitCode: 2,
    });
  });

  it.each(['KeyObject', 'DER', 'PEM'] as const)('refuses a non-Ed25519 key through both APIs: %s', async encoding => {
    const other = generateKeyPairSync('x25519').publicKey;
    const der = other.export({ type: 'spki', format: 'der' });
    signature.proof.keyId = rawDigest(der);
    signature.proof.proofBytes = sign(null, signatureMessage(signature), keys.privateKey).toString('base64');
    await writeSignature();
    trust.keys[0]!.keyId = signature.proof.keyId;
    trust.keys[0]!.publicKeySpki = der.toString('base64');
    const inputs = { KeyObject: other, DER: der, PEM: other.export({ type: 'spki', format: 'pem' }) };
    await expect(verifyPack(dir, inputs[encoding])).rejects.toMatchObject({
      code: 'PACK_PUBLISHER_UNTRUSTED', message: 'PACK_PUBLISHER_UNTRUSTED', stack: 'PACK_PUBLISHER_UNTRUSTED', exitCode: 1,
    });
    await expect(verifyPack(verification())).rejects.toMatchObject({
      code: 'PACK_PUBLISHER_UNTRUSTED', message: 'PACK_PUBLISHER_UNTRUSTED', stack: 'PACK_PUBLISHER_UNTRUSTED', exitCode: 1,
    });
  });

  it('uses a fixed signature message vector and CRLF-only digest vectors', () => {
    const vector = { ...signature, manifestDigest: 'digest', signedAt: 'clock', proof: { ...signature.proof, keyId: 'key' } };
    expect(signatureMessage(vector).toString()).toBe('analytics-spine/domain-pack/v1\0digest\0key\0clock');
    expect(fileDigest('x.TXT', Buffer.from('a\r\nb\rc\n'))).toBe('sha256-lf:6f52afe4d39e9cf2a7c126277dd775264d5d47ac6af9ed8c6d2040c1839c45aa');
    expect(fileDigest('x.bin', Buffer.from('a\r\nb\rc\n'))).toBe(rawDigest(Buffer.from('a\r\nb\rc\n')));
  });

  it('refuses tampered payload before accepting a valid publisher signature', async () => {
    await writeFile(path.join(dir, 'payload', 'notice.txt'), negative.tamperedPayload);
    await expect(verifyPack(verification())).rejects.toMatchObject({ code: 'PACK_DIGEST_MISMATCH' });
  });

  it.each(negative.unsafePaths)('refuses unsafe manifest path %s', async unsafe => {
    manifest.files[0]!.path = unsafe;
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_PATH_INVALID' });
  });

  it('refuses a payload symlink/junction pointing outside the pack', async () => {
    const outside = path.join(temp, 'outside');
    await mkdir(outside);
    await writeFile(path.join(outside, 'example.txt'), 'synthetic outside file');
    await symlink(outside, path.join(dir, 'payload', negative.symlinkName), process.platform === 'win32' ? 'junction' : 'dir');
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_PATH_INVALID' });
    expect(await readFile(path.join(outside, 'example.txt'), 'utf8')).toBe('synthetic outside file');
  });

  it('refuses a symlink/junction in the pack root ancestor chain', async () => {
    const alias = path.join(temp, 'alias');
    await symlink(dir, alias, process.platform === 'win32' ? 'junction' : 'dir');
    await expect(validatePack(alias)).rejects.toMatchObject({ code: 'PACK_PATH_INVALID' });
  });

  it('refuses hardlinked payload files', async () => {
    const target = path.join(dir, 'payload', 'notice.txt');
    await link(target, path.join(temp, 'hardlink.txt'));
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_PATH_INVALID' });
  });

  it('refuses a bad signature, wrong key and absent key', async () => {
    signature.proof.proofBytes = negative.badSignature;
    await writeSignature();
    await expect(verifyPack(verification())).rejects.toMatchObject({ code: 'PACK_SIGNATURE_INVALID' });
    const wrong = generateKeyPairSync('ed25519').publicKey;
    await expect(verifyPack(dir, wrong)).rejects.toMatchObject({ code: negative.unknownKeyResult });
    await expect(verifyPack({ ...verification(), trust: { ...trust, keys: [] } })).rejects.toMatchObject({ code: 'PACK_PUBLISHER_UNTRUSTED' });
  });

  it('refuses a signature for a different manifest even when payload digests still match', async () => {
    manifest.version = '1.0.1';
    await writeManifest();
    await expect(verifyPack(verification())).rejects.toMatchObject({ code: 'PACK_SIGNATURE_INVALID' });
  });

  it('enforces key revocation and retired signing intervals', async () => {
    trust.keys[0]!.state = 'revoked';
    await expect(verifyPack(verification())).rejects.toMatchObject({ code: 'PACK_KEY_REVOKED' });
    trust.keys[0]!.state = 'retired';
    await expect(verifyPack(verification())).resolves.toMatchObject({ manifestDigest: signature.manifestDigest });
    trust.keys[0]!.notBefore = signature.signedAt;
    await expect(verifyPack(verification())).resolves.toBeDefined();
    trust.keys[0]!.notBefore = '2025-01-01T00:00:00Z';
    trust.keys[0]!.notAfter = signature.signedAt;
    await expect(verifyPack(verification())).rejects.toMatchObject({ code: 'PACK_SIGNATURE_INVALID' });
  });

  it('refuses duplicate or mismatched publisher trust keys', async () => {
    trust.keys.push({ ...trust.keys[0]! });
    await expect(verifyPack(verification())).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
    trust.keys.pop();
    trust.keys[0]!.keyId = `sha256:${'1'.repeat(64)}`;
    await expect(verifyPack(verification())).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it('refuses future signatures and invalid calendar timestamps', async () => {
    await expect(verifyPack({ ...verification(), now: '2025-12-31T23:59:59Z' })).rejects.toMatchObject({ code: 'PACK_SIGNATURE_INVALID' });
    signature.signedAt = '2026-02-30T00:00:00Z';
    await writeSignature();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it('refuses unknown nested members and incorrect schema versions', async () => {
    (manifest.erp as unknown as Record<string, unknown>)[negative.unknownField] = true;
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it.each([negative.duplicateKeyJson, negative.escapedDuplicateKeyJson, '{"schemaVersion":1.0}', '{"schemaVersion":1e0}', '{"schemaVersion":2}', '{"x":1e999}', '{"x":"\\ud800"}'])('refuses ambiguous or invalid JSON %s', async text => {
    await writeFile(path.join(dir, 'manifest.json'), text);
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it('refuses noncanonical manifest bytes and malformed signature envelope', async () => {
    await writeFile(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
    await writeManifest();
    (signature as unknown as Record<string, unknown>).extra = true;
    await writeSignature();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it('refuses extra files, empty directories and missing signature', async () => {
    await writeFile(path.join(dir, 'extra.txt'), 'example');
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_STRUCTURE_INVALID' });
    await rm(path.join(dir, 'extra.txt'));
    await mkdir(path.join(dir, 'empty'));
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_STRUCTURE_INVALID' });
    await rm(path.join(dir, 'empty'), { recursive: true });
    await rm(path.join(dir, 'pack-signature.json'));
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_PATH_INVALID' });
  });

  it('refuses case aliases, unsorted file lists and wrong digest domains', async () => {
    manifest.files[1]!.path = 'NOTICE.TXT';
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_PATH_INVALID' });
    manifest = JSON.parse(await readFile(path.join(fixtureDir, 'valid/manifest.json'), 'utf8')) as Manifest;
    manifest.files.reverse();
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
    manifest.files.reverse();
    manifest.files[0]!.sha256 = manifest.files[0]!.sha256.replace('sha256-lf:', 'sha256:');
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it('checks reference bindings and per-file size limits', async () => {
    manifest.erp.sourceSchemaDigest = `sha256-lf:${'0'.repeat(64)}`;
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
    manifest.erp.sourceSchemaDigest = manifest.files[2]!.sha256;
    manifest.files[0]!.bytes = 16777217;
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it('compares numeric engine ranges, including the exclusive upper bound', async () => {
    await expect(validatePack({ ...options(), engineVersion: '2.10.0' })).resolves.toBeDefined();
    await expect(validatePack({ ...options(), engineVersion: '3.0.0' })).rejects.toMatchObject({ code: 'PACK_ENGINE_INCOMPATIBLE' });
    await expect(validatePack({ ...options(), engineVersion: '0.9.0' })).rejects.toMatchObject({ code: 'PACK_ENGINE_INCOMPATIBLE' });
    await expect(validatePack({ ...options(), engineVersion: '9007199254740992.0.0' })).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
  });

  it('accepts public fixtures only in explicit test mode', async () => {
    manifest.classification = 'public-fixture';
    await writeManifest();
    await expect(validatePack(dir)).rejects.toMatchObject({ code: 'PACK_SCHEMA_INVALID' });
    await expect(validatePack({ ...options(), mode: 'test' })).resolves.toBeDefined();
  });

  it('keeps CLI success/error output fixed and handles PEM/DER public keys', async () => {
    const cli = (...args: string[]) => spawnSync(process.execPath, ['dist/cli.js', ...args], { cwd: repo, encoding: 'utf8', windowsHide: true });
    const before = await readFile(path.join(dir, 'manifest.json'));
    const validated = cli('validate', dir);
    expect(validated.status).toBe(0);
    expect(JSON.parse(validated.stdout)).toEqual({ valid: true, manifestDigest: signature.manifestDigest });
    for (const format of ['pem', 'der'] as const) {
      const keyFile = path.join(temp, `public.${format}`);
      const encoded = format === 'pem' ? keys.publicKey.export({ type: 'spki', format: 'pem' }) : keys.publicKey.export({ type: 'spki', format: 'der' });
      await writeFile(keyFile, encoded);
      const verified = cli('verify', dir, '--key', keyFile);
      expect(verified.stderr).toBe('');
      expect(verified.status).toBe(0);
      await writeFile(keyFile, Buffer.concat([Buffer.from(encoded), Buffer.from('junk')]));
      const malformed = cli('verify', dir, '--key', keyFile);
      expect(malformed.status).toBe(1);
      expect(malformed.stdout).toBe('');
      expect(malformed.stderr).toBe('PACK_PUBLISHER_UNTRUSTED\n');
    }
    const usage = cli('validate', dir, '--unknown');
    expect(usage.status).toBe(2);
    expect(usage.stderr).toBe('PACK_USAGE\n');
    const missingKey = cli('verify', dir, '--key', path.join(temp, 'missing.pem'));
    expect(missingKey.status).toBe(1);
    expect(missingKey.stderr).toBe('PACK_PUBLISHER_UNTRUSTED\n');
    await writeFile(path.join(dir, 'payload', 'notice.txt'), negative.tamperedPayload);
    const tampered = cli('verify', dir, '--key', path.join(temp, 'public.pem'));
    expect(tampered.status).toBe(2);
    expect(tampered.stderr).toBe('PACK_DIGEST_MISMATCH\n');
    expect(await readFile(path.join(dir, 'manifest.json'))).toEqual(before);
  });

  it('imports built library without CLI, file reads, or network effects', () => {
    const script = `import { syncBuiltinESMExports } from 'node:module';
      import fs from 'node:fs'; import fsp from 'node:fs/promises'; import http from 'node:http'; import https from 'node:https';
      const deny = () => { throw new Error('UNEXPECTED_EFFECT'); };
      fs.readFileSync = deny; fsp.readFile = deny; http.request = deny; https.request = deny; globalThis.fetch = deny;
      syncBuiltinESMExports(); await import('./dist/index.js');`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: repo, encoding: 'utf8', windowsHide: true });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('exposes only sanitized error messages and stacks', async () => {
    try { await validatePack(path.join(temp, 'missing')); }
    catch (error) {
      expect(error).toBeInstanceOf(PackError);
      expect((error as PackError).message).toBe('PACK_PATH_INVALID');
      expect((error as PackError).stack).toBe('PACK_PATH_INVALID');
      return;
    }
    throw new Error('Expected refusal');
  });
});
