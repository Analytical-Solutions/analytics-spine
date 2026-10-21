# Analytics Spine domain packs

A small TypeScript package for validating domain pack distributions and verifying
their Ed25519 publisher signatures locally. Node.js 24 or newer, ESM, zero runtime
dependencies, and no network calls. The repository is licensed under Apache-2.0;
see [LICENSE](LICENSE). Pack content has its own licence.

This is the public open-core format and verifier. The hosted product owns accounts,
registry hosting, authorization, entitlement evaluation, billing, installation
consent, and commercial pack content. A valid signature establishes integrity and
publisher identity under your supplied key; it does not grant redistribution rights,
evaluate entitlements, approve a pack's claims, or ratify domain grain.

## Install and check

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run gate
```

Installation needs an npm registry or populated cache. After installation,
`npm run gate` runs typechecking, ESLint, Vitest, and a build entirely offline.
There are no GitHub Actions workflows. The package is `private: true`; npm
publication is disabled. Use a reviewed Git checkout or copy the built verifier
and its `schemas/` directory into a consumer, preserving the relative layout.

## Usage

```sh
node dist/cli.js validate ./my-pack
node dist/cli.js verify ./my-pack --key ./publisher-public.pem
# The package's bin name, when locally linked, is analytics-spine-pack.
analytics-spine-pack validate ./my-pack
analytics-spine-pack verify ./my-pack --key ./publisher-public.pem
```

`--key` reads an out-of-band Ed25519 public key in PEM or DER SPKI format. Never
trust a key downloaded with a pack. Commands print a small JSON success record.
Failures print only the fixed error code to stderr. Validation/usage failures
exit 2; signature/key failures exit 1. Commands write no pack files.

```js
import { validatePack, verifyPack } from '@analytics-spine/domain-packs';

const validated = await validatePack('./my-pack');
const verified = await verifyPack('./my-pack', publisherPublicKey);
// publisherPublicKey: PEM string, PEM/DER SPKI Buffer, or public KeyObject.
```

The loader-compatible object form preserves the same result fields:

```js
await validatePack({ packDir, engineVersion: '2.0.0', mode: 'production' });
await verifyPack({ packDir, engineVersion: '2.0.0', mode: 'production', trust, now });
```

`trust` follows `schemas/publisher-trust.schema.json`: out-of-band keys bind
`keyId` to `sha256:<SPKI DER hex>`, canonical base64 `publicKeySpki`, UTC
`notBefore`/`notAfter`, and `active`, `retired`, or `revoked` state. Duplicate
IDs and malformed keys refuse. Revoked keys always refuse; retired keys verify
only signatures inside their signing interval. All intervals are start-inclusive,
end-exclusive; signatures from the future refuse. `now` is a calendar-valid UTC
string. Direct key calls have no revocation/validity policy and use the current
clock for the future-signature check.

`validatePack` returns `{ manifest, manifestDigest, files }`; `verifyPack` also
returns `{ signature, signatureDigest }`. `files` keeps the path-sorted manifest
entries `{ path, sha256, bytes, role }`. `fileDigest(path, bytes)` is exported for
consumer rechecks. The hosted adapter must separately supply its entitlement
evaluator. This package exports no `evaluateEntitlement` function.

Object calls can enforce `minimumVersion <= engineVersion < maximumExclusiveVersion`
by numeric semver triple comparison. Directory-only calls check the declared range
is well formed but do not select an engine. Production mode is the default;
`public-fixture` classification requires an explicit object call with `mode: 'test'`.
The CLI uses production mode.

## Distribution format and signature

```text
my-pack/
  manifest.json
  pack-signature.json
  payload/
    <each manifest.files[].path>
```

The three bundled closed Draft 2020-12 schemas define the envelope and publisher
trust. Unknown members, duplicate decoded JSON keys, nonfinite numbers, lone
surrogates, invalid UTF-8, and noninteger schema versions refuse. Payloads have
at most 1,024 files, 16 MiB per file and 64 MiB total. Manifest and signature
JSON are each capped at 4 MiB. File bindings referenced by source, licence,
provenance and proof fields must resolve to their declared payload roles.
External approval-record digests are commitments only; this verifier does not
authenticate those records or interpret process/proof contents.

Paths use portable ASCII slash-separated components. Absolute paths, empty or
dot components, `..`, backslashes, drive/stream syntax, reserved Windows basenames,
trailing dots, case aliases, symlinks, junctions, hardlinks, special files, extra
files and extra directories refuse. Directory traversal and reads are bounded;
file identity/size and tree metadata are rechecked during validation. Keep the
distribution immutable while validating and consuming it; verification does not
make subsequent independent reads atomic.

Payload digests are tagged `sha256-lf:<hex>` for `.json`, `.md`, `.sql`, `.py`,
`.tmdl`, `.pbir`, `.pbism`, `.pbip`, `.platform`, `.dax`, `.csv`, `.txt`, `.html`,
`.mjs`, `.js`, `.ipynb`, `.yml`, `.yaml`, `.toml`, `.xml`, and `.svg` (case
insensitive), and `sha256:<hex>` otherwise. Only CRLF pairs normalize to LF;
other bytes are preserved. `bytes` always counts original bytes.

Manifest and signature files must use `serialize(value)`: ordinal sorted object
keys, preserved array order, JSON UTF-8, no extra whitespace, and exactly one LF.
Their digest is tagged SHA-256 of those exact bytes, **including the final LF**.
This canonical distribution encoding makes the canonical manifest commitment
equal the hosted loader's raw-byte commitment. It is deliberately stricter than
loaders that accept arbitrary JSON whitespace; reformatting a pack requires a
new signature. `canonical(value)` itself returns JSON without the terminal LF.

The signed UTF-8 message is the NUL-joined sequence:

```text
analytics-spine/domain-pack/v1
signature.manifestDigest
signature.proof.keyId
signature.signedAt
```

There is no trailing NUL. `proof.algorithm` is `Ed25519`; `proofBytes` is canonical
base64 encoding of exactly 64 signature bytes. No signing, installation, archive
extraction, executable hooks, registry client, or remote service is included.

## Error codes

| Code | Meaning |
| --- | --- |
| `PACK_USAGE` | Unsupported command or flags |
| `PACK_SCHEMA_INVALID` | Invalid envelope, serialization, reference, limit or policy input |
| `PACK_PATH_INVALID` | Unsafe, missing, linked or aliased filesystem path |
| `PACK_STRUCTURE_INVALID` | Extra entries or bounded-tree limit exceeded |
| `PACK_DIGEST_MISMATCH` | Payload length or digest differs from manifest |
| `PACK_PLAN_CHANGED` | File identity or tree metadata changed during reading |
| `PACK_ENGINE_INCOMPATIBLE` | Selected engine is outside the declared range |
| `PACK_SIGNATURE_INVALID` | Wrong commitment, signature bytes or signing time |
| `PACK_PUBLISHER_UNTRUSTED` | Publisher key absent, wrong or unsupported |
| `PACK_KEY_REVOKED` | Publisher trust explicitly revoked the key |

These errors carry `.code` and `.exitCode`; messages and stacks disclose no rejected
paths or values. Additional structure/digest codes are more precise than consumers
that map all content failures to a single refusal. See [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [RELEASING.md](RELEASING.md).
