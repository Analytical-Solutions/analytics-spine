# Contributing

Use Node.js 24 or newer. Work on a branch and propose a pull request.

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run gate
git diff --check
npm run scan:public
```

The gate runs strict TypeScript checks for source and tests, ESLint, all Vitest
tests, and the distributable build. Filesystem/security tests have a bounded
30-second per-test timeout to allow full ancestor checks on Windows. The gate
requires no database or network after
dependency installation. The build produces ignored `dist/` output. Importing
the library starts no CLI or network operation. Subprocesses in tooling/tests
must set `windowsHide: true`.

Preserve schema field names, digest domains, exact signature message and loader
result shapes. Add regression fixtures for changes to these boundaries. Fixtures
must be synthetic and literal; signing keys are generated in memory per test.
Never commit a private key, credential, customer data, organization identifier,
internal endpoint, or private repository content/path. Do not add workflows or
publish packages without a separate owner decision.

This repository is public. Before **every push**, commit the intended changes and
run `npm run scan:public`. The script scans the first-party working tree (including
ignored build files), every reachable Git blob and commit/tag metadata, plus
paths and refs. It reports fixed rule IDs and content hashes, never matching text.
Third-party `node_modules/` and Git's object storage are excluded from filesystem
walking; reachable Git objects are scanned through Git. Its reproducible regex
rules detect common credentials, private-key envelopes, private paths, internal
hostnames and sensitive data-field markers. It rejects filesystem links and
unexpected binary blobs. Review all intended public files as well: regex scanning
cannot prove arbitrary data is safe. No scanner result authorizes a publication
beyond the branch/PR approved by the owner.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md), not public issues.
