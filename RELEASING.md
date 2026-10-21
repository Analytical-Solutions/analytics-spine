# Releasing and rollback

This initial repository is source-only. `private: true` disables npm publication.
No release, tag, registry upload or production deployment is authorized by the
initial implementation PR. Keep release publication as a separate owner action.

For a future approved source release:

1. Review the exact commit, dependency lockfile, public contents and compatibility
   notes. Run a clean install, `npm run gate`, `git diff --check`, and
   `npm run scan:public` on that commit. Record commands, results and commit SHA.
2. Choose a new semantic version, update documentation, and merge the reviewed PR
   under the repository owner's process. Recheck the exact release commit.
3. With explicit release authorization, create an immutable annotated version tag
   (for example `v0.1.0`) at the reviewed SHA and publish only that authorized tag
   and reviewed source archive. Do not include local scan receipts or dependencies.
4. Release notes identify the SHA, supported Node version, verifier changes and
   any schema or consumer migration requirements. No private source paths belong
   in public notes. Test a fresh checkout with the lockfile and no private sources.

If a defect is found, stop further distribution. Prefer a reviewed revert commit
and a new patch version/tag. Do not rewrite a published tag, force-push history,
delete unrelated resources, or claim old clones/caches can be recalled. Consumers
can pin the last known good reviewed SHA while a fix is prepared.

If a release asset must be withdrawn, obtain the owner's authorization, mark the
release withdrawn and explain safe replacement versions without exposing sensitive
details. If a package registry is approved in the future, use its supported yank
or deprecation mechanism; never reuse a version. That future registry policy must
define retention and rollback before the first publish.

Suspected secret exposure requires private incident handling and credential
rotation by the owner. Reverting a file does not remove it from public history,
forks or caches. Coordinate any exceptional history/asset cleanup separately.
