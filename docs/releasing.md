# Fail-closed release procedure

Releases are pinned to SymCrypt 103.13.0, tag `v103.13.0`, commit
`286762b7730e2b780678f5ab11fef2b1bad639e0`, and Jitterentropy gitlink
`887c9871ea110e397812ff7f3b28a6269f0a2ffc`.

`zig build release-package` requires an exact fixture provenance manifest, a
clean tracked worktree, and tag `v0.1.0`. It depends on format, package
extraction, staged consumer example, ABI, linkage, initialization, and complete
safe-wrapper tests. The GitHub release workflow runs the full four-target,
two-linkage, two-optimization matrix before creating or uploading any archive.

## SymCrypt upgrade checklist

1. Select an upstream signed/tagged commit. Verify the tag, commit, canonical
   repository, `version.json`, and all submodule gitlinks. Review
   `CHANGELOG.md`, `doc/breaking_changes.md`, public headers, build logic, and
   dynamic export lists.
2. Update `src/symcrypt_version.zig`, `ci/symcrypt-fixtures.json`, generated
   `symcrypt_internal_shared.inc`, all bundled public headers, and provenance
   text together. Never change only numeric macros.
3. Regenerate and audit every entry in `src/abi.zig` and the required linked
   symbol coverage. Treat a layout, calling convention, or symbol change as an
   intentional wrapper/API review, not an automatic baseline rewrite.
4. Regenerate or review all known-answer, failure, interoperability, and
   upstream-derived vectors. Run Debug and ReleaseSafe safe-wrapper suites,
   fault injection, wiping, initialization mismatch, and concurrency tests for
   both linkage modes on all four native targets.
5. Rebuild immutable fixtures, regenerate their SHA-256 provenance manifests,
   and review the exact dynamic/static library lists and system dependencies.
6. Refresh `LICENSE`, the complete unmodified upstream `NOTICE.txt`, provenance
   notes, target/linking/initialization/FIPS documentation, examples, package
   allow-list, and any security implications.
7. Require a clean tree, package-version/tag agreement, package
   extraction/rebuild, exact fixture provenance, and every required GitHub
   check. Publish only the final source archive, its checksum, and matrix
   evidence; never publish fixture binaries.
