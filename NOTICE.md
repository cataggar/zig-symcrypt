# Notices

This package bundles public headers derived from Microsoft SymCrypt
`v103.13.0`, commit `286762b7730e2b780678f5ab11fef2b1bad639e0`:
<https://github.com/microsoft/SymCrypt/tree/v103.13.0>.

`vendor/symcrypt/include/symcrypt_internal_shared.inc` is generated from
upstream `conf/symcrypt_internal_shared.inc.in` and `version.json` with API,
minor, and patch values `103`, `13`, and `0`.

The internal layout header has a narrowly guarded `SYMCRYPT_ZIG_IMPORT`
compatibility path: it suppresses one declaration-position Prefast pragma and
represents ARM64 NEON storage as equivalently sized/aligned Clang vector types
so Zig's C translator does not import the intrinsic API. Normal C compilation
of the header remains upstream-identical.

The bundled upstream license and notice are in
`vendor/symcrypt/LICENSE.txt` and `vendor/symcrypt/NOTICE.txt`. SymCrypt is
Copyright Microsoft Corporation and licensed under the MIT License.

`vendor/symcrypt/NOTICE.txt` is the complete, unmodified notice from that exact
commit. It includes the FreeBSD `elfdefinitions.h` notice, the Jitterentropy
notice, and the post-quantum KAT test-vector notice. The wrapper itself is
licensed under the root `LICENSE`.
