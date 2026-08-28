# Native fixture contract

Native binaries are deliberately not committed. Obtain Microsoft SymCrypt tag
`v103.13.0` at commit `286762b7730e2b780678f5ab11fef2b1bad639e0`.

On native Linux, `tools/build-linux-fixtures.sh SOURCE OUTPUT ARCH` accepts
`x86_64` or `aarch64`, rejects a host/fixture architecture mismatch, and
configures an upstream CMake/Ninja release build without maintaining a Zig-side
C source inventory. It verifies the canonical upstream origin, tag, commit,
version, Jitterentropy gitlink, ELF machine, and shared-library SONAME. The
pinned submodule must be initialized. The script emits a SHA-256 provenance
manifest consumed by `abi-release-gate`. Dynamic tests take
`module/generic/libsymcrypt.so`. Static tests take the exact ordered archive list
printed by the script.

On Windows, build the same commit's user-mode module and `symcrypt_plus`
MSBuild projects in Release configuration. The project-scoped build avoids
requiring unrelated kernel/WDK projects from the full solution.
Use `symcrypt.lib` plus the matching runtime `symcrypt.dll` for dynamic mode.
Use `symcrypt_static_NoCIL.lib` for static mode. Keep checked and release
artifacts separate and set `-Dsymcrypt_checked=true` only for checked binaries.
