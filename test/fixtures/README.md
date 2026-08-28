# Native fixture contract

Native binaries are deliberately not committed. Obtain Microsoft SymCrypt tag
`v103.13.0` at commit `286762b7730e2b780678f5ab11fef2b1bad639e0`.

On Linux, `tools/build-linux-fixtures.sh SOURCE OUTPUT` configures an upstream
CMake/Ninja release build without maintaining a Zig-side C source inventory.
Dynamic tests take `module/generic/libsymcrypt.so`. Static tests take the exact
ordered archive list printed by the script.

On Windows, build the same commit with upstream's documented MSBuild workflow.
Use `symcrypt.lib` plus the matching runtime `symcrypt.dll` for dynamic mode.
Use `symcrypt_static_NoCIL.lib` for static mode. Keep checked and release
artifacts separate and set `-Dsymcrypt_checked=true` only for checked binaries.
