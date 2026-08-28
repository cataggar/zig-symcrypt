# Linking local SymCrypt libraries

The package is source-only. It neither downloads SymCrypt nor packages upstream
binaries, and it never uses `dlopen` or `LoadLibrary`. Every input is an exact
file passed with repeated `-Dsymcrypt_libraries=...` options.

Dynamic Linux order:

1. `libsymcrypt_plus.a`
2. `libsymcrypt.so` (or its exact versioned file)

Static Linux order:

1. `libsymcrypt_plus.a`
2. `libsymcrypt_posixusermode.a`
3. `libsymcrypt_common.a`
4. `libsymcrypt_mlkem.a`

The package additionally links `atomic` and `pthread`. Dynamic execution must
make the same `libsymcrypt.so.103` reachable with an application rpath, system
loader configuration, or a process-local `LD_LIBRARY_PATH`.

Dynamic Windows order is `symcrypt_plus_NoCIL.lib` followed by the import
library for the matching `symcrypt_zig_103_13.dll`. Pass the import `.lib`,
never the DLL.
Static Windows order is `symcrypt_plus_NoCIL.lib` then
`symcrypt_static_NoCIL.lib`; the package also links `bcrypt`. Put the exact
dynamic DLL beside the application. Repository tests and staged consumers
require provenance and use `tools/run_verified.py` to verify the source DLL,
copy it beside the executable, verify the copy again, and only then execute.
An ambient `PATH` entry is never the validation boundary.

`-Dsymcrypt_include_dir` selects a complete header set and defaults to the
bundled pin. `-Dsymcrypt_checked=true` must be used only when both headers and
libraries use the checked/`DBG` ABI. A FRE/checked mismatch is unsupported.
`-Dsymcrypt_provenance` is mandatory for `abi-release-gate` and records hashes,
architecture, linkage roles, source commit, tag, submodule gitlink, structured
compiler/toolchain identity, and (on Windows) the exact runtime DLL, PE
architecture/version, SHA-256, filename, and import-library relationship.

See `examples/dynamic` and `examples/static`. Each is an independent package
consumer and accepts the same include/library options.
