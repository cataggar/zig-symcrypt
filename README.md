# zig-symcrypt

Zig 0.16.0+ bootstrap package for prebuilt Microsoft SymCrypt 103.13.0
libraries. It imports pinned C headers for the selected target instead of
shipping translated bindings, and never uses `dlopen` or `LoadLibrary`.

## Supported targets

| Target | Status |
|---|---|
| `x86_64-linux-gnu` | compile and native execution supported |
| `aarch64-linux-gnu` | compile supported; execute on native/QEMU fixture |
| `x86_64-windows-msvc` | compile supported; execute on Windows fixture |
| `aarch64-windows-msvc` | compile supported; native ARM64 execution is a release gate |

Other targets fail during build with the supported triples. Linux musl and
Windows GNU are intentionally rejected.

## Dependency

```zig
const dep = b.dependency("zig_symcrypt", .{
    .target = target,
    .optimize = optimize,
    .linkage = .dynamic,
    .symcrypt_libraries = &.{.{ .cwd_relative = "/opt/symcrypt/lib/libsymcrypt.so" }},
});
root_module.addImport("symcrypt", dep.module("symcrypt"));
```

Options:

- `linkage`: `dynamic` (default) or `static`.
- `symcrypt_libraries`: required ordered exact library paths.
- `symcrypt_include_dir`: optional complete header directory; defaults to the
  bundled pin and is rejected at compile time unless it is exactly 103.13.0.
- `symcrypt_system_include_dirs`: optional ordered SDK/CRT include paths for
  explicit cross-toolchains (Windows cross-compilation requires these).
- `symcrypt_checked`: define `DBG=1`; this must match the supplied binary.
- `headers_only`: package-maintainer ABI compilation without native binaries.

Maintainer validation distinguishes checks available from the current host from
the advertised full target matrix:

```sh
zig build abi-local -Dheaders_only=true
zig build abi -Dheaders_only=true
```

`abi-local` checks Linux targets and also checks Windows when a native Windows
SDK or explicit `symcrypt_system_include_dirs` are available. `abi` is the full
release gate and fails rather than skipping Windows when the SDK inputs are
absent. GitHub Actions runs that full ABI gate on Windows, executes dynamic and
static tests on Windows x86_64, and compile-links both test sets for Windows
ARM64. Native Windows ARM64 execution remains a release gate on an ARM64
runner.

For command-line use, repeat the path option to preserve archive order:

```sh
zig build test -Dlinkage=dynamic \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt.so

zig build test -Dlinkage=static \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_posixusermode.a \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_common.a \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_mlkem.a
```

Windows dynamic mode takes the import `symcrypt.lib`, never the DLL. Static
mode should use `symcrypt_static_NoCIL.lib`. Windows builds require native
MSVC/SDK discovery. Linux dynamic deployments must make the matching SONAME
reachable through normal loader paths or an application-owned rpath. Put
`symcrypt.dll` beside the Windows executable or on its documented DLL search
path. This package does not copy binaries or mutate loader configuration.

## API and initialization

```zig
const symcrypt = @import("symcrypt");
try symcrypt.init();
```

Dynamic initialization uses the module loader's constructor/`DllMain`, then a
recoverable `SymCryptModuleInitEx(103, 13)` compatibility handshake. Static
initialization materializes the selected upstream environment macro and calls
`SymCryptInit()` once. Both paths use a process-wide atomic state machine.
`error.IncompatibleSymCryptVersion` identifies a dynamic API/minor mismatch;
other nonzero dynamic results become
`error.SymCryptInitializationFailed`. A static archive/header mismatch remains
an unrecoverable upstream fatal condition.

Static callbacks use OS entropy (`getrandom` or `BCryptGenRandom`), 32-byte
aligned allocation, and native mutexes. Static builds are not claimed to be
FIPS validated. A successful dynamic handshake proves API/minor compatibility,
not exact patch identity or validation status. Initialize before any operation;
future state wrappers must not permit copying or moving SymCrypt state.

See the generic `examples/initialize.zig`, linkage-specific
`initialize_dynamic.zig`/`initialize_static.zig`, and
`test/fixtures/README.md`.
