# zig-symcrypt

Zig 0.16.0+ bootstrap package for prebuilt Microsoft SymCrypt 103.13.0
libraries. It imports pinned C headers for the selected target instead of
shipping translated bindings, and never uses `dlopen` or `LoadLibrary`.

## Supported targets

| Target | Status |
|---|---|
| `x86_64-linux-gnu` | compile, dynamic/static link, and native execution validated in CI |
| `aarch64-linux-gnu` | compile, dynamic/static link, and native execution validated in CI |
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
- `legacy`: expose MD5 and SHA-1 hash, HMAC, and HKDF algorithm tags/types.
  It defaults to `false`, is intended only for compatibility or integrity-only
  consumers, and does not imply FIPS approval.
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
ARM64. Linux Actions jobs build the exact pinned upstream commit and execute the
complete dynamic and static test paths, including isolated concurrent first
initialization, on native x86_64 and ARM64 runners. Native Windows ARM64
execution remains a release gate on an ARM64 runner.

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

Maintainers can build native Linux fixtures with
`tools/build-linux-fixtures.sh SOURCE OUTPUT x86_64` or `aarch64`. The script
fails unless the native host matches the requested architecture and the source,
tag, version, and emitted ELF artifacts match the 103.13.0 pin.

## Cryptographic primitives

```zig
const std = @import("std");
const symcrypt = @import("symcrypt");

const allocator = std.heap.page_allocator;
const digest = try symcrypt.hash.digest(.sha256, "message");

const hash = try symcrypt.hash.Sha256.create(allocator);
defer hash.deinit();
try hash.update("part one");
const checkpoint = try hash.snapshot(); // source remains usable
const independent = try hash.clone(allocator);
defer independent.deinit();
try hash.update("part two");
const final_digest = try hash.final(); // hash state is reset and reusable

const mac = try symcrypt.hmac.mac(.sha3_256, "key", "message");
const hmac = try symcrypt.hmac.Sha256.create(allocator, "key");
defer hmac.deinit();
try hmac.update("message");
const tag = try hmac.final(); // call reset before another computation
try hmac.reset();

var derived: [42]u8 = undefined;
try symcrypt.hkdf.derive(.sha256, "ikm", "salt", "context", &derived);

var nonce: [32]u8 = undefined;
try symcrypt.random.fill(&nonce);

_ = .{ digest, checkpoint, final_digest, mac, tag };
```

Supported default hash families are SHA-256, SHA-384, SHA-512, SHA3-224,
SHA3-256, SHA3-384, and SHA3-512. Pinned SymCrypt 103.13.0 publicly exposes
one-shot/incremental HMAC and HKDF for all of those families, so the same matrix
is available in `symcrypt.hmac` and `symcrypt.hkdf`. `-Dlegacy=true` additionally
adds MD5 and SHA-1 declarations and enum tags; without it those names do not
exist in the public surface. Algorithms outside this matrix are not wrapped.

Incremental contexts are opaque allocator-owned handles whose SymCrypt objects
are allocated directly at their final stable address. Copying a handle only
creates an alias; `clone` is the sole supported independent copy operation.
Call `deinit` exactly once. It is deliberately not idempotent, and the handle
and all aliases are invalid afterward. Complete hash/HMAC implementation
objects and temporary copied/expanded states are wiped with `SymCryptWipe`.
Caller-owned digest, MAC, HKDF, and random output buffers remain the caller's
responsibility.

HMAC rejects update/final/snapshot/clone after finalization with
`error.InvalidState`; `reset` securely rebinds the retained expanded key.
Hash `final` follows SymCrypt's reset-on-result behavior. `digestInto` and
`macInto` require exact output sizes. HKDF rejects output longer than
`255 * HashLen` before FFI and accepts zero output. Non-empty HKDF `info` and
output slices must not overlap; full or partial overlap returns
`error.OverlappingBuffers` because SymCrypt rereads `info` between output
blocks. Every HKDF error securely zeroes the entire output with an
initialization-independent optimizer-resistant wipe, including validation,
overlap, initialization/version mismatch, and SymCrypt errors. No SymCrypt
function is called after initialization fails.
Empty optional HMAC keys and HKDF salt/info are passed as null only where the
pinned API explicitly permits it.

`symcrypt.Error` includes every public 103.13.0 `SYMCRYPT_ERROR`, initialization
failures, `InvalidState`, `OverlappingBuffers`, and `UnknownSymCryptError`.
`classifyCode(raw_u32)`
returns `Status`, preserving an unfamiliar raw value in `.unknown_code` for
forward-compatible diagnosis without constructing or casting to a C enum.

## Initialization

Every primitive initializes automatically. Explicit initialization remains
available:

```zig
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

Dynamic random generation uses exported `SymCryptRandom`, whose module failure
contract is fatal rather than recoverable. Static random generation routes
through the package callback and maps its `SYMCRYPT_ERROR`. Static callbacks
use OS entropy (`getrandom` or `BCryptGenRandom`), 32-byte
aligned allocation, and native mutexes. Static builds are not claimed to be
FIPS validated. A successful dynamic handshake proves API/minor compatibility,
not exact patch identity or validation status. Initialize before any operation;
the wrappers never copy or move SymCrypt state except through its state-copy
APIs.

See the generic `examples/initialize.zig`, linkage-specific
`initialize_dynamic.zig`/`initialize_static.zig`, and
`test/fixtures/README.md`.
