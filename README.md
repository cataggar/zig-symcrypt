# zig-symcrypt

Zig 0.16.0+ bootstrap package for prebuilt Microsoft SymCrypt 103.13.0
libraries. It imports pinned C headers for the selected target instead of
shipping translated bindings, and never uses `dlopen` or `LoadLibrary`.

## Supported targets

| Target | Status |
|---|---|
| `x86_64-linux-gnu` | compile, dynamic/static link, and native execution validated in CI |
| `aarch64-linux-gnu` | compile, dynamic/static link, and native execution validated in CI |
| `x86_64-windows-msvc` | compile, dynamic/static link, and native execution validated in CI |
| `aarch64-windows-msvc` | compile, dynamic/static link, and native execution validated in CI |

Other targets fail during build with the supported triples. Linux musl and
Windows GNU are intentionally rejected.

## Dependency

```zig
const dep = b.dependency("zig_symcrypt", .{
    .target = target,
    .optimize = optimize,
    .linkage = .dynamic,
    .symcrypt_libraries = &.{
        .{ .cwd_relative = "/opt/symcrypt/lib/libsymcrypt_plus.a" },
        .{ .cwd_relative = "/opt/symcrypt/lib/libsymcrypt.so" },
    },
});
root_module.addImport("symcrypt", dep.module("symcrypt"));
```

Options:

- `linkage`: `dynamic` (default) or `static`.
- `symcrypt_libraries`: required ordered exact library paths. The pinned
  `symcrypt_plus` static companion must come first for either core linkage mode;
  it supplies the checked SEC1 and RFC 7748 IETF encodings.
- `symcrypt_include_dir`: optional complete header directory; defaults to the
  bundled pin and is rejected at compile time unless it is exactly 103.13.0.
- `symcrypt_system_include_dirs`: optional ordered SDK/CRT include paths for
  explicit cross-toolchains (Windows cross-compilation requires these).
- `symcrypt_checked`: define `DBG=1`; this must match the supplied binary.
- `legacy`: expose MD5 and SHA-1 hash, HMAC, and HKDF algorithm tags/types.
  It defaults to `false`, is intended only for compatibility or integrity-only
  consumers, and does not imply FIPS approval.
- `enable_legacy_rsa_pkcs1_encryption`: expose RSAES-PKCS1-v1_5 encryption and
  decryption under `asymmetric.rsa.legacy`. This padding-oracle-sensitive API
  defaults off independently of legacy hashes.
- `enable_mlkem` and `enable_tls_x25519_mlkem768`: deliberately unavailable fail-closed
  gates. SymCrypt's composite ML-KEM is not RFC 10024; independent FIPS 203
  and RFC 10024/TLS interoperability fixtures are required before enabling.
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
absent. GitHub Actions builds the exact pinned upstream commit and executes the
same complete safe-wrapper suite in Debug and ReleaseSafe for dynamic and
static linkage on native Linux and Windows x86_64/Arm64 runners. It also runs
isolated mismatch and concurrent-first-initialization processes, fixture
provenance, package, formatter, diagnostics, and consumer-example gates.

For command-line use, repeat the path option to preserve archive order:

```sh
zig build test -Dlinkage=dynamic \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_plus.a \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt.so

zig build test -Dlinkage=static \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_plus.a \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_posixusermode.a \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_common.a \
  -Dsymcrypt_libraries=/opt/symcrypt/lib/libsymcrypt_mlkem.a
```

Windows dynamic mode takes `symcrypt_plus_NoCIL.lib` followed by the core
import `symcrypt.lib`, never the DLL. Static mode takes
`symcrypt_plus_NoCIL.lib` followed by `symcrypt_static_NoCIL.lib`. Windows builds require native
MSVC/SDK discovery. Linux dynamic deployments must make the matching SONAME
reachable through normal loader paths or an application-owned rpath. Put
`symcrypt.dll` beside the Windows executable or on its documented DLL search
path. This package does not copy binaries or mutate loader configuration.

Maintainers can build native Linux fixtures with
`tools/build-linux-fixtures.sh SOURCE OUTPUT x86_64` or `aarch64`. The script
fails unless the native host matches the requested architecture and the source,
tag, version, Jitterentropy gitlink, and emitted ELF artifacts match the
103.13.0 pin. It emits `provenance.json` containing the exact ordered library
roles, architecture, and SHA-256 hashes. Pass that file to
`zig build abi-release-gate -Dsymcrypt_provenance=...`.

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

Authenticated encryption and raw AES-CBC are exposed through explicit
caller-buffer and allocator-owned APIs:

```zig
const key = [_]u8{0x42} ** 16;
const nonce = [_]u8{0x24} ** 12; // must be unique for every encryption with this key
const gcm = try symcrypt.aead.Aes128Gcm.init(allocator, &key);
defer gcm.deinit();

var sealed = try gcm.sealAlloc(allocator, &nonce, "metadata", "message", 16);
defer sealed.deinit();
var opened = try gcm.openAlloc(
    allocator,
    &nonce,
    "metadata",
    sealed.ciphertext(),
    sealed.tag(),
);
defer opened.deinit(); // wipes the complete plaintext allocation before free

const aes = try symcrypt.cipher.AesKey.init(allocator, &key);
defer aes.deinit();
var iv = [_]u8{0} ** symcrypt.cipher.block_size;
var blocks: [32]u8 = undefined; // length must be an exact multiple of 16
try aes.cbcEncryptInPlace(&iv, &blocks);
```

`Aes128Gcm` and `Aes256Gcm` accept non-empty byte nonces, 12-16 byte
authentication tags, AAD shorter than `2^61` bytes, and data no longer than
`2^36 - 32` bytes. `ChaCha20Poly1305` requires a 32-byte key, 12-byte nonce,
16-byte tag, and at most `274,877,906,880` data bytes. Reusing a key/nonce
pair with either AEAD catastrophically breaks security.

Caller-buffer out-of-place operations require fully disjoint buffers.
Dedicated in-place operations pass one exact source/destination region.
Every partial overlap is rejected, as are overlaps between mutable output and
the key, nonce, AAD, or detached tag. Validation failures do not mutate caller
buffers. Authentication failure wipes the complete plaintext destination with
an initialization-independent secure zero operation; for in-place decryption
this intentionally destroys the ciphertext. Owned sealing allocates one
`ciphertext.len + tag.len` backing region and writes both slices directly.
Owned opening and CBC operations allocate their exact output once without
staging or copy-after-FFI paths.

AES-CBC supports 128-, 192-, and 256-bit AES keys for rust-symcrypt parity.
It is a raw, unauthenticated block-mode primitive: **there is no implicit
padding of any kind**. Inputs must be empty or a multiple of 16 bytes, and the
caller-provided IV/chaining value is updated to the final chain. Applications
must select and validate any padding separately and must authenticate CBC
ciphertext before use; AEAD is preferred for new protocols.

AEAD and AES expanded keys are opaque allocator-owned handles whose
self-referential SymCrypt state is created at its final stable address. Call
`deinit` exactly once. Deinitialization and all post-allocation failure paths
wipe the complete imported C object before exactly one free. Expanded keys are
immutable after creation and can be used concurrently with independent
buffers, nonces, and CBC IVs.

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
`examples/symmetric.zig`, `examples/asymmetric.zig`, and
`test/fixtures/README.md`. `examples/dynamic` and `examples/static` are
independent package consumers that are built from the extracted release
allow-list in CI.

## Release and policy documentation

- [Supported native target matrix](docs/supported-targets.md)
- [Exact local library lists and loader behavior](docs/linking.md)
- [Initialization and version compatibility](docs/initialization.md)
- [FIPS boundary and limitations](docs/fips.md)
- [Test coverage](docs/test-coverage.md)
- [Fail-closed release and SymCrypt upgrade checklist](docs/releasing.md)

Release archives are source-only and contain no SymCrypt binaries. The release
workflow cannot create or upload an archive until every native target/linkage,
security, ABI/provenance, package, formatter, legacy-gate, and example job has
succeeded for the same commit.

## Asymmetric cryptography

`symcrypt.asymmetric` provides allocator-owned opaque keys for:

- P-256, P-384, and P-521 generation, fixed-width private scalar import/export,
  SEC1 uncompressed public import/export, immutable ECDSA/ECDH usage, ECDH, and
  canonical DER ECDSA;
- X25519 through SymCrypt Curve25519, with RFC 7748 little-endian encoding,
  u-coordinate normalization, and low-order/all-zero agreement rejection;
- RSA 2048–16384-bit two-prime generation, checked raw component import/export,
  immutable usage, PKCS#1 v1.5 signatures, PSS, and OAEP.

Advertised asymmetric algorithm matrix:

| Operation | Algorithms |
|---|---|
| ECDH/ECDSA | P-256/P-384/P-521 with SHA-256/384/512 and SHA3-256/384/512, using normal ECDSA digest truncation |
| X25519 | RFC 7748 Curve25519, 32-byte little-endian private/public/shared values |
| RSA PKCS#1 signatures | SHA-256/384/512 and SHA3-256/384/512 |
| RSA-PSS and RSA-OAEP | SHA-256/384/512 and SHA3-256/384/512 |
| Legacy hash gate | ECDSA SHA-1; RSA PKCS#1 SHA-1/MD5; RSA-PSS/OAEP SHA-1 |

The native matrix exercises every listed ECDSA curve/hash combination, generates
2048-, 3072-, and 4096-bit RSA keys, and exercises each modern RSA SHA-2/SHA-3 row.
Pinned NIST vectors cover ECDH/ECDSA on all three
curves, RFC 7748 covers base and 1,000-iteration X25519 behavior, and pinned
RSA vectors cover PKCS#1, PSS, and OAEP independently of generated round trips.

```zig
const private = try symcrypt.asymmetric.ecc.PrivateKey.generate(
    allocator,
    .p256,
    .signing_and_agreement,
);
defer private.deinit();
const public = try private.publicKey(allocator);
defer public.deinit();

const digest = try symcrypt.hash.digest(.sha256, "message");
var signature: [139]u8 = undefined;
const signature_len = try private.sign(.sha256, &digest, &signature);
try public.verify(.sha256, &digest, signature[0..signature_len]);
```

ECDSA decoding accepts exactly one minimally encoded
`SEQUENCE(INTEGER r, INTEGER s)` and rejects negative, redundant, truncated,
overflowing, extra, and trailing encodings without modifying the destination.
RSA PKCS#1 signature `DigestInfo` is assembled from a stable allow-list in Zig,
avoiding SymCrypt's private OID layout. Failed OAEP and gated legacy decryptions
wipe the complete caller output. Owning handles must be destroyed exactly once;
their aliases become invalid after `deinit`. Modulus-sized PKCS#1/PSS signature
representatives outside the RSA modulus are reported as `error.InvalidSignature`;
caller length/hash/usage errors remain distinct. RSA component imports reject
zero-prefixed and even big-endian moduli before allocation. X25519's public
slice APIs validate 32-byte lengths before fixed-size normalization.
