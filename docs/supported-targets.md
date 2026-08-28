# Supported targets

The release matrix is mandatory and fail-closed:

| Zig target | Runner | Dynamic | Static |
|---|---|---|---|
| `x86_64-linux-gnu` | Ubuntu 24.04 x86-64 | Debug/ReleaseSafe build and execute | Debug/ReleaseSafe build and execute |
| `aarch64-linux-gnu` | Ubuntu 24.04 Arm64 | Debug/ReleaseSafe build and execute | Debug/ReleaseSafe build and execute |
| `x86_64-windows-msvc` | Windows Server 2025 x86-64 | Debug/ReleaseSafe build and execute | Debug/ReleaseSafe build and execute |
| `aarch64-windows-msvc` | Windows 11 Arm64 | Debug/ReleaseSafe build and execute | Debug/ReleaseSafe build and execute |

Release support requires native execution. A new target may initially have a
separate build-only lane only when no trusted native runner or approved
emulator exists; it remains experimental and cannot satisfy the release gate.
Linux musl, Windows GNU, 32-bit targets, WASI, and other OSes fail before any
header or library search with a diagnostic listing the supported triples.

The tested toolchain is Zig 0.16.0 and SymCrypt 103.13.0 at commit
`286762b7730e2b780678f5ab11fef2b1bad639e0`.
The Windows Arm64 runner executes Arm64 outputs natively; CI uses the
SHA-256-pinned x86-64 Zig compiler under Windows emulation because the 0.16.0
native Arm64 compiler exits before build diagnostics on that hosted image.
To keep that emulated compiler lane bounded, Arm64 runs the complete default
suite in Debug and ReleaseSafe for both linkages plus one ReleaseSafe execution
with both independent legacy gates enabled. The full separate default, legacy,
and legacy-RSA optimization matrix also runs locally and on native x86-64.
