#!/usr/bin/env python3
"""Negative tests for architecture, hash, and linkage provenance diagnostics."""

from __future__ import annotations

import atexit
import hashlib
import json
import pathlib
import shutil
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRATCH_ROOT = ROOT / ".zig-negative-fixtures"
SCRATCH = SCRATCH_ROOT / "manifest"
PIN = json.loads((ROOT / "ci/symcrypt-fixtures.json").read_text(encoding="utf-8"))


def cleanup() -> None:
    if SCRATCH_ROOT.exists():
        shutil.rmtree(SCRATCH_ROOT)


atexit.register(cleanup)


def elf(machine: int) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def archive(member: bytes) -> bytes:
    name = b"object.o/".ljust(16)
    metadata = name + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
    metadata += b"100644".ljust(8) + str(len(member)).encode().ljust(10) + b"`\n"
    return b"!<arch>\n" + metadata + member + (b"\n" if len(member) & 1 else b"")


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe(machine: int) -> bytes:
    image = bytearray(128)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 64)
    image[64:68] = b"PE\0\0"
    struct.pack_into("<H", image, 68, machine)
    return bytes(image)


def expect_failure(
    name: str,
    expected: str,
    manifest: dict,
    libraries: list[pathlib.Path],
    runtime: pathlib.Path | None = None,
) -> None:
    path = SCRATCH / f"{name}.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    command = [
        "python3",
        str(ROOT / "tools/fixture_manifest.py"),
        "verify",
        "--manifest",
        str(path),
        "--target",
        manifest["target"],
        "--linkage",
        "dynamic",
    ]
    for library in libraries:
        command.extend(("--library", str(library)))
    if runtime is not None:
        command.extend(("--runtime", str(runtime)))
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode == 0 or expected not in result.stderr:
        raise SystemExit(
            f"{name} did not fail with {expected!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def base_manifest(plus: pathlib.Path, core: pathlib.Path) -> dict:
    return {
        **PIN,
        "target": "aarch64-linux-gnu",
        "host": {},
        "compiler": {
            "executable": "/usr/bin/aarch64-linux-gnu-gcc",
            "producer": "GNU",
            "version": "15.2.1",
            "target": "aarch64-linux-gnu",
            "architecture": "aarch64",
            "toolchain": {
                "kind": "gcc",
                "version": "15.2.1",
                "installation": "/usr",
            },
        },
        "build_options": [
            "scripts/build.py cmake",
            "config=Release",
            "fips=upstream-default",
        ],
        "libraries": {
            "dynamic": [
                {
                    "role": "plus",
                    "path": plus.name,
                    "sha256": digest(plus),
                    "format": "archive",
                    "architecture": "aarch64",
                },
                {
                    "role": "core",
                    "path": core.name,
                    "sha256": digest(core),
                    "format": "elf-shared",
                    "architecture": "aarch64",
                },
            ],
            "static": [],
        },
        "runtime": {},
    }


def windows_manifest(plus: pathlib.Path, core: pathlib.Path, runtime: pathlib.Path) -> dict:
    plus_path = plus.relative_to(SCRATCH).as_posix()
    core_path = core.relative_to(SCRATCH).as_posix()
    runtime_path = runtime.relative_to(SCRATCH).as_posix()
    return {
        **PIN,
        "target": "aarch64-windows-msvc",
        "host": {},
        "compiler": {
            "executable": r"C:\VS\VC\Tools\MSVC\14.50\bin\Hostarm64\arm64\cl.exe",
            "producer": "Microsoft C/C++ Optimizing Compiler",
            "version": "19.50.12345",
            "target": "aarch64-windows-msvc",
            "architecture": "aarch64",
            "toolchain": {
                "kind": "msvc",
                "version": "14.50.12345",
                "installation": r"C:\VS",
                "installation_version": "18.0.0",
            },
        },
        "build_options": [
            "MSBuild user-mode module and symcrypt_plus projects",
            "config=Release",
            "dynamic-name=symcrypt_zig_103_13",
        ],
        "libraries": {
            "dynamic": [
                {
                    "role": "plus",
                    "path": plus_path,
                    "sha256": digest(plus),
                    "format": "archive",
                    "architecture": "aarch64",
                },
                {
                    "role": "core",
                    "path": core_path,
                    "sha256": digest(core),
                    "format": "archive",
                    "architecture": "aarch64",
                },
            ],
            "static": [],
        },
        "runtime": {
            "dynamic": {
                "role": "core-runtime",
                "path": runtime_path,
                "sha256": digest(runtime),
                "format": "pe",
                "architecture": "aarch64",
                "expected_filename": "symcrypt_zig_103_13.dll",
                "import_library_path": core_path,
                "source": {
                    "repository": PIN["repository"],
                    "tag": PIN["tag"],
                    "commit": PIN["commit"],
                    "version": PIN["version"],
                },
                "version_info": {
                    "file_version": "103.13.0.0",
                    "product_version": "103.13.0.0-release",
                },
            },
        },
    }


def main() -> None:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True)
    plus = SCRATCH / "libsymcrypt_plus.a"
    core = SCRATCH / "libsymcrypt.so"
    plus.write_bytes(archive(elf(62)))
    core.write_bytes(elf(62))

    manifest = base_manifest(plus, core)
    expect_failure("wrong-architecture", "wrong architecture", manifest, [plus, core])

    bad_hash = base_manifest(plus, core)
    bad_hash["libraries"]["dynamic"][0]["sha256"] = "0" * 64
    expect_failure("wrong-hash", "SHA-256 mismatch", bad_hash, [plus, core])

    missing_plus = base_manifest(plus, core)
    missing_plus["libraries"]["dynamic"][0]["role"] = "core"
    expect_failure(
        "missing-plus-role",
        "must have roles/order",
        missing_plus,
        [plus, core],
    )

    missing_compiler = base_manifest(plus, core)
    missing_compiler.pop("compiler")
    expect_failure("missing-compiler", "compiler metadata must be an object", missing_compiler, [plus, core])

    placeholder_compiler = base_manifest(plus, core)
    placeholder_compiler["compiler"]["producer"] = "default"
    expect_failure(
        "placeholder-compiler",
        "compiler.producer must be a non-placeholder",
        placeholder_compiler,
        [plus, core],
    )

    wrong_compiler_arch = base_manifest(plus, core)
    wrong_compiler_arch["compiler"]["architecture"] = "x86_64"
    expect_failure(
        "wrong-compiler-architecture",
        "compiler architecture/target is inconsistent",
        wrong_compiler_arch,
        [plus, core],
    )

    windows = SCRATCH / "windows"
    windows.mkdir()
    win_plus = windows / "symcrypt_plus_NoCIL.lib"
    win_core = windows / "symcrypt_zig_103_13.lib"
    win_runtime = windows / "symcrypt_zig_103_13.dll"
    arm64_pe = pe(0xAA64)
    win_plus.write_bytes(archive(arm64_pe))
    win_core.write_bytes(archive(arm64_pe + b"symcrypt_zig_103_13.dll\0"))
    win_runtime.write_bytes(arm64_pe)

    runtime_manifest = windows_manifest(win_plus, win_core, win_runtime)
    missing_toolset = windows_manifest(win_plus, win_core, win_runtime)
    missing_toolset["compiler"]["toolchain"]["version"] = ""
    expect_failure(
        "missing-msvc-toolset",
        "compiler.toolchain.version must be a non-placeholder",
        missing_toolset,
        [win_plus, win_core],
        win_runtime,
    )

    win_core.write_bytes(archive(arm64_pe + b"symcrypt.dll\0"))
    wrong_import_relationship = windows_manifest(win_plus, win_core, win_runtime)
    expect_failure(
        "runtime-import-relationship",
        "does not name the exact runtime DLL",
        wrong_import_relationship,
        [win_plus, win_core],
        win_runtime,
    )
    win_core.write_bytes(archive(arm64_pe + b"symcrypt_zig_103_13.dll\0"))

    substitute = windows / "substitute.dll"
    substitute.write_bytes(arm64_pe)
    expect_failure(
        "runtime-substitution",
        "manifest requires",
        runtime_manifest,
        [win_plus, win_core],
        substitute,
    )

    tampered_manifest = windows_manifest(win_plus, win_core, win_runtime)
    win_runtime.write_bytes(arm64_pe + b"tampered")
    expect_failure(
        "runtime-tampering",
        "SHA-256 mismatch for runtime DLL",
        tampered_manifest,
        [win_plus, win_core],
        win_runtime,
    )

    win_runtime.write_bytes(pe(0x8664))
    wrong_runtime_arch = windows_manifest(win_plus, win_core, win_runtime)
    wrong_runtime_arch["runtime"]["dynamic"]["architecture"] = "aarch64"
    expect_failure(
        "runtime-wrong-architecture",
        "wrong architecture for runtime DLL",
        wrong_runtime_arch,
        [win_plus, win_core],
        win_runtime,
    )
    print("fixture manifest provenance, compiler, and runtime negative tests passed")


if __name__ == "__main__":
    main()
