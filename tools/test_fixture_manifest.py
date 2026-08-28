#!/usr/bin/env python3
"""Negative tests for architecture, hash, and linkage provenance diagnostics."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".zig-negative-fixtures" / "manifest"
PIN = json.loads((ROOT / "ci/symcrypt-fixtures.json").read_text(encoding="utf-8"))


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


def expect_failure(name: str, expected: str, manifest: dict, libraries: list[pathlib.Path]) -> None:
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
    print("fixture manifest negative architecture, hash, and linkage tests passed")


if __name__ == "__main__":
    main()
