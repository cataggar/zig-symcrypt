#!/usr/bin/env python3
"""Create and verify fail-closed manifests for pinned SymCrypt fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import struct
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / "ci" / "symcrypt-fixtures.json"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"SymCrypt fixture validation failed: {message}")


def load_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read JSON '{path}': {error}")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*args: str, cwd: pathlib.Path | None = None) -> str:
    try:
        return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"command {' '.join(args)!r} failed: {error}")


def expected_arch(target: str) -> str:
    if target.startswith("x86_64-"):
        return "x86_64"
    if target.startswith("aarch64-"):
        return "aarch64"
    fail(f"unsupported target '{target}'")


def machine_name(value: int) -> str | None:
    return {
        62: "x86_64",       # ELF EM_X86_64
        183: "aarch64",     # ELF EM_AARCH64
        0x8664: "x86_64",  # COFF IMAGE_FILE_MACHINE_AMD64
        0xAA64: "aarch64", # COFF IMAGE_FILE_MACHINE_ARM64
    }.get(value)


def binary_machine(data: bytes) -> str | None:
    if data.startswith(b"\x7fELF") and len(data) >= 20:
        endian = "<" if data[5] == 1 else ">"
        return machine_name(struct.unpack_from(endian + "H", data, 18)[0])
    if data.startswith(b"MZ") and len(data) >= 0x40:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if pe + 6 <= len(data) and data[pe : pe + 4] == b"PE\0\0":
            return machine_name(struct.unpack_from("<H", data, pe + 4)[0])
    if len(data) >= 2:
        return machine_name(struct.unpack_from("<H", data, 0)[0])
    return None


def archive_machine(data: bytes) -> str | None:
    if not data.startswith(b"!<arch>\n"):
        return None
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            fail("malformed ar/COFF archive member header")
        start = offset + 60
        member = data[start : start + size]
        machine = binary_machine(member)
        if machine is not None:
            return machine
        offset = start + size + (size & 1)
    return None


def inspect_binary(path: pathlib.Path) -> tuple[str, str]:
    data = path.read_bytes()
    if data.startswith(b"!<arch>\n"):
        kind = "archive"
        machine = archive_machine(data)
    elif data.startswith(b"\x7fELF"):
        kind = "elf-shared"
        machine = binary_machine(data)
    elif data.startswith(b"MZ"):
        kind = "pe"
        machine = binary_machine(data)
    else:
        fail(f"unrecognized library format: {path}")
    if machine is None:
        fail(f"cannot determine library architecture: {path}")
    return kind, machine


def validate_source(source: pathlib.Path, pin: dict) -> None:
    source = source.resolve()
    actual = command("git", "rev-parse", "HEAD^{commit}", cwd=source)
    if actual != pin["commit"]:
        fail(f"source commit is {actual}, expected {pin['commit']}")
    tag = command("git", "rev-parse", f"{pin['tag']}^{{commit}}", cwd=source)
    if tag != pin["commit"]:
        fail(f"tag {pin['tag']} resolves to {tag}, expected {pin['commit']}")
    origin = command("git", "remote", "get-url", "origin", cwd=source).removesuffix("/")
    accepted = {
        "https://github.com/microsoft/SymCrypt",
        "https://github.com/microsoft/SymCrypt.git",
        "git@github.com:microsoft/SymCrypt.git",
    }
    if origin not in accepted:
        fail(f"source origin is '{origin}', expected canonical Microsoft SymCrypt")
    version = load_json(source / "version.json")
    expected_version = {
        "major": pin["version"]["api"],
        "minor": pin["version"]["minor"],
        "patch": pin["version"]["patch"],
    }
    if version != expected_version:
        fail(f"source version is {version!r}, expected {expected_version!r}")
    gitlink = command(
        "git", "ls-tree", "HEAD", "3rdparty/jitterentropy-library", cwd=source
    ).split()
    if len(gitlink) < 3 or gitlink[2] != pin["jitterentropy_commit"]:
        found = gitlink[2] if len(gitlink) >= 3 else "missing"
        fail(f"Jitterentropy gitlink is {found}, expected {pin['jitterentropy_commit']}")
    dirty = command("git", "status", "--porcelain", "--untracked-files=no", cwd=source)
    if dirty:
        fail("source tree has tracked modifications")


def validate_roles(target: str, linkage: str, entries: list[dict]) -> None:
    roles = [entry["role"] for entry in entries]
    if target.endswith("-linux-gnu"):
        expected = ["plus", "core"] if linkage == "dynamic" else [
            "plus", "environment", "common", "mlkem"
        ]
    elif target.endswith("-windows-msvc"):
        expected = ["plus", "core"]
    else:
        fail(f"unsupported target '{target}'")
    if roles != expected:
        fail(f"{target} {linkage} libraries must have roles/order {expected}, found {roles}")

    names = [pathlib.Path(entry["path"]).name.lower() for entry in entries]
    if "symcrypt_plus" not in names[0]:
        fail("first library must be the pinned symcrypt_plus companion")
    if target.endswith("-linux-gnu"):
        if linkage == "dynamic" and not (".so" in names[1]):
            fail("dynamic Linux core library must be libsymcrypt.so or a versioned SONAME")
        if linkage == "static" and any(not name.endswith(".a") for name in names):
            fail("static Linux linkage accepts only .a archives")
    else:
        if any(not name.endswith(".lib") for name in names):
            fail("Windows link inputs must be .lib files, never DLLs")
        core = names[1]
        if linkage == "static" and "static" not in core:
            fail("static Windows core library name must identify symcrypt_static")
        if linkage == "dynamic" and "static" in core:
            fail("dynamic Windows linkage requires the DLL import library, not symcrypt_static")


def create(args: argparse.Namespace) -> None:
    pin = load_json(PIN_PATH)
    if args.target not in pin["supported_targets"]:
        fail(f"unsupported target '{args.target}'")
    source = pathlib.Path(args.source)
    validate_source(source, pin)
    fixture_root = pathlib.Path(args.root).resolve()
    entries_by_linkage: dict[str, list[dict]] = {"dynamic": [], "static": []}
    for specification in args.library:
        try:
            linkage, role, raw_path = specification.split(":", 2)
        except ValueError:
            fail(f"invalid --library '{specification}'; expected linkage:role:path")
        if linkage not in entries_by_linkage:
            fail(f"invalid linkage '{linkage}' in --library")
        path = pathlib.Path(raw_path).resolve()
        try:
            relative = path.relative_to(fixture_root)
        except ValueError:
            fail(f"library is outside fixture root '{fixture_root}': {path}")
        if not path.is_file():
            fail(f"missing library: {path}")
        kind, arch = inspect_binary(path)
        expected = expected_arch(args.target)
        if arch != expected:
            fail(f"wrong architecture for {path}: found {arch}, expected {expected}")
        entries_by_linkage[linkage].append({
            "role": role,
            "path": relative.as_posix(),
            "sha256": sha256(path),
            "format": kind,
            "architecture": arch,
        })
    for linkage, entries in entries_by_linkage.items():
        validate_roles(args.target, linkage, entries)

    compiler = os.environ.get("CC", "default")
    manifest = {
        "schema": 1,
        "repository": pin["repository"],
        "tag": pin["tag"],
        "commit": pin["commit"],
        "version": pin["version"],
        "jitterentropy_commit": pin["jitterentropy_commit"],
        "target": args.target,
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "compiler": compiler,
        },
        "build_options": args.build_option,
        "libraries": entries_by_linkage,
    }
    output = pathlib.Path(args.output or fixture_root / "provenance.json")
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)


def verify(args: argparse.Namespace) -> None:
    pin = load_json(PIN_PATH)
    manifest_path = pathlib.Path(args.manifest).resolve()
    manifest = load_json(manifest_path)
    for field in ("schema", "repository", "tag", "commit", "version", "jitterentropy_commit"):
        if manifest.get(field) != pin.get(field):
            fail(f"manifest {field} is {manifest.get(field)!r}, expected {pin.get(field)!r}")
    if manifest.get("target") != args.target:
        fail(f"manifest target is {manifest.get('target')!r}, expected {args.target!r}")
    build_options = manifest.get("build_options")
    if not isinstance(build_options, list) or "config=Release" not in build_options:
        fail("manifest does not record the required Release fixture configuration")
    if args.target.endswith("-linux-gnu") and "fips=upstream-default" not in build_options:
        fail("Linux manifest does not record upstream-default module self-test configuration")
    if args.target.endswith("-windows-msvc") and not any(
        option.startswith("dynamic-name=symcrypt_zig_103_13") for option in build_options
    ):
        fail("Windows manifest does not record the unique pinned test DLL name")
    if args.linkage not in ("dynamic", "static"):
        fail(f"unsupported linkage '{args.linkage}'")
    entries = manifest.get("libraries", {}).get(args.linkage)
    if not isinstance(entries, list):
        fail(f"manifest has no {args.linkage} library list")
    validate_roles(args.target, args.linkage, entries)
    if len(entries) != len(args.library):
        fail(f"supplied {len(args.library)} libraries, manifest requires {len(entries)}")
    expected_architecture = expected_arch(args.target)
    root = manifest_path.parent
    for index, (entry, supplied_raw) in enumerate(zip(entries, args.library)):
        recorded = (root / entry["path"]).resolve()
        supplied = pathlib.Path(supplied_raw).resolve()
        if supplied != recorded:
            fail(f"library {index} is '{supplied}', manifest requires '{recorded}'")
        if not supplied.is_file():
            fail(f"missing library: {supplied}")
        actual_hash = sha256(supplied)
        if actual_hash != entry.get("sha256"):
            fail(f"SHA-256 mismatch for {supplied}: found {actual_hash}, expected {entry.get('sha256')}")
        kind, architecture = inspect_binary(supplied)
        if architecture != expected_architecture or architecture != entry.get("architecture"):
            fail(
                f"wrong architecture for {supplied}: found {architecture}, "
                f"expected {expected_architecture}"
            )
        if kind != entry.get("format"):
            fail(f"binary format mismatch for {supplied}: found {kind}, expected {entry.get('format')}")
    print(f"verified SymCrypt {pin['tag']} {args.target} {args.linkage} fixture provenance")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    create_parser = sub.add_parser("create")
    create_parser.add_argument("--root", required=True)
    create_parser.add_argument("--source", required=True)
    create_parser.add_argument("--target", required=True)
    create_parser.add_argument("--output")
    create_parser.add_argument("--library", action="append", required=True)
    create_parser.add_argument("--build-option", action="append", default=[])
    create_parser.set_defaults(function=create)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--target", required=True)
    verify_parser.add_argument("--linkage", required=True)
    verify_parser.add_argument("--library", action="append", default=[])
    verify_parser.set_defaults(function=verify)
    return result


if __name__ == "__main__":
    parser_args = parser().parse_args()
    parser_args.function(parser_args)
