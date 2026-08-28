#!/usr/bin/env python3
"""Create and verify fail-closed manifests for pinned SymCrypt fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import platform
import struct
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / "ci" / "symcrypt-fixtures.json"
PLACEHOLDERS = {"", "cc", "default", "unknown", "unset", "none", "n/a"}


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


def require_identity(value: object, field: str) -> str:
    if not isinstance(value, str) or value.strip().lower() in PLACEHOLDERS:
        fail(f"manifest {field} must be a non-placeholder string")
    return value.strip()


def is_absolute_path(value: str) -> bool:
    return pathlib.PurePosixPath(value).is_absolute() or pathlib.PureWindowsPath(value).is_absolute()


def target_mentions_architecture(value: str, architecture: str) -> bool:
    lowered = value.lower()
    if architecture == "x86_64":
        return "x86_64" in lowered or "amd64" in lowered or "x64" in lowered
    return "aarch64" in lowered or "arm64" in lowered


def validate_compiler(target: str, compiler: object) -> None:
    if not isinstance(compiler, dict):
        fail("manifest compiler metadata must be an object")
    executable = require_identity(compiler.get("executable"), "compiler.executable")
    if not is_absolute_path(executable):
        fail("manifest compiler.executable must be the actual absolute compiler path")
    producer = require_identity(compiler.get("producer"), "compiler.producer")
    require_identity(compiler.get("version"), "compiler.version")
    compiler_target = require_identity(compiler.get("target"), "compiler.target")
    architecture = require_identity(compiler.get("architecture"), "compiler.architecture")
    expected = expected_arch(target)
    if architecture != expected or not target_mentions_architecture(compiler_target, expected):
        fail(
            f"compiler architecture/target is inconsistent with {target}: "
            f"found {architecture!r} and {compiler_target!r}"
        )
    toolchain = compiler.get("toolchain")
    if not isinstance(toolchain, dict):
        fail("manifest compiler.toolchain metadata must be an object")
    kind = require_identity(toolchain.get("kind"), "compiler.toolchain.kind").lower()
    require_identity(toolchain.get("version"), "compiler.toolchain.version")
    installation = require_identity(
        toolchain.get("installation"),
        "compiler.toolchain.installation",
    )
    if not is_absolute_path(installation):
        fail("manifest compiler.toolchain.installation must be an absolute path")
    if target.endswith("-windows-msvc"):
        if kind != "msvc":
            fail(f"Windows fixture compiler toolchain must be MSVC, found {kind!r}")
        require_identity(
            toolchain.get("installation_version"),
            "compiler.toolchain.installation_version",
        )
        if pathlib.PureWindowsPath(executable).name.lower() != "cl.exe":
            fail("Windows fixture compiler executable must be the selected cl.exe")
        if compiler_target != target:
            fail(f"Windows compiler target is {compiler_target!r}, expected {target!r}")
        if "microsoft" not in producer.lower():
            fail(f"Windows compiler producer must identify Microsoft, found {producer!r}")
        if not target_mentions_architecture(executable, expected):
            fail(f"Windows compiler path does not identify the {expected} target tools")
    else:
        if kind not in ("gcc", "clang"):
            fail(f"Linux fixture compiler toolchain must be GCC or Clang, found {kind!r}")
        if "linux" not in compiler_target.lower():
            fail(f"Linux compiler target does not identify Linux: {compiler_target!r}")
        if "musl" in compiler_target.lower():
            fail(f"Linux compiler target is musl, but the fixture target is GNU: {compiler_target!r}")
        if kind == "gcc" and not any(name in producer.lower() for name in ("gnu", "gcc")):
            fail(f"GCC toolchain producer is inconsistent: {producer!r}")
        if kind == "clang" and "clang" not in producer.lower():
            fail(f"Clang toolchain producer is inconsistent: {producer!r}")


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
    if not entries or any(not isinstance(entry, dict) for entry in entries):
        fail(f"{target} {linkage} libraries must be a nonempty artifact list")
    for entry in entries:
        for field in ("role", "path", "sha256", "format", "architecture"):
            require_identity(entry.get(field), f"libraries.{linkage}.{field}")
        path = pathlib.PurePosixPath(entry["path"])
        if path.is_absolute() or ".." in path.parts:
            fail(f"library manifest path must be relative and contained: {entry['path']!r}")
        digest = entry["sha256"]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            fail(f"library manifest SHA-256 is malformed: {digest!r}")
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


def expected_windows_dll(pin: dict) -> str:
    return f"symcrypt_zig_{pin['version']['api']}_{pin['version']['minor']}.dll"


def validate_import_relationship(path: pathlib.Path, expected_dll: str) -> None:
    if expected_dll.lower().encode("ascii") not in path.read_bytes().lower():
        fail(f"import library {path} does not name the exact runtime DLL {expected_dll!r}")


def validate_runtime_record(target: str, manifest: dict, record: object) -> dict:
    if not isinstance(record, dict):
        fail("dynamic Windows manifest must record a typed runtime DLL artifact")
    if record.get("role") != "core-runtime":
        fail("dynamic Windows runtime artifact role must be 'core-runtime'")
    runtime_path = require_identity(record.get("path"), "runtime.path")
    path_parts = pathlib.PurePosixPath(runtime_path)
    if path_parts.is_absolute() or ".." in path_parts.parts:
        fail(f"runtime DLL manifest path must be relative and contained: {runtime_path!r}")
    digest = require_identity(record.get("sha256"), "runtime.sha256")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        fail(f"runtime DLL SHA-256 is malformed: {digest!r}")
    expected_name = expected_windows_dll(manifest)
    if record.get("expected_filename") != expected_name:
        fail(
            f"runtime DLL expected filename is {record.get('expected_filename')!r}, "
            f"expected {expected_name!r}"
        )
    if path_parts.name.lower() != expected_name.lower():
        fail(f"runtime DLL path must end in the exact pinned filename {expected_name!r}")
    if record.get("format") != "pe":
        fail("dynamic Windows runtime artifact must be a PE DLL")
    expected = expected_arch(target)
    if record.get("architecture") != expected:
        fail(
            f"runtime DLL architecture is {record.get('architecture')!r}, expected {expected!r}"
        )
    libraries = manifest.get("libraries")
    dynamic_entries = libraries.get("dynamic") if isinstance(libraries, dict) else None
    if not isinstance(dynamic_entries, list) or len(dynamic_entries) != 2:
        fail("dynamic Windows manifest must contain the import-library linkage pair")
    import_path = dynamic_entries[1].get("path")
    if record.get("import_library_path") != import_path:
        fail("runtime DLL must identify its exact related import library")
    source = record.get("source")
    expected_source = {
        "repository": manifest.get("repository"),
        "tag": manifest.get("tag"),
        "commit": manifest.get("commit"),
        "version": manifest.get("version"),
    }
    if source != expected_source:
        fail("runtime DLL source metadata is not tied to the pinned SymCrypt source")
    version_info = record.get("version_info")
    if not isinstance(version_info, dict):
        fail("runtime DLL must record exact PE file and product version metadata")
    prefix = (
        f"{manifest['version']['api']}."
        f"{manifest['version']['minor']}."
        f"{manifest['version']['patch']}."
    )
    for field in ("file_version", "product_version"):
        value = require_identity(version_info.get(field), f"runtime.version_info.{field}")
        if not value.startswith(prefix):
            fail(f"runtime DLL {field} {value!r} is not pinned version {prefix}*")
    return record


def verify_runtime_artifact(
    manifest_path: pathlib.Path,
    manifest: dict,
    target: str,
    artifact: pathlib.Path,
    require_recorded_path: bool,
) -> None:
    runtime = manifest.get("runtime")
    record = validate_runtime_record(
        target,
        manifest,
        runtime.get("dynamic") if isinstance(runtime, dict) else None,
    )
    recorded = (manifest_path.parent / record["path"]).resolve()
    supplied = artifact.resolve()
    if require_recorded_path and supplied != recorded:
        fail(f"runtime DLL is '{supplied}', manifest requires '{recorded}'")
    if not supplied.is_file():
        fail(f"missing runtime DLL: {supplied}")
    actual_hash = sha256(supplied)
    if actual_hash != record.get("sha256"):
        fail(
            f"SHA-256 mismatch for runtime DLL {supplied}: "
            f"found {actual_hash}, expected {record.get('sha256')}"
        )
    kind, architecture = inspect_binary(supplied)
    expected = expected_arch(target)
    if architecture != expected or architecture != record.get("architecture"):
        fail(f"wrong architecture for runtime DLL {supplied}: found {architecture}, expected {expected}")
    if kind != "pe":
        fail(f"runtime DLL format mismatch for {supplied}: found {kind}, expected pe")


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

    compiler = {
        "executable": args.compiler_executable,
        "producer": args.compiler_producer,
        "version": args.compiler_version,
        "target": args.compiler_target,
        "architecture": args.compiler_architecture,
        "toolchain": {
            "kind": args.compiler_toolchain_kind,
            "version": args.compiler_toolchain_version,
            "installation": args.compiler_toolchain_installation,
        },
    }
    if args.compiler_toolchain_installation_version:
        compiler["toolchain"]["installation_version"] = (
            args.compiler_toolchain_installation_version
        )
    validate_compiler(args.target, compiler)

    runtime: dict[str, dict] = {}
    if args.runtime_library:
        if not args.target.endswith("-windows-msvc"):
            fail("--runtime-library is valid only for dynamic Windows fixtures")
        path = pathlib.Path(args.runtime_library).resolve()
        try:
            relative = path.relative_to(fixture_root)
        except ValueError:
            fail(f"runtime DLL is outside fixture root '{fixture_root}': {path}")
        if not path.is_file():
            fail(f"missing runtime DLL: {path}")
        kind, arch = inspect_binary(path)
        expected = expected_arch(args.target)
        if kind != "pe" or arch != expected:
            fail(
                f"wrong architecture or format for runtime DLL {path}: "
                f"found {kind}/{arch}, expected pe/{expected}"
            )
        dynamic_import = entries_by_linkage["dynamic"][1]["path"]
        validate_import_relationship(
            fixture_root / dynamic_import,
            expected_windows_dll(pin),
        )
        runtime["dynamic"] = {
            "role": "core-runtime",
            "path": relative.as_posix(),
            "sha256": sha256(path),
            "format": kind,
            "architecture": arch,
            "expected_filename": expected_windows_dll(pin),
            "import_library_path": dynamic_import,
            "source": {
                "repository": pin["repository"],
                "tag": pin["tag"],
                "commit": pin["commit"],
                "version": pin["version"],
            },
            "version_info": {
                "file_version": args.runtime_file_version,
                "product_version": args.runtime_product_version,
            },
        }
    if args.target.endswith("-windows-msvc") and "dynamic" not in runtime:
        fail("dynamic Windows fixture creation requires --runtime-library")

    manifest = {
        "schema": pin["schema"],
        "repository": pin["repository"],
        "tag": pin["tag"],
        "commit": pin["commit"],
        "version": pin["version"],
        "jitterentropy_commit": pin["jitterentropy_commit"],
        "target": args.target,
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "compiler": compiler,
        "build_options": args.build_option,
        "libraries": entries_by_linkage,
        "runtime": runtime,
    }
    if args.target.endswith("-windows-msvc"):
        validate_runtime_record(args.target, manifest, runtime["dynamic"])
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
    validate_compiler(args.target, manifest.get("compiler"))
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
    manifest_libraries = manifest.get("libraries")
    entries = manifest_libraries.get(args.linkage) if isinstance(manifest_libraries, dict) else None
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
    if args.target.endswith("-windows-msvc") and args.linkage == "dynamic":
        runtime = manifest.get("runtime")
        record = validate_runtime_record(
            args.target,
            manifest,
            runtime.get("dynamic") if isinstance(runtime, dict) else None,
        )
        validate_import_relationship(
            pathlib.Path(args.library[1]).resolve(),
            record["expected_filename"],
        )
        supplied_runtime = pathlib.Path(args.runtime) if args.runtime else root / record["path"]
        verify_runtime_artifact(manifest_path, manifest, args.target, supplied_runtime, True)
    print(f"verified SymCrypt {pin['tag']} {args.target} {args.linkage} fixture provenance")


def verify_runtime(args: argparse.Namespace) -> None:
    pin = load_json(PIN_PATH)
    manifest_path = pathlib.Path(args.manifest).resolve()
    manifest = load_json(manifest_path)
    for field in ("schema", "repository", "tag", "commit", "version", "jitterentropy_commit"):
        if manifest.get(field) != pin.get(field):
            fail(f"manifest {field} is {manifest.get(field)!r}, expected {pin.get(field)!r}")
    if manifest.get("target") != args.target or not args.target.endswith("-windows-msvc"):
        fail(f"runtime verification requires the manifest's Windows target, found {args.target!r}")
    validate_compiler(args.target, manifest.get("compiler"))
    verify_runtime_artifact(
        manifest_path,
        manifest,
        args.target,
        pathlib.Path(args.artifact),
        False,
    )
    print(f"verified pinned runtime DLL copy for {args.target}")


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
    create_parser.add_argument("--runtime-library")
    create_parser.add_argument("--runtime-file-version")
    create_parser.add_argument("--runtime-product-version")
    create_parser.add_argument("--compiler-executable", required=True)
    create_parser.add_argument("--compiler-producer", required=True)
    create_parser.add_argument("--compiler-version", required=True)
    create_parser.add_argument("--compiler-target", required=True)
    create_parser.add_argument("--compiler-architecture", required=True)
    create_parser.add_argument("--compiler-toolchain-kind", required=True)
    create_parser.add_argument("--compiler-toolchain-version", required=True)
    create_parser.add_argument("--compiler-toolchain-installation", required=True)
    create_parser.add_argument("--compiler-toolchain-installation-version")
    create_parser.set_defaults(function=create)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--target", required=True)
    verify_parser.add_argument("--linkage", required=True)
    verify_parser.add_argument("--library", action="append", default=[])
    verify_parser.add_argument("--runtime")
    verify_parser.set_defaults(function=verify)
    runtime_parser = sub.add_parser("verify-runtime")
    runtime_parser.add_argument("--manifest", required=True)
    runtime_parser.add_argument("--target", required=True)
    runtime_parser.add_argument("--artifact", required=True)
    runtime_parser.set_defaults(function=verify_runtime)
    return result


if __name__ == "__main__":
    parser_args = parser().parse_args()
    parser_args.function(parser_args)
