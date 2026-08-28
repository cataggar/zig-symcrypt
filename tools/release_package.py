#!/usr/bin/env python3
"""Run release gates, then atomically install the source archive/checksum pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE_VERSION = "0.1.0"
EXPECTED_TAG = f"v{PACKAGE_VERSION}"
ALLOW = (
    "build.zig",
    "build.zig.zon",
    "LICENSE",
    "NOTICE.md",
    "README.md",
    "ci",
    "docs",
    "examples",
    "src",
    "test",
    "tools",
    "vendor",
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"release package refused: {message}")


def remove_tree(path: pathlib.Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


def validate_manifest(path: pathlib.Path) -> None:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read fixture provenance '{path}': {error}")
    if manifest.get("commit") != "286762b7730e2b780678f5ab11fef2b1bad639e0":
        fail("fixture provenance is not the pinned SymCrypt commit")
    if manifest.get("version") != {"api": 103, "minor": 13, "patch": 0}:
        fail("fixture provenance is not exact SymCrypt 103.13.0")


def run_validation(args: argparse.Namespace) -> None:
    command = [
        args.zig,
        "build",
        "abi-release-gate",
        "format-check",
        "package-check",
        "consumer-example",
        f"-Dtarget={args.target}",
        f"-Doptimize={args.optimize}",
        f"-Dlinkage={args.linkage}",
        f"-Dsymcrypt_include_dir={pathlib.Path(args.include).resolve()}",
        f"-Dsymcrypt_checked={args.checked}",
        f"-Dlegacy={args.legacy}",
        f"-Denable_legacy_rsa_pkcs1_encryption={args.legacy_rsa}",
        f"-Dsymcrypt_provenance={pathlib.Path(args.provenance).resolve()}",
    ]
    command.extend(
        f"-Dsymcrypt_libraries={pathlib.Path(library).resolve()}"
        for library in args.library
    )
    try:
        subprocess.run(command, cwd=ROOT, check=True)
    except subprocess.CalledProcessError as error:
        fail(f"release validation command failed with exit code {error.returncode}")


def copy_package(package_root: pathlib.Path) -> None:
    for item in ALLOW:
        source = ROOT / item
        destination = package_root / item
        if source.is_dir():
            shutil.copytree(
                source,
                destination,
                ignore=shutil.ignore_patterns(
                    ".zig-cache",
                    "zig-out",
                    "__pycache__",
                    "*.pyc",
                    "*.dll",
                    "*.lib",
                    "*.so",
                    "*.so.*",
                    "*.a",
                    "*.exe",
                    "provenance.json",
                ),
            )
        else:
            shutil.copy2(source, destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--optimize", required=True)
    parser.add_argument("--linkage", choices=("dynamic", "static"), required=True)
    parser.add_argument("--include", required=True)
    parser.add_argument("--checked", required=True)
    parser.add_argument("--legacy", required=True)
    parser.add_argument("--legacy-rsa", required=True)
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("--zig", default="zig")
    args = parser.parse_args()

    output = ROOT / "zig-out" / "release"
    staging = ROOT / ".zig-release-staging"
    remove_tree(output)
    remove_tree(staging)

    if args.tag != EXPECTED_TAG:
        fail(f"tag '{args.tag}' does not match package version {PACKAGE_VERSION} ({EXPECTED_TAG})")
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT,
        text=True,
    ).strip()
    if dirty:
        fail("tracked worktree is not clean")
    validate_manifest(pathlib.Path(args.provenance))

    try:
        run_validation(args)
        if os.environ.get("SYMCRYPT_ZIG_RELEASE_FAIL_STAGE") == "after-validation":
            fail("induced failure after validation")

        staged_output = staging / "release"
        package_root = staging / f"zig-symcrypt-{PACKAGE_VERSION}"
        staged_output.mkdir(parents=True)
        package_root.mkdir(parents=True)
        copy_package(package_root)

        archive = staged_output / f"zig-symcrypt-{PACKAGE_VERSION}.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            tar.add(package_root, arcname=package_root.name)
        if os.environ.get("SYMCRYPT_ZIG_RELEASE_FAIL_STAGE") == "after-archive":
            fail("induced failure after archive")

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum = archive.with_suffix(archive.suffix + ".sha256")
        checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
        if os.environ.get("SYMCRYPT_ZIG_RELEASE_FAIL_STAGE") == "after-checksum":
            fail("induced failure after checksum")

        output.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_output, output)
        print(output / archive.name)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


if __name__ == "__main__":
    main()
