#!/usr/bin/env python3
"""Create the source-only release archive after all build dependencies pass."""

from __future__ import annotations

import argparse
import hashlib
import json
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--provenance", required=True)
    args = parser.parse_args()
    if args.tag != EXPECTED_TAG:
        fail(f"tag '{args.tag}' does not match package version {PACKAGE_VERSION} ({EXPECTED_TAG})")
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True
    ).strip()
    if dirty:
        fail("tracked worktree is not clean")
    manifest = json.loads(pathlib.Path(args.provenance).read_text(encoding="utf-8"))
    if manifest.get("commit") != "286762b7730e2b780678f5ab11fef2b1bad639e0":
        fail("fixture provenance is not the pinned SymCrypt commit")
    if manifest.get("version") != {"api": 103, "minor": 13, "patch": 0}:
        fail("fixture provenance is not exact SymCrypt 103.13.0")

    output = ROOT / "zig-out" / "release"
    staging = ROOT / ".zig-release-staging"
    archive = output / f"zig-symcrypt-{PACKAGE_VERSION}.tar.gz"
    if staging.exists():
        shutil.rmtree(staging)
    output.mkdir(parents=True, exist_ok=True)
    archive.unlink(missing_ok=True)
    package_root = staging / f"zig-symcrypt-{PACKAGE_VERSION}"
    package_root.mkdir(parents=True)
    try:
        for item in ALLOW:
            source = ROOT / item
            destination = package_root / item
            if source.is_dir():
                shutil.copytree(
                    source,
                    destination,
                    ignore=shutil.ignore_patterns(
                        ".zig-cache", "zig-out", "__pycache__", "*.pyc", "*.dll", "*.lib",
                        "*.so", "*.so.*", "*.a", "*.exe", "provenance.json"
                    ),
                )
            else:
                shutil.copy2(source, destination)
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            tar.add(package_root, arcname=package_root.name)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="ascii"
    )
    print(archive)


if __name__ == "__main__":
    main()
