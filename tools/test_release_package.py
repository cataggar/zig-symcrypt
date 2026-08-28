#!/usr/bin/env python3
"""Exercise fail-closed release packaging through the actual Zig build step."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def assert_no_outputs() -> None:
    forbidden = (
        ROOT / "zig-out/release",
        ROOT / ".zig-release-staging",
    )
    for path in forbidden:
        if path.exists():
            raise SystemExit(f"failed release left artifact path behind: {path}")
    for root in (ROOT / "zig-out", ROOT):
        if not root.exists():
            continue
        for pattern in ("zig-symcrypt-*.tmp", "zig-symcrypt-*.partial"):
            leftover = next(root.rglob(pattern), None)
            if leftover is not None:
                raise SystemExit(f"failed release left temporary artifact behind: {leftover}")


def release_command(args: argparse.Namespace, provenance: pathlib.Path) -> list[str]:
    command = [
        "zig",
        "build",
        "release-package",
        f"-Dtarget={args.target}",
        f"-Doptimize={args.optimize}",
        f"-Dlinkage={args.linkage}",
        "-Drelease_tag=v0.1.0",
        f"-Dsymcrypt_provenance={provenance}",
    ]
    command.extend(f"-Dsymcrypt_libraries={pathlib.Path(item).resolve()}" for item in args.library)
    return command


def expect_failure(command: list[str], environment: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, cwd=ROOT, env=environment)
    if result.returncode == 0:
        raise SystemExit(f"negative release command unexpectedly succeeded: {' '.join(command)}")
    assert_no_outputs()


def expect_success(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)
    output = ROOT / "zig-out/release"
    archive = output / "zig-symcrypt-0.1.0.tar.gz"
    checksum = output / "zig-symcrypt-0.1.0.tar.gz.sha256"
    files = sorted(path.name for path in output.iterdir()) if output.is_dir() else []
    if files != [archive.name, checksum.name]:
        raise SystemExit(f"positive release did not atomically install the expected pair: {files}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if checksum.read_text(encoding="ascii") != f"{digest}  {archive.name}\n":
        raise SystemExit("positive release checksum does not match the installed archive")
    shutil.rmtree(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--optimize", default="ReleaseSafe")
    parser.add_argument("--linkage", choices=("dynamic", "static"), required=True)
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("--later-stage", action="store_true")
    parser.add_argument("--positive", action="store_true")
    args = parser.parse_args()

    scratch = ROOT / ".zig-release-negative"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir()
    try:
        manifest = json.loads(pathlib.Path(args.provenance).read_text(encoding="utf-8"))
        manifest["commit"] = "0" * 40
        altered = scratch / "altered-provenance.json"
        altered.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        expect_failure(release_command(args, altered))

        if args.later_stage:
            environment = os.environ.copy()
            environment["SYMCRYPT_ZIG_RELEASE_FAIL_STAGE"] = "after-archive"
            expect_failure(
                release_command(args, pathlib.Path(args.provenance).resolve()),
                environment,
            )
        if args.positive:
            expect_success(release_command(args, pathlib.Path(args.provenance).resolve()))
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)
    print("actual release-package negative and atomic cleanup gates passed")


if __name__ == "__main__":
    main()
