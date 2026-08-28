#!/usr/bin/env python3
"""Stage the publish allow-list and run one external package consumer."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOW = (
    "build.zig",
    "build.zig.zon",
    "ci",
    "docs",
    "LICENSE",
    "NOTICE.md",
    "README.md",
    "examples",
    "src",
    "test",
    "tools",
    "vendor",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--linkage", choices=("dynamic", "static"), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--optimize", required=True)
    parser.add_argument("--include", required=True)
    parser.add_argument("--checked", required=True)
    parser.add_argument("--legacy", required=True)
    parser.add_argument("--legacy-rsa", required=True)
    parser.add_argument("--provenance")
    parser.add_argument("--library", action="append", default=[])
    args = parser.parse_args()

    stage = ROOT / ".zig-consumer-stage" / args.linkage
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    try:
        for item in ALLOW:
            source = ROOT / item
            destination = stage / item
            if source.is_dir():
                shutil.copytree(
                    source,
                    destination,
                    ignore=shutil.ignore_patterns(
                        ".zig-cache", "zig-out", "__pycache__", "*.pyc", "*.a", "*.so",
                        "*.so.*", "*.dll", "*.lib", "*.exe", "*.o", "*.obj"
                    ),
                )
            else:
                shutil.copy2(source, destination)
        include = pathlib.Path(args.include).resolve()
        bundled = (ROOT / "vendor/symcrypt/include").resolve()
        if include == bundled:
            include = stage / "vendor/symcrypt/include"
        command = [
            "zig",
            "build",
            "run",
            f"-Dtarget={args.target}",
            f"-Doptimize={args.optimize}",
            f"-Dsymcrypt_include_dir={include}",
            f"-Dsymcrypt_checked={args.checked}",
            f"-Dlegacy={args.legacy}",
            f"-Denable_legacy_rsa_pkcs1_encryption={args.legacy_rsa}",
        ]
        command.extend(f"-Dsymcrypt_libraries={pathlib.Path(path).resolve()}" for path in args.library)
        if args.provenance:
            command.append(f"-Dsymcrypt_provenance={pathlib.Path(args.provenance).resolve()}")
        subprocess.run(command, cwd=stage / "examples" / args.linkage, check=True)
    finally:
        shutil.rmtree(ROOT / ".zig-consumer-stage", ignore_errors=True)


if __name__ == "__main__":
    main()
