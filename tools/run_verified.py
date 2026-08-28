#!/usr/bin/env python3
"""Verify and stage the exact pinned Windows DLL immediately before execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("executable")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if not args.target.endswith("-windows-msvc"):
        raise SystemExit("verified runtime launcher is only valid for Windows MSVC targets")

    manifest_path = pathlib.Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    runtime = manifest.get("runtime", {}).get("dynamic", {})
    runtime_path = (manifest_path.parent / runtime.get("path", "")).resolve()

    verify = [
        "python3",
        str(ROOT / "tools/fixture_manifest.py"),
        "verify",
        "--manifest",
        str(manifest_path),
        "--target",
        args.target,
        "--linkage",
        "dynamic",
    ]
    for library in args.library:
        verify.extend(("--library", str(pathlib.Path(library).resolve())))
    subprocess.run(verify, check=True)

    executable = pathlib.Path(args.executable).resolve()
    identity = hashlib.sha256(str(executable).encode("utf-8")).hexdigest()[:16]
    stage = ROOT / ".zig-verified-runs" / f"{executable.stem}-{identity}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    try:
        staged_executable = stage / executable.name
        staged_runtime = stage / runtime["expected_filename"]
        shutil.copy2(executable, staged_executable)
        shutil.copy2(runtime_path, staged_runtime)
        subprocess.run(
            [
                "python3",
                str(ROOT / "tools/fixture_manifest.py"),
                "verify-runtime",
                "--manifest",
                str(manifest_path),
                "--target",
                args.target,
                "--artifact",
                str(staged_runtime),
            ],
            check=True,
        )
        environment = os.environ.copy()
        environment["PATH"] = str(stage) + os.pathsep + environment.get("PATH", "")
        subprocess.run(
            [str(staged_executable), *args.arguments],
            cwd=stage,
            env=environment,
            check=True,
        )
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    main()
