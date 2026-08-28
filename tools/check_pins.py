#!/usr/bin/env python3
"""Verify every packaged SymCrypt version/provenance record agrees."""

from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED = {
    "api": 103,
    "minor": 13,
    "patch": 0,
    "tag": "v103.13.0",
    "commit": "286762b7730e2b780678f5ab11fef2b1bad639e0",
    "jitterentropy_commit": "887c9871ea110e397812ff7f3b28a6269f0a2ffc",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"pin consistency check failed: {message}")


config = json.loads((ROOT / "ci/symcrypt-fixtures.json").read_text(encoding="utf-8"))
for key in ("tag", "commit", "jitterentropy_commit"):
    if config.get(key) != EXPECTED[key]:
        fail(f"fixture {key} is {config.get(key)!r}")
if config.get("version") != {key: EXPECTED[key] for key in ("api", "minor", "patch")}:
    fail("fixture version is not exact 103.13.0")

zig = (ROOT / "src/symcrypt_version.zig").read_text(encoding="utf-8")
for key in ("api", "minor", "patch"):
    if not re.search(rf"pub const {key}: u32 = {EXPECTED[key]};", zig):
        fail(f"Zig version record has wrong {key}")
for key in ("tag", "commit", "jitterentropy_commit"):
    if f'pub const {key} = "{EXPECTED[key]}";' not in zig:
        fail(f"Zig version record has wrong {key}")

vendor = {}
for line in (ROOT / "vendor/symcrypt/VERSION").read_text(encoding="utf-8").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        vendor[key] = value
for key in ("tag", "commit", "api", "minor", "patch"):
    if vendor.get(key) != str(EXPECTED[key]):
        fail(f"vendor VERSION has wrong {key}")

generated = (ROOT / "vendor/symcrypt/include/symcrypt_internal_shared.inc").read_text(
    encoding="utf-8"
)
for macro, key in (
    ("SYMCRYPT_CODE_VERSION_API", "api"),
    ("SYMCRYPT_CODE_VERSION_MINOR", "minor"),
    ("SYMCRYPT_CODE_VERSION_PATCH", "patch"),
):
    if not re.search(rf"#define\s+{macro}\s+{EXPECTED[key]}\b", generated):
        fail(f"generated header has wrong {macro}")

print("all packaged SymCrypt version, commit, generated-header, and submodule pins agree")
