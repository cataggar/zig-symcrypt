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
ACTION_PINS = {
    "actions/checkout": "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a",
    "cataggar/ghr/actions/install": "c4be68b52d67d7acd2a7fe6c1e5f126e1754176e",
}
GHR_VERSION = "v0.8.1"
ZIG_TOOL = (
    "cataggar/zig@v0.16.0 "
    "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
)
EXPECTED_GHR_STEPS = {
    "linux-validation.yml": 1,
    "release-validation.yml": 1,
    "release.yml": 1,
    "windows-validation.yml": 2,
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

workflow_dir = ROOT / ".github/workflows"
ghr_step_pattern = re.compile(
    r"(?m)^(?P<indent>\s*)- name: Install Zig via ghr\n"
    rf"(?P=indent)  uses: cataggar/ghr/actions/install@{ACTION_PINS['cataggar/ghr/actions/install']} # {GHR_VERSION}\n"
    r"(?P=indent)  env:\n"
    r"(?P=indent)    GH_TOKEN: \$\{\{ github\.token \}\}\n"
    r"(?P=indent)  with:\n"
    rf"(?P=indent)    ghr-version: {GHR_VERSION}\n"
    r"(?P=indent)    tools: >-\n"
    r"(?P=indent)      cataggar/zig@v0\.16\.0\n"
    r"(?P=indent)      RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti\+JO/wCYvhbAb/U$"
)
uses_pattern = re.compile(r"(?m)^\s+(?:-\s+)?uses:\s+([^#\s]+)")
for workflow_name, expected_ghr_steps in EXPECTED_GHR_STEPS.items():
    workflow = (workflow_dir / workflow_name).read_text(encoding="utf-8")
    if "mlugg/setup-zig" in workflow:
        fail(f"{workflow_name} still invokes mlugg/setup-zig")
    if not re.search(
        r"(?m)^permissions:\n  contents: read\n  attestations: read$",
        workflow,
    ):
        fail(f"{workflow_name} does not grant exact read permissions for ghr")

    actual_ghr_steps = len(ghr_step_pattern.findall(workflow))
    if actual_ghr_steps != expected_ghr_steps:
        fail(
            f"{workflow_name} has {actual_ghr_steps} exact ghr Zig install steps, "
            f"expected {expected_ghr_steps}"
        )

    for action_reference in uses_pattern.findall(workflow):
        if action_reference.startswith("./"):
            continue
        if "@" not in action_reference:
            fail(f"{workflow_name} action is not pinned: {action_reference}")
        action, pin = action_reference.rsplit("@", 1)
        expected_pin = ACTION_PINS.get(action)
        if expected_pin is None:
            fail(f"{workflow_name} action is not allow-listed: {action}")
        if pin != expected_pin:
            fail(
                f"{workflow_name} action {action} is pinned to {pin}, "
                f"expected {expected_pin}"
            )

release_workflow = (workflow_dir / "release.yml").read_text(encoding="utf-8")
if not re.search(
    r"(?m)^    permissions:\n      contents: write\n      attestations: read$",
    release_workflow,
):
    fail("release.yml publish job does not preserve contents: write with attestations: read")

print(
    "all packaged SymCrypt version, commit, generated-header, submodule, "
    f"workflow action, ghr {GHR_VERSION}, and Zig {ZIG_TOOL} pins agree"
)
