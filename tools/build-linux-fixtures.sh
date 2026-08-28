#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 /path/to/SymCrypt /path/to/output x86_64|aarch64" >&2
    exit 2
fi

source_dir=$1
output_dir=$2
requested_arch=$3
expected=286762b7730e2b780678f5ab11fef2b1bad639e0
expected_tag=v103.13.0

case "$requested_arch" in
    x86_64)
        upstream_arch=amd64
        target=x86_64-linux-gnu
        elf_machine="Advanced Micro Devices X86-64"
        ;;
    aarch64)
        upstream_arch=arm64
        target=aarch64-linux-gnu
        elf_machine=AArch64
        ;;
    *)
        echo "unsupported Linux fixture architecture '$requested_arch'; expected x86_64 or aarch64" >&2
        exit 2
        ;;
esac

case "$(uname -m)" in
    x86_64|amd64) host_arch=x86_64 ;;
    aarch64|arm64) host_arch=aarch64 ;;
    *)
        echo "unsupported native Linux build host architecture '$(uname -m)'" >&2
        exit 1
        ;;
esac
[ "$host_arch" = "$requested_arch" ] || {
    echo "refusing to build $requested_arch fixtures on native host $host_arch" >&2
    exit 1
}

origin=$(git -C "$source_dir" remote get-url origin)
case "$origin" in
    https://github.com/microsoft/SymCrypt|https://github.com/microsoft/SymCrypt.git|git@github.com:microsoft/SymCrypt.git) ;;
    *)
        echo "expected canonical Microsoft SymCrypt origin, found '$origin'" >&2
        exit 1
        ;;
esac

actual=$(git -C "$source_dir" rev-parse HEAD^{commit})
[ "$actual" = "$expected" ] || {
    echo "expected SymCrypt $expected_tag commit $expected, found $actual" >&2
    exit 1
}
tag_commit=$(git -C "$source_dir" rev-parse "refs/tags/$expected_tag^{commit}") || {
    echo "required provenance tag $expected_tag is unavailable" >&2
    exit 1
}
[ "$tag_commit" = "$expected" ] || {
    echo "expected $expected_tag to resolve to $expected, found $tag_commit" >&2
    exit 1
}
[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=no)" ] || {
    echo "SymCrypt source has tracked modifications before fixture build" >&2
    exit 1
}
gitlink_line=$(git -C "$source_dir" ls-tree HEAD 3rdparty/jitterentropy-library)
set -- $gitlink_line
jitterentropy=${3:-missing}
[ "$jitterentropy" = "887c9871ea110e397812ff7f3b28a6269f0a2ffc" ] || {
    echo "unexpected Jitterentropy gitlink: $jitterentropy" >&2
    exit 1
}
initialized=$(git -C "$source_dir/3rdparty/jitterentropy-library" rev-parse HEAD 2>/dev/null || true)
[ "$initialized" = "$jitterentropy" ] || {
    echo "initialize only the pinned 3rdparty/jitterentropy-library submodule before building" >&2
    exit 1
}
mkdir -p "$(dirname "$output_dir")"
python3 - "$source_dir/version.json" <<'PY'
import json
import pathlib
import sys

version = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if version != {"major": 103, "minor": 13, "patch": 0}:
    raise SystemExit(f"expected SymCrypt version 103.13.0, found {version!r}")
PY

python3 "$source_dir/scripts/build.py" cmake "$output_dir" \
    --arch "$upstream_arch" \
    --config Release \
    --clean

shared=$output_dir/module/generic/libsymcrypt.so
static_environment=$output_dir/lib/libsymcrypt_posixusermode.a
static_common=$output_dir/lib/libsymcrypt_common.a
static_mlkem=$output_dir/lib/libsymcrypt_mlkem.a
static_plus=$output_dir/lib/libsymcrypt_plus.a
for artifact in "$shared" "$static_plus" "$static_environment" "$static_common" "$static_mlkem"; do
    [ -f "$artifact" ] || {
        echo "missing expected $requested_arch fixture artifact: $artifact" >&2
        exit 1
    }
    readelf -h "$artifact" 2>/dev/null | grep -F "Machine:" | grep -F "$elf_machine" >/dev/null || {
        echo "fixture artifact is not $requested_arch ELF: $artifact" >&2
        exit 1
    }
done
readelf -d "$shared" | grep -F '(SONAME)' | grep -F 'libsymcrypt.so.103' >/dev/null || {
    echo "shared fixture has an unexpected SONAME: $shared" >&2
    exit 1
}

compiler_cache=$(sed -n 's/^CMAKE_C_COMPILER:FILEPATH=//p' "$output_dir/CMakeCache.txt")
[ -n "$compiler_cache" ] || {
    echo "CMake did not record the C compiler executable" >&2
    exit 1
}
compiler=$(readlink -f "$compiler_cache")
compiler_metadata=$(find "$output_dir/CMakeFiles" -name CMakeCCompiler.cmake -print -quit)
[ -n "$compiler_metadata" ] || {
    echo "CMake did not emit C compiler identity metadata" >&2
    exit 1
}
compiler_producer=$(sed -n 's/^set(CMAKE_C_COMPILER_ID "\(.*\)")/\1/p' "$compiler_metadata")
compiler_version=$(sed -n 's/^set(CMAKE_C_COMPILER_VERSION "\(.*\)")/\1/p' "$compiler_metadata")
compiler_target=$("$compiler" -dumpmachine)
case "$compiler_producer" in
    GNU) compiler_kind=gcc ;;
    Clang|AppleClang) compiler_kind=clang ;;
    *)
        echo "unsupported CMake C compiler producer '$compiler_producer'" >&2
        exit 1
        ;;
esac
compiler_installation=$(dirname "$(dirname "$compiler")")

python3 "$(dirname "$0")/fixture_manifest.py" create \
    --root "$output_dir" \
    --source "$source_dir" \
    --target "$target" \
    --build-option "scripts/build.py cmake" \
    --build-option "config=Release" \
    --build-option "fips=upstream-default" \
    --build-option "fips-postprocess=upstream-default" \
    --compiler-executable "$compiler" \
    --compiler-producer "$compiler_producer" \
    --compiler-version "$compiler_version" \
    --compiler-target "$compiler_target" \
    --compiler-architecture "$requested_arch" \
    --compiler-toolchain-kind "$compiler_kind" \
    --compiler-toolchain-version "$compiler_version" \
    --compiler-toolchain-installation "$compiler_installation" \
    --library "dynamic:plus:$static_plus" \
    --library "dynamic:core:$shared" \
    --library "static:plus:$static_plus" \
    --library "static:environment:$static_environment" \
    --library "static:common:$static_common" \
    --library "static:mlkem:$static_mlkem"

echo "architecture: $requested_arch"
echo "source: $expected_tag ($expected)"
echo "provenance: $output_dir/provenance.json"
echo "shared: $shared"
echo "static archives (preserve this order):"
echo "  $static_plus"
echo "  $static_environment"
echo "  $static_common"
echo "  $static_mlkem"
