#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
scratch=.zig-negative-fixtures
rm -rf "$scratch"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch"

expect_failure() {
    name=$1
    expected=$2
    shift 2
    if "$@" >"$scratch/$name.log" 2>&1; then
        echo "$name unexpectedly succeeded" >&2
        exit 1
    fi
    grep -F "$expected" "$scratch/$name.log" >/dev/null || {
        echo "$name did not contain: $expected" >&2
        cat "$scratch/$name.log" >&2
        exit 1
    }
}

expect_failure missing-libraries "no SymCrypt libraries supplied" zig build
expect_failure unsupported-arch "unsupported target 'x86-linux" \
    zig build abi -Dheaders_only=true -Dtarget=x86-linux-gnu
expect_failure musl "fixtures are GNU user mode, not musl" \
    zig build abi -Dheaders_only=true -Dtarget=x86_64-linux-musl
expect_failure windows-gnu "Windows requires the MSVC ABI/SDK" \
    zig build abi -Dheaders_only=true -Dtarget=x86_64-windows-gnu
expect_failure dynamic-archive "expected .so or versioned .so.N" \
    zig build abi -Dsymcrypt_libraries=fake.a
expect_failure windows-dll "pass the import .lib; the .dll is a runtime artifact" \
    zig build abi -Dtarget=x86_64-windows-msvc -Dsymcrypt_libraries=symcrypt.dll

cp -R vendor/symcrypt/include "$scratch/missing-header"
rm "$scratch/missing-header/symcrypt_no_sal.h"
expect_failure missing-header "'symcrypt_no_sal.h' not found" \
    zig build abi -Dheaders_only=true -Dsymcrypt_include_dir="$scratch/missing-header"

cp -R vendor/symcrypt/include "$scratch/wrong-version"
sed -i 's/SYMCRYPT_CODE_VERSION_MINOR     13/SYMCRYPT_CODE_VERSION_MINOR     14/' \
    "$scratch/wrong-version/symcrypt_internal_shared.inc"
expect_failure wrong-version "expected 103.13.0, found 103.14.0" \
    zig build abi -Dheaders_only=true -Dsymcrypt_include_dir="$scratch/wrong-version"

echo "all negative build diagnostics passed"
