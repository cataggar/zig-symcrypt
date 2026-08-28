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
expect_failure full-abi-needs-windows "full ABI matrix requires MSVC/Windows SDK headers" \
    zig build abi -Dheaders_only=true
expect_failure unsupported-arch "unsupported target 'x86-linux" \
    zig build abi-local -Dheaders_only=true -Dtarget=x86-linux-gnu
expect_failure unsupported-os "unsupported target 'wasm32-wasi" \
    zig build abi-local -Dheaders_only=true -Dtarget=wasm32-wasi
expect_failure musl "fixtures are GNU user mode, not musl" \
    zig build abi-local -Dheaders_only=true -Dtarget=x86_64-linux-musl
expect_failure windows-gnu "Windows requires the MSVC ABI/SDK" \
    zig build abi-local -Dheaders_only=true -Dtarget=x86_64-windows-gnu
expect_failure dynamic-archive "expected .so or versioned .so.N" \
    zig build abi-local -Dsymcrypt_libraries=fake.a
expect_failure missing-plus "missing pinned symcrypt_plus" \
    zig build abi-local -Dsymcrypt_libraries=libsymcrypt.so
expect_failure wrong-linux-static-set "wrong static Linux linkage set" \
    zig build abi-local -Dlinkage=static \
      -Dsymcrypt_libraries=libsymcrypt_plus.a \
      -Dsymcrypt_libraries=libsymcrypt_common.a
expect_failure windows-dll "pass the import .lib; the .dll is a runtime artifact" \
    zig build abi-local -Dtarget=x86_64-windows-msvc -Dsymcrypt_libraries=symcrypt.dll
expect_failure mlkem-gate "ML-KEM-768 and RFC 10024" \
    zig build abi-local -Dheaders_only=true -Denable_mlkem=true
expect_failure tls-hybrid-gate "ML-KEM-768 and RFC 10024" \
    zig build abi-local -Dheaders_only=true -Denable_tls_x25519_mlkem768=true

cp -R vendor/symcrypt/include "$scratch/missing-header"
rm "$scratch/missing-header/symcrypt_no_sal.h"
expect_failure missing-header "'symcrypt_no_sal.h' not found" \
    zig build abi-local -Dheaders_only=true -Dsymcrypt_include_dir="$scratch/missing-header"

cp -R vendor/symcrypt/include "$scratch/wrong-version"
sed -i 's/SYMCRYPT_CODE_VERSION_MINOR     13/SYMCRYPT_CODE_VERSION_MINOR     14/' \
    "$scratch/wrong-version/symcrypt_internal_shared.inc"
expect_failure wrong-version "expected 103.13.0, found 103.14.0" \
    zig build abi-local -Dheaders_only=true -Dsymcrypt_include_dir="$scratch/wrong-version"

cp ci/symcrypt-fixtures.json "$scratch/altered-provenance.json"
sed -i 's/286762b7730e2b780678f5ab11fef2b1bad639e0/0000000000000000000000000000000000000000/' \
    "$scratch/altered-provenance.json"
rm -f zig-out/release/zig-symcrypt-0.1.0.tar.gz \
    zig-out/release/zig-symcrypt-0.1.0.tar.gz.sha256
expect_failure altered-provenance "manifest commit" \
    python3 tools/fixture_manifest.py verify \
      --manifest "$scratch/altered-provenance.json" \
      --target x86_64-linux-gnu \
      --linkage dynamic
[ ! -e zig-out/release/zig-symcrypt-0.1.0.tar.gz ] || {
    echo "negative provenance test left a release archive" >&2
    exit 1
}
python3 tools/test_fixture_manifest.py

echo "all negative build diagnostics passed"
