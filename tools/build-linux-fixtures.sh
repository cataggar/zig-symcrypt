#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /path/to/SymCrypt /path/to/output" >&2
    exit 2
fi

source_dir=$1
output_dir=$2
expected=286762b7730e2b780678f5ab11fef2b1bad639e0
actual=$(git -C "$source_dir" rev-parse HEAD)
[ "$actual" = "$expected" ] || {
    echo "expected SymCrypt v103.13.0 commit $expected, found $actual" >&2
    exit 1
}

cmake -S "$source_dir" -B "$output_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DSYMCRYPT_UNIT_TESTS=OFF \
    -DSYMCRYPT_FIPS_BUILD=OFF \
    -DSYMCRYPT_FIPS_POSTPROCESS=OFF \
    -DSYMCRYPT_STRIP_BINARY=OFF
cmake --build "$output_dir" --parallel

echo "shared: $output_dir/module/generic/libsymcrypt.so"
echo "static archives (preserve this order):"
echo "  $output_dir/lib/libsymcrypt_posixusermode.a"
echo "  $output_dir/lib/libsymcrypt_common.a"
echo "  $output_dir/lib/libsymcrypt_mlkem.a"
