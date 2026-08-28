#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if grep -R -n -E '(\.\./SymCrypt|/d/SymCrypt|/d/rust-symcrypt)' \
    --exclude=check-package.sh \
    --exclude-dir=.git --exclude-dir=.zig-cache --exclude-dir=.tools \
    --exclude-dir=.symcrypt-build --exclude-dir=.symcrypt-zig-build \
    --exclude-dir=.symcrypt-ci --exclude-dir=.symcrypt-ci-source .; then
    echo "package contains a developer-local reference path" >&2
    exit 1
fi

if find . -type f \( -name '*.a' -o -name '*.so' -o -name '*.so.*' -o \
    -name '*.dll' -o -name '*.lib' -o -name '*.exe' -o -name '*.o' -o -name '*.obj' \) \
    -not -path './.git/*' -not -path '*/.zig-cache/*' -not -path '*/zig-out/*' \
    -not -path './.symcrypt-ci/*' -not -path './.symcrypt-ci-source/*' \
    -not -path './.symcrypt-build/*' -not -path './.symcrypt-zig-build/*' \
    -print | grep .; then
    echo "source package contains a compiled binary" >&2
    exit 1
fi

scratch=.zig-package-check
rm -rf "$scratch"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch"
stage="$scratch/stage"
extract="$scratch/extract"
mkdir "$stage" "$extract"
cp build.zig build.zig.zon LICENSE NOTICE.md README.md "$stage/"
cp -R ci docs examples src test tools vendor "$stage/"

(
    cd "$stage"
    tar -czf ../package.tar.gz \
        build.zig build.zig.zon ci docs LICENSE NOTICE.md README.md examples src test tools vendor
)
tar -xzf "$scratch/package.tar.gz" -C "$extract"

expected="LICENSE
NOTICE.md
README.md
build.zig
build.zig.zon
ci
docs
examples
src
test
tools
vendor"
actual=$(find "$extract" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
[ "$actual" = "$expected" ] || {
    echo "package top-level allow-list mismatch" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    exit 1
}

for required in \
    LICENSE NOTICE.md README.md \
    ci/symcrypt-fixtures.json \
    docs/supported-targets.md docs/linking.md docs/initialization.md docs/fips.md \
    docs/releasing.md docs/test-coverage.md \
    examples/dynamic/build.zig examples/dynamic/build.zig.zon examples/dynamic/src/main.zig \
    examples/static/build.zig examples/static/build.zig.zon examples/static/src/main.zig \
    src/symcrypt_version.zig \
    vendor/symcrypt/LICENSE.txt vendor/symcrypt/NOTICE.txt vendor/symcrypt/VERSION \
    vendor/symcrypt/include/symcrypt.h; do
    [ -f "$extract/$required" ] || {
        echo "package is missing required file: $required" >&2
        exit 1
    }
done

(
    cd "$extract"
    zig build --help >/dev/null
    zig build abi-local -Dheaders_only=true
)

echo "package extraction, allow-list, metadata, and header-only rebuild passed"
