#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if grep -R -n -E '(\.\./SymCrypt|/d/SymCrypt|/d/rust-symcrypt)' \
    --exclude=check-package.sh \
    --exclude-dir=.git --exclude-dir=.zig-cache --exclude-dir=.tools \
    --exclude-dir=.symcrypt-build --exclude-dir=.symcrypt-zig-build .; then
    echo "package contains a developer-local reference path" >&2
    exit 1
fi

scratch=.zig-package-check
rm -rf "$scratch"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch"
cp build.zig build.zig.zon LICENSE NOTICE.md README.md "$scratch/"
cp -R examples src test tools vendor "$scratch/"

(
    cd "$scratch"
    zig build --help >/dev/null
    zig build abi-local -Dheaders_only=true
)

echo "package metadata and header-only build passed"
