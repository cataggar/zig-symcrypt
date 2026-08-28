#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

scratch=.zig-callback-check
rm -rf "$scratch"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch"

include="-Ivendor/symcrypt/include"
zig cc -std=c11 "$include" -c src/callbacks.c -o "$scratch/production.o"
zig cc -std=c11 "$include" -c src/callback_runtime.c -o "$scratch/runtime.o"
zig cc -std=c11 "$include" -c test/callbacks.c -o "$scratch/test.o"
zig ar rcs "$scratch/production.a" "$scratch/production.o" "$scratch/runtime.o"
zig ar rcs "$scratch/test.a" "$scratch/test.o" "$scratch/runtime.o"

production_symbols=$(nm -g --defined-only "$scratch/production.a")
test_symbols=$(nm -g --defined-only "$scratch/test.a")

if printf '%s\n' "$production_symbols" | grep -q 'SymCryptZigTest'; then
    echo "production callback archive exports test controls" >&2
    exit 1
fi

for symbol in \
    SymCryptCallbackAlloc \
    SymCryptCallbackFree \
    SymCryptCallbackRandom \
    SymCryptCallbackAllocateMutexFastInproc \
    SymCryptCallbackFreeMutexFastInproc \
    SymCryptCallbackAcquireMutexFastInproc \
    SymCryptCallbackReleaseMutexFastInproc; do
    printf '%s\n' "$production_symbols" | grep -q "[[:space:]]$symbol$" || {
        echo "production callback archive is missing $symbol" >&2
        exit 1
    }
done

for symbol in \
    SymCryptZigTestFailAllocationAfter \
    SymCryptZigTestDeferAllocationFailureAfter \
    SymCryptZigTestDisableAllocationFailure \
    SymCryptZigTestConsumeDeferredAllocationFailure \
    SymCryptZigTestOutstandingAllocations; do
    printf '%s\n' "$test_symbols" | grep -q "[[:space:]]$symbol$" || {
        echo "test callback archive is missing $symbol" >&2
        exit 1
    }
done

echo "production and test callback symbol separation passed"
