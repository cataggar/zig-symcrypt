const std = @import("std");
const c = @import("c.zig").raw;
const options = @import("symcrypt_options");
const InitError = @import("errors.zig").InitError;

const State = enum(u8) {
    uninitialized,
    initializing,
    ready,
    incompatible,
    failed,
};

var state: State = .uninitialized;
var test_claimed = false;
var test_claim_release = false;
var test_waiters: usize = 0;

pub const TestHooks = struct {
    pub fn prepare() void {
        if (!options.init_test_hooks) @compileError("initialization test hooks are disabled");
        std.debug.assert(@atomicLoad(State, &state, .acquire) == .uninitialized);
        @atomicStore(bool, &test_claimed, false, .monotonic);
        @atomicStore(bool, &test_claim_release, false, .monotonic);
        @atomicStore(usize, &test_waiters, 0, .release);
    }

    pub fn claimed() bool {
        return @atomicLoad(bool, &test_claimed, .acquire);
    }

    pub fn waiterCount() usize {
        return @atomicLoad(usize, &test_waiters, .acquire);
    }

    pub fn releaseClaim() void {
        @atomicStore(bool, &test_claim_release, true, .release);
    }
};

fn testAfterClaim() void {
    if (!options.init_test_hooks) return;
    @atomicStore(bool, &test_claimed, true, .release);
    while (!@atomicLoad(bool, &test_claim_release, .acquire)) {
        std.Thread.yield() catch {};
    }
}

fn testWhileInitializing() void {
    if (!options.init_test_hooks) {
        std.Thread.yield() catch {};
        return;
    }

    _ = @atomicRmw(usize, &test_waiters, .Add, 1, .acq_rel);
    while (@atomicLoad(State, &state, .acquire) == .initializing) {
        std.Thread.yield() catch {};
    }
}

pub fn ensureInitialized() InitError!void {
    return initializeVersion(103, 13);
}

pub fn initializeVersion(api: u32, minor: u32) InitError!void {
    while (true) {
        switch (@atomicLoad(State, &state, .acquire)) {
            .ready => return,
            .incompatible => return error.IncompatibleSymCryptVersion,
            .failed => return error.SymCryptInitializationFailed,
            .initializing => testWhileInitializing(),
            .uninitialized => {
                if (@cmpxchgStrong(
                    State,
                    &state,
                    .uninitialized,
                    .initializing,
                    .acquire,
                    .monotonic,
                ) != null) continue;

                testAfterClaim();
                if (comptime std.mem.eql(u8, options.linkage, "dynamic")) {
                    const result = c.SymCryptModuleInitEx(api, minor);
                    if (result == c.SYMCRYPT_NO_ERROR) {
                        @atomicStore(State, &state, .ready, .release);
                        return;
                    }
                    if (result == c.SYMCRYPT_INVALID_ARGUMENT) {
                        @atomicStore(State, &state, .incompatible, .release);
                        return error.IncompatibleSymCryptVersion;
                    }
                    @atomicStore(State, &state, .failed, .release);
                    return error.SymCryptInitializationFailed;
                } else {
                    c.SymCryptInit();
                    @atomicStore(State, &state, .ready, .release);
                    return;
                }
            },
        }
    }
}
