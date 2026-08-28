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

pub fn ensureInitialized() InitError!void {
    return initializeVersion(103, 13);
}

pub fn initializeVersion(api: u32, minor: u32) InitError!void {
    while (true) {
        switch (@atomicLoad(State, &state, .acquire)) {
            .ready => return,
            .incompatible => return error.IncompatibleSymCryptVersion,
            .failed => return error.SymCryptInitializationFailed,
            .initializing => std.Thread.yield() catch {},
            .uninitialized => {
                if (@cmpxchgStrong(
                    State,
                    &state,
                    .uninitialized,
                    .initializing,
                    .acquire,
                    .monotonic,
                ) != null) continue;

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
