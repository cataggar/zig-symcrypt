const std = @import("std");
const builtin = @import("builtin");
const c = @import("c.zig").raw;
const initialization = @import("init.zig");
const errors = @import("errors.zig");
const state_memory = @import("internal/state.zig");
const secure_memory = @import("internal/secure_memory.zig");

const empty_input: u8 = 0;
var test_fail_create_after_allocation = false;

pub fn testFailNextCreateAfterAllocation() void {
    if (!builtin.is_test) @compileError("HMAC test hooks are disabled");
    std.debug.assert(!@atomicRmw(
        bool,
        &test_fail_create_after_allocation,
        .Xchg,
        true,
        .acq_rel,
    ));
}

fn testMaybeFailCreateAfterAllocation() errors.Error!void {
    if (!builtin.is_test) return;
    if (@atomicRmw(
        bool,
        &test_fail_create_after_allocation,
        .Xchg,
        false,
        .acq_rel,
    )) return error.MemoryAllocationFailure;
}

pub fn Api(comptime AlgorithmType: type) type {
    return struct {
        pub const Algorithm = AlgorithmType;

        pub fn Digest(comptime algorithm: Algorithm) type {
            return [Ops(algorithm).digest_length]u8;
        }

        pub fn mac(
            comptime algorithm: Algorithm,
            key: []const u8,
            data: []const u8,
        ) errors.Error!Digest(algorithm) {
            try initialization.ensureInitialized();
            const A = Ops(algorithm);
            var expanded_key: A.Key = undefined;
            @memset(std.mem.asBytes(&expanded_key), 0);
            defer secure_memory.wipe(std.mem.asBytes(&expanded_key));
            try errors.check(A.expandKey(&expanded_key, optionalPtr(key), key.len));
            var result: Digest(algorithm) = undefined;
            A.oneShot(&expanded_key, requiredPtr(data), data.len, result[0..].ptr);
            return result;
        }

        pub fn macInto(
            comptime algorithm: Algorithm,
            key: []const u8,
            data: []const u8,
            output: []u8,
        ) errors.Error!void {
            if (output.len != Ops(algorithm).digest_length) return error.WrongDataSize;
            try initialization.ensureInitialized();
            const A = Ops(algorithm);
            var expanded_key: A.Key = undefined;
            @memset(std.mem.asBytes(&expanded_key), 0);
            defer secure_memory.wipe(std.mem.asBytes(&expanded_key));
            try errors.check(A.expandKey(&expanded_key, optionalPtr(key), key.len));
            A.oneShot(&expanded_key, requiredPtr(data), data.len, output.ptr);
        }

        /// Allocator-owned, stable-address keyed state. Call `deinit` exactly once.
        /// `final` consumes the active computation; call `reset` before reuse.
        pub fn Context(comptime algorithm: Algorithm) type {
            const A = Ops(algorithm);
            const Impl = struct {
                allocator: std.mem.Allocator,
                key: A.Key,
                state: A.State,
                active: bool,
            };

            return opaque {
                const Self = @This();

                pub fn create(
                    allocator: std.mem.Allocator,
                    key: []const u8,
                ) (std.mem.Allocator.Error || errors.Error)!*Self {
                    try initialization.ensureInitialized();
                    const implementation = try state_memory.allocate(Impl, allocator);
                    errdefer state_memory.destroy(Impl, allocator, implementation);
                    implementation.allocator = allocator;
                    try testMaybeFailCreateAfterAllocation();
                    try errors.check(A.expandKey(&implementation.key, optionalPtr(key), key.len));
                    A.init(&implementation.state, &implementation.key);
                    implementation.active = true;
                    return @ptrCast(implementation);
                }

                pub fn update(self: *Self, data: []const u8) errors.Error!void {
                    const implementation = impl(self);
                    if (!implementation.active) return error.InvalidState;
                    if (data.len == 0) return;
                    A.append(&implementation.state, data.ptr, data.len);
                }

                pub fn final(self: *Self) errors.Error!Digest(algorithm) {
                    const implementation = impl(self);
                    if (!implementation.active) return error.InvalidState;
                    var result: Digest(algorithm) = undefined;
                    A.result(&implementation.state, result[0..].ptr);
                    implementation.active = false;
                    return result;
                }

                pub fn reset(self: *Self) errors.Error!void {
                    const implementation = impl(self);
                    A.init(&implementation.state, &implementation.key);
                    implementation.active = true;
                }

                pub fn snapshot(self: *const Self) errors.Error!Digest(algorithm) {
                    const implementation = implConst(self);
                    if (!implementation.active) return error.InvalidState;
                    var temporary: A.State = undefined;
                    @memset(std.mem.asBytes(&temporary), 0);
                    defer secure_memory.wipe(std.mem.asBytes(&temporary));
                    A.copyState(&implementation.state, &implementation.key, &temporary);
                    var result: Digest(algorithm) = undefined;
                    A.result(&temporary, result[0..].ptr);
                    return result;
                }

                pub fn clone(
                    self: *const Self,
                    allocator: std.mem.Allocator,
                ) (std.mem.Allocator.Error || errors.Error)!*Self {
                    const source = implConst(self);
                    if (!source.active) return error.InvalidState;
                    const duplicate = try state_memory.allocate(Impl, allocator);
                    errdefer state_memory.destroy(Impl, allocator, duplicate);
                    duplicate.allocator = allocator;
                    A.copyKey(&source.key, &duplicate.key);
                    A.copyState(&source.state, &duplicate.key, &duplicate.state);
                    duplicate.active = true;
                    return @ptrCast(duplicate);
                }

                pub fn deinit(self: *Self) void {
                    const implementation = impl(self);
                    const allocator = implementation.allocator;
                    state_memory.destroy(Impl, allocator, implementation);
                }

                fn impl(self: *Self) *Impl {
                    return @ptrCast(@alignCast(self));
                }

                fn implConst(self: *const Self) *const Impl {
                    return @ptrCast(@alignCast(self));
                }
            };
        }
    };
}

fn optionalPtr(data: []const u8) [*c]const u8 {
    return if (data.len == 0) null else @ptrCast(data.ptr);
}

fn requiredPtr(data: []const u8) [*c]const u8 {
    return if (data.len == 0) @ptrCast(&empty_input) else @ptrCast(data.ptr);
}

fn Ops(comptime algorithm: anytype) type {
    const name = @tagName(algorithm);
    if (std.mem.eql(u8, name, "md5")) return Md5Ops;
    if (std.mem.eql(u8, name, "sha1")) return Sha1Ops;
    if (std.mem.eql(u8, name, "sha256")) return Sha256Ops;
    if (std.mem.eql(u8, name, "sha384")) return Sha384Ops;
    if (std.mem.eql(u8, name, "sha512")) return Sha512Ops;
    if (std.mem.eql(u8, name, "sha3_224")) return Sha3_224Ops;
    if (std.mem.eql(u8, name, "sha3_256")) return Sha3_256Ops;
    if (std.mem.eql(u8, name, "sha3_384")) return Sha3_384Ops;
    if (std.mem.eql(u8, name, "sha3_512")) return Sha3_512Ops;
    @compileError("unsupported HMAC algorithm");
}

const Md5Ops = struct {
    const Key = c.SYMCRYPT_HMAC_MD5_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_MD5_STATE;
    const digest_length = c.SYMCRYPT_HMAC_MD5_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacMd5ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacMd5KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacMd5(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacMd5StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacMd5Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacMd5Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacMd5Result(state, out);
    }
};

const Sha1Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA1_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA1_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA1_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha1ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha1KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha1(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha1StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha1Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha1Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha1Result(state, out);
    }
};

const Sha256Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA256_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA256_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA256_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha256ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha256KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha256(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha256StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha256Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha256Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha256Result(state, out);
    }
};

const Sha384Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA384_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA384_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA384_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha384ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha384KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha384(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha384StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha384Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha384Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha384Result(state, out);
    }
};

const Sha512Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA512_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA512_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA512_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha512ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha512KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha512(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha512StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha512Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha512Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha512Result(state, out);
    }
};

const Sha3_224Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA3_224_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA3_224_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha3_224ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha3_224KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha3_224(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha3_224StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha3_224Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha3_224Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha3_224Result(state, out);
    }
};

const Sha3_256Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA3_256_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA3_256_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha3_256ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha3_256KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha3_256(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha3_256StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha3_256Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha3_256Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha3_256Result(state, out);
    }
};

const Sha3_384Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA3_384_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA3_384_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha3_384ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha3_384KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha3_384(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha3_384StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha3_384Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha3_384Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha3_384Result(state, out);
    }
};

const Sha3_512Ops = struct {
    const Key = c.SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY;
    const State = c.SYMCRYPT_HMAC_SHA3_512_STATE;
    const digest_length = c.SYMCRYPT_HMAC_SHA3_512_RESULT_SIZE;
    fn expandKey(key: *Key, data: [*c]const u8, len: usize) c.SYMCRYPT_ERROR {
        return c.SymCryptHmacSha3_512ExpandKey(key, data, len);
    }
    fn copyKey(source: *const Key, destination: *Key) void {
        c.SymCryptHmacSha3_512KeyCopy(source, destination);
    }
    fn oneShot(key: *const Key, data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptHmacSha3_512(key, data, len, out);
    }
    fn copyState(source: *const State, key: *const Key, destination: *State) void {
        c.SymCryptHmacSha3_512StateCopy(source, key, destination);
    }
    fn init(state: *State, key: *const Key) void {
        c.SymCryptHmacSha3_512Init(state, key);
    }
    fn append(state: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptHmacSha3_512Append(state, data, len);
    }
    fn result(state: *State, out: [*c]u8) void {
        c.SymCryptHmacSha3_512Result(state, out);
    }
};
