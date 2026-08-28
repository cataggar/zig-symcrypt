const std = @import("std");
const c = @import("c.zig").raw;
const initialization = @import("init.zig");
const errors = @import("errors.zig");
const state_memory = @import("internal/state.zig");
const secure_memory = @import("internal/secure_memory.zig");

const empty_input: u8 = 0;

pub fn Api(comptime AlgorithmType: type) type {
    return struct {
        pub const Algorithm = AlgorithmType;

        pub fn Digest(comptime algorithm: Algorithm) type {
            return [Ops(algorithm).digest_length]u8;
        }

        pub fn digest(comptime algorithm: Algorithm, data: []const u8) errors.Error!Digest(algorithm) {
            try initialization.ensureInitialized();
            var result: Digest(algorithm) = undefined;
            Ops(algorithm).oneShot(requiredPtr(data), data.len, result[0..].ptr);
            return result;
        }

        pub fn digestInto(
            comptime algorithm: Algorithm,
            data: []const u8,
            output: []u8,
        ) errors.Error!void {
            if (output.len != Ops(algorithm).digest_length) return error.WrongDataSize;
            try initialization.ensureInitialized();
            Ops(algorithm).oneShot(requiredPtr(data), data.len, output.ptr);
        }

        /// Allocator-owned, stable-address state. Call `deinit` exactly once.
        /// `deinit` is intentionally not idempotent; aliases become invalid afterward.
        pub fn Context(comptime algorithm: Algorithm) type {
            const A = Ops(algorithm);
            const Impl = struct {
                allocator: std.mem.Allocator,
                state: A.State,
            };

            return opaque {
                const Self = @This();

                pub fn create(allocator: std.mem.Allocator) (std.mem.Allocator.Error || errors.Error)!*Self {
                    try initialization.ensureInitialized();
                    const implementation = try state_memory.allocate(Impl, allocator);
                    implementation.allocator = allocator;
                    A.init(&implementation.state);
                    return @ptrCast(implementation);
                }

                pub fn update(self: *Self, data: []const u8) errors.Error!void {
                    if (data.len == 0) return;
                    A.append(&impl(self).state, data.ptr, data.len);
                }

                pub fn final(self: *Self) errors.Error!Digest(algorithm) {
                    var result: Digest(algorithm) = undefined;
                    A.result(&impl(self).state, result[0..].ptr);
                    return result;
                }

                pub fn reset(self: *Self) errors.Error!void {
                    A.init(&impl(self).state);
                }

                pub fn snapshot(self: *const Self) errors.Error!Digest(algorithm) {
                    var temporary: A.State = undefined;
                    @memset(std.mem.asBytes(&temporary), 0);
                    defer secure_memory.wipe(std.mem.asBytes(&temporary));
                    A.copy(&implConst(self).state, &temporary);
                    var result: Digest(algorithm) = undefined;
                    A.result(&temporary, result[0..].ptr);
                    return result;
                }

                pub fn clone(
                    self: *const Self,
                    allocator: std.mem.Allocator,
                ) (std.mem.Allocator.Error || errors.Error)!*Self {
                    const duplicate = try state_memory.allocate(Impl, allocator);
                    errdefer state_memory.destroy(Impl, allocator, duplicate);
                    duplicate.allocator = allocator;
                    A.copy(&implConst(self).state, &duplicate.state);
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
    @compileError("unsupported hash algorithm");
}

const Md5Ops = struct {
    const State = c.SYMCRYPT_MD5_STATE;
    const digest_length = c.SYMCRYPT_MD5_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptMd5(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptMd5Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptMd5Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptMd5Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptMd5StateCopy(source, destination);
    }
};

const Sha1Ops = struct {
    const State = c.SYMCRYPT_SHA1_STATE;
    const digest_length = c.SYMCRYPT_SHA1_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha1(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha1Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha1Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha1Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha1StateCopy(source, destination);
    }
};

const Sha256Ops = struct {
    const State = c.SYMCRYPT_SHA256_STATE;
    const digest_length = c.SYMCRYPT_SHA256_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha256(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha256Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha256Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha256Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha256StateCopy(source, destination);
    }
};

const Sha384Ops = struct {
    const State = c.SYMCRYPT_SHA384_STATE;
    const digest_length = c.SYMCRYPT_SHA384_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha384(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha384Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha384Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha384Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha384StateCopy(source, destination);
    }
};

const Sha512Ops = struct {
    const State = c.SYMCRYPT_SHA512_STATE;
    const digest_length = c.SYMCRYPT_SHA512_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha512(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha512Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha512Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha512Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha512StateCopy(source, destination);
    }
};

const Sha3_224Ops = struct {
    const State = c.SYMCRYPT_SHA3_224_STATE;
    const digest_length = c.SYMCRYPT_SHA3_224_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha3_224(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha3_224Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha3_224Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha3_224Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha3_224StateCopy(source, destination);
    }
};

const Sha3_256Ops = struct {
    const State = c.SYMCRYPT_SHA3_256_STATE;
    const digest_length = c.SYMCRYPT_SHA3_256_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha3_256(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha3_256Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha3_256Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha3_256Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha3_256StateCopy(source, destination);
    }
};

const Sha3_384Ops = struct {
    const State = c.SYMCRYPT_SHA3_384_STATE;
    const digest_length = c.SYMCRYPT_SHA3_384_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha3_384(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha3_384Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha3_384Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha3_384Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha3_384StateCopy(source, destination);
    }
};

const Sha3_512Ops = struct {
    const State = c.SYMCRYPT_SHA3_512_STATE;
    const digest_length = c.SYMCRYPT_SHA3_512_RESULT_SIZE;
    fn oneShot(data: [*c]const u8, len: usize, out: [*c]u8) void {
        c.SymCryptSha3_512(data, len, out);
    }
    fn init(value: *State) void {
        c.SymCryptSha3_512Init(value);
    }
    fn append(value: *State, data: [*c]const u8, len: usize) void {
        c.SymCryptSha3_512Append(value, data, len);
    }
    fn result(value: *State, out: [*c]u8) void {
        c.SymCryptSha3_512Result(value, out);
    }
    fn copy(source: *const State, destination: *State) void {
        c.SymCryptSha3_512StateCopy(source, destination);
    }
};
