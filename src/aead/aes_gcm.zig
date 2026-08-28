const std = @import("std");
const builtin = @import("builtin");
const c = @import("../c.zig").raw;
const errors = @import("../errors.zig");
const initialization = @import("../init.zig");
const state_memory = @import("../internal/state.zig");
const buffers = @import("../internal/buffers.zig");
const owned = @import("../internal/owned.zig");
const algorithms = @import("../internal/algorithms.zig");
const secure_memory = @import("../internal/secure_memory.zig");

pub const max_data_length: u64 = (@as(u64, 1) << 36) - 32;
pub const max_aad_length_exclusive: u64 = @as(u64, 1) << 61;

var test_fail_after_allocation = false;

pub fn testFailNextCreateAfterAllocation() void {
    if (!builtin.is_test) @compileError("AES-GCM test hooks are disabled");
    std.debug.assert(!@atomicRmw(bool, &test_fail_after_allocation, .Xchg, true, .acq_rel));
}

fn maybeFailAfterAllocation() errors.Error!void {
    if (!builtin.is_test) return;
    if (@atomicRmw(bool, &test_fail_after_allocation, .Xchg, false, .acq_rel))
        return error.MemoryAllocationFailure;
}

pub fn validateLengths(nonce_len: u64, aad_len: u64, data_len: u64, tag_len: u64) errors.Error!void {
    if (nonce_len == 0 or nonce_len > std.math.maxInt(u64) / 8) return error.WrongNonceSize;
    if (aad_len >= max_aad_length_exclusive or data_len > max_data_length) return error.WrongDataSize;
    if (tag_len < 12 or tag_len > 16) return error.WrongTagSize;
}

pub fn testSymCryptValidateLengths(
    nonce_len: u64,
    aad_len: u64,
    data_len: u64,
    tag_len: u64,
) (errors.Error || error{ValueTooLarge})!u32 {
    if (!builtin.is_test) @compileError("AES-GCM test hooks are disabled");
    if (nonce_len > std.math.maxInt(usize) or tag_len > std.math.maxInt(usize))
        return error.ValueTooLarge;
    try initialization.ensureInitialized();
    return @bitCast(c.SymCryptGcmValidateParameters(
        algorithms.aesBlockCipher(),
        @intCast(nonce_len),
        aad_len,
        data_len,
        @intCast(tag_len),
    ));
}

pub fn AesGcm(comptime key_len: usize) type {
    if (key_len != 16 and key_len != 32) @compileError("AES-GCM supports only 128- and 256-bit keys");

    const Impl = struct {
        allocator: std.mem.Allocator,
        expanded_key: c.SYMCRYPT_GCM_EXPANDED_KEY,
    };

    return opaque {
        const Self = @This();

        pub const key_length = key_len;
        pub const tag_length_min = 12;
        pub const tag_length_max = 16;
        pub const max_plaintext_length = max_data_length;

        /// Creates an opaque, allocator-owned expanded key at its final address.
        /// Call `deinit` exactly once; the handle and aliases are invalid afterward.
        pub fn init(
            allocator: std.mem.Allocator,
            key: []const u8,
        ) (std.mem.Allocator.Error || errors.Error)!*Self {
            if (key.len != key_len) return error.WrongKeySize;
            try initialization.ensureInitialized();
            const implementation = try state_memory.allocate(Impl, allocator);
            errdefer state_memory.destroy(Impl, allocator, implementation);
            implementation.allocator = allocator;
            try maybeFailAfterAllocation();
            try errors.check(c.SymCryptGcmExpandKey(
                &implementation.expanded_key,
                algorithms.aesBlockCipher(),
                buffers.constPtr(key),
                key.len,
            ));
            return @ptrCast(implementation);
        }

        pub fn deinit(self: *Self) void {
            const implementation = impl(self);
            const allocator = implementation.allocator;
            state_memory.destroy(Impl, allocator, implementation);
        }

        pub fn seal(
            self: *const Self,
            nonce: []const u8,
            aad: []const u8,
            plaintext: []const u8,
            ciphertext: []u8,
            tag: []u8,
        ) errors.Error!void {
            try validate(nonce, aad, plaintext.len, ciphertext.len, tag.len);
            try validateOutOfPlace(plaintext, ciphertext, tag, nonce, aad);
            c.SymCryptGcmEncrypt(
                &implConst(self).expanded_key,
                buffers.constPtr(nonce),
                nonce.len,
                buffers.optionalConstPtr(aad),
                aad.len,
                buffers.constPtr(plaintext),
                buffers.mutPtr(ciphertext),
                plaintext.len,
                buffers.mutPtr(tag),
                tag.len,
            );
        }

        pub fn open(
            self: *const Self,
            nonce: []const u8,
            aad: []const u8,
            ciphertext: []const u8,
            plaintext: []u8,
            tag: []const u8,
        ) errors.Error!void {
            try validate(nonce, aad, ciphertext.len, plaintext.len, tag.len);
            try validateOutOfPlace(ciphertext, plaintext, tag, nonce, aad);
            const result = c.SymCryptGcmDecrypt(
                &implConst(self).expanded_key,
                buffers.constPtr(nonce),
                nonce.len,
                buffers.optionalConstPtr(aad),
                aad.len,
                buffers.constPtr(ciphertext),
                buffers.mutPtr(plaintext),
                ciphertext.len,
                buffers.constPtr(tag),
                tag.len,
            );
            errors.check(result) catch |err| {
                secure_memory.wipeIndependent(plaintext);
                return err;
            };
        }

        pub fn sealInPlace(
            self: *const Self,
            nonce: []const u8,
            aad: []const u8,
            buffer: []u8,
            tag: []u8,
        ) errors.Error!void {
            try validate(nonce, aad, buffer.len, buffer.len, tag.len);
            try validateInPlace(buffer, tag, nonce, aad);
            c.SymCryptGcmEncrypt(
                &implConst(self).expanded_key,
                buffers.constPtr(nonce),
                nonce.len,
                buffers.optionalConstPtr(aad),
                aad.len,
                buffers.constPtr(buffer),
                buffers.mutPtr(buffer),
                buffer.len,
                buffers.mutPtr(tag),
                tag.len,
            );
        }

        /// Authentication failure wipes `buffer`, destroying the ciphertext.
        pub fn openInPlace(
            self: *const Self,
            nonce: []const u8,
            aad: []const u8,
            buffer: []u8,
            tag: []const u8,
        ) errors.Error!void {
            try validate(nonce, aad, buffer.len, buffer.len, tag.len);
            try validateInPlace(buffer, tag, nonce, aad);
            const result = c.SymCryptGcmDecrypt(
                &implConst(self).expanded_key,
                buffers.constPtr(nonce),
                nonce.len,
                buffers.optionalConstPtr(aad),
                aad.len,
                buffers.constPtr(buffer),
                buffers.mutPtr(buffer),
                buffer.len,
                buffers.constPtr(tag),
                tag.len,
            );
            errors.check(result) catch |err| {
                secure_memory.wipeIndependent(buffer);
                return err;
            };
        }

        pub fn sealAlloc(
            self: *const Self,
            allocator: std.mem.Allocator,
            nonce: []const u8,
            aad: []const u8,
            plaintext: []const u8,
            tag_len: usize,
        ) (std.mem.Allocator.Error || errors.Error)!owned.OwnedSealed {
            try validateLengths(nonce.len, aad.len, plaintext.len, tag_len);
            const total = try buffers.checkedAdd(plaintext.len, tag_len);
            const allocation = try allocator.alloc(u8, total);
            errdefer secure_memory.wipeAndFree(allocator, allocation);
            try self.seal(
                nonce,
                aad,
                plaintext,
                allocation[0..plaintext.len],
                allocation[plaintext.len..],
            );
            return .{ .allocator = allocator, .bytes = allocation, .ciphertext_len = plaintext.len };
        }

        pub fn openAlloc(
            self: *const Self,
            allocator: std.mem.Allocator,
            nonce: []const u8,
            aad: []const u8,
            ciphertext: []const u8,
            tag: []const u8,
        ) (std.mem.Allocator.Error || errors.Error)!owned.OwnedPlaintext {
            try validateLengths(nonce.len, aad.len, ciphertext.len, tag.len);
            const allocation = try allocator.alloc(u8, ciphertext.len);
            errdefer secure_memory.wipeAndFree(allocator, allocation);
            try self.open(nonce, aad, ciphertext, allocation, tag);
            return .{ .allocator = allocator, .bytes = allocation };
        }

        fn validate(
            nonce: []const u8,
            aad: []const u8,
            input_len: usize,
            output_len: usize,
            tag_len: usize,
        ) errors.Error!void {
            if (input_len != output_len) return error.WrongDataSize;
            try validateLengths(nonce.len, aad.len, input_len, tag_len);
        }

        fn impl(self: *Self) *Impl {
            return @ptrCast(@alignCast(self));
        }

        fn implConst(self: *const Self) *const Impl {
            return @ptrCast(@alignCast(self));
        }
    };
}

fn validateOutOfPlace(
    input: []const u8,
    output: []const u8,
    tag: []const u8,
    nonce: []const u8,
    aad: []const u8,
) errors.Error!void {
    try buffers.requireDisjoint(input, output);
    try buffers.requireDisjoint(tag, input);
    try buffers.requireDisjointFromAll(output, .{ tag, nonce, aad });
    try buffers.requireDisjointFromAll(tag, .{ nonce, aad });
}

fn validateInPlace(
    buffer: []const u8,
    tag: []const u8,
    nonce: []const u8,
    aad: []const u8,
) errors.Error!void {
    try buffers.requireDisjointFromAll(buffer, .{ tag, nonce, aad });
    try buffers.requireDisjointFromAll(tag, .{ nonce, aad });
}
