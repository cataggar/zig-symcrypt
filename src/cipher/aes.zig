const std = @import("std");
const builtin = @import("builtin");
const c = @import("../c.zig").raw;
const errors = @import("../errors.zig");
const initialization = @import("../init.zig");
const state_memory = @import("../internal/state.zig");
const buffers = @import("../internal/buffers.zig");
const owned = @import("../internal/owned.zig");
const cbc = @import("aes_cbc.zig");

var test_fail_after_allocation = false;

pub fn testFailNextCreateAfterAllocation() void {
    if (!builtin.is_test) @compileError("AES test hooks are disabled");
    std.debug.assert(!@atomicRmw(bool, &test_fail_after_allocation, .Xchg, true, .acq_rel));
}

fn maybeFailAfterAllocation() errors.Error!void {
    if (!builtin.is_test) return;
    if (@atomicRmw(bool, &test_fail_after_allocation, .Xchg, false, .acq_rel))
        return error.MemoryAllocationFailure;
}

const Impl = struct {
    allocator: std.mem.Allocator,
    expanded_key: c.SYMCRYPT_AES_EXPANDED_KEY,
};

pub const AesKey = opaque {
    const Self = @This();

    /// Creates an opaque, allocator-owned expanded key at its final address.
    /// Call `deinit` exactly once; the handle and aliases are invalid afterward.
    pub fn init(
        allocator: std.mem.Allocator,
        key: []const u8,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        if (key.len != 16 and key.len != 24 and key.len != 32) return error.WrongKeySize;
        try initialization.ensureInitialized();
        const implementation = try state_memory.allocate(Impl, allocator);
        errdefer state_memory.destroy(Impl, allocator, implementation);
        implementation.allocator = allocator;
        try maybeFailAfterAllocation();
        try errors.check(c.SymCryptAesExpandKey(
            &implementation.expanded_key,
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

    /// Raw AES-CBC encryption. No padding or authentication is performed.
    pub fn cbcEncrypt(
        self: *const Self,
        iv: *[cbc.block_size]u8,
        plaintext: []const u8,
        ciphertext: []u8,
    ) errors.Error!void {
        try cbc.encrypt(&implConst(self).expanded_key, iv, plaintext, ciphertext);
    }

    /// Raw AES-CBC decryption. No padding or authentication is performed.
    pub fn cbcDecrypt(
        self: *const Self,
        iv: *[cbc.block_size]u8,
        ciphertext: []const u8,
        plaintext: []u8,
    ) errors.Error!void {
        try cbc.decrypt(&implConst(self).expanded_key, iv, ciphertext, plaintext);
    }

    pub fn cbcEncryptInPlace(
        self: *const Self,
        iv: *[cbc.block_size]u8,
        data: []u8,
    ) errors.Error!void {
        try cbc.encryptInPlace(&implConst(self).expanded_key, iv, data);
    }

    pub fn cbcDecryptInPlace(
        self: *const Self,
        iv: *[cbc.block_size]u8,
        data: []u8,
    ) errors.Error!void {
        try cbc.decryptInPlace(&implConst(self).expanded_key, iv, data);
    }

    pub fn cbcEncryptAlloc(
        self: *const Self,
        allocator: std.mem.Allocator,
        iv: *[cbc.block_size]u8,
        plaintext: []const u8,
    ) (std.mem.Allocator.Error || errors.Error)!owned.OwnedCiphertext {
        return cbc.encryptAlloc(&implConst(self).expanded_key, allocator, iv, plaintext);
    }

    pub fn cbcDecryptAlloc(
        self: *const Self,
        allocator: std.mem.Allocator,
        iv: *[cbc.block_size]u8,
        ciphertext: []const u8,
    ) (std.mem.Allocator.Error || errors.Error)!owned.OwnedPlaintext {
        return cbc.decryptAlloc(&implConst(self).expanded_key, allocator, iv, ciphertext);
    }

    fn impl(self: *Self) *Impl {
        return @ptrCast(@alignCast(self));
    }

    fn implConst(self: *const Self) *const Impl {
        return @ptrCast(@alignCast(self));
    }
};
