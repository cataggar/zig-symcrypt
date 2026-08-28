const std = @import("std");
const secure_memory = @import("internal/secure_memory.zig");
const options = @import("symcrypt_options");

pub const ecc = @import("asymmetric/ecc.zig");
pub const x25519 = @import("asymmetric/x25519.zig");
pub const ecdsa_der = @import("asymmetric/ecdsa_der.zig");
pub const rsa = @import("asymmetric/rsa.zig");

pub const capabilities = .{
    .p_curves = true,
    .x25519 = true,
    .rsa = true,
    .legacy_rsa_pkcs1_encryption = options.enable_legacy_rsa_pkcs1_encryption,
    .mlkem768 = false,
    .tls_x25519_mlkem768 = false,
};

/// Allocator-owned secret bytes. Call `deinit` exactly once; aliases are invalid afterward.
pub const SecretBytes = opaque {
    const Self = @This();
    const Impl = struct {
        allocator: std.mem.Allocator,
        allocation: []u8,
    };

    pub fn create(allocator: std.mem.Allocator, len: usize) std.mem.Allocator.Error!*Self {
        const implementation = try allocator.create(Impl);
        errdefer allocator.destroy(implementation);
        implementation.* = .{ .allocator = allocator, .allocation = try allocator.alloc(u8, len) };
        @memset(implementation.allocation, 0);
        return @ptrCast(implementation);
    }

    pub fn bytes(self: *const Self) []const u8 {
        return implConst(self).allocation;
    }

    pub fn deinit(self: *Self) void {
        const implementation = impl(self);
        const allocator = implementation.allocator;
        secure_memory.wipeIndependent(implementation.allocation);
        if (implementation.allocation.len != 0) {
            allocator.rawFree(
                implementation.allocation,
                .fromByteUnits(@alignOf(u8)),
                @returnAddress(),
            );
        }
        secure_memory.wipeIndependent(std.mem.asBytes(implementation));
        allocator.destroy(implementation);
    }

    /// Mutable access for filling caller-owned secret outputs.
    pub fn mutable(self: *Self) []u8 {
        return impl(self).allocation;
    }

    fn impl(self: *Self) *Impl {
        return @ptrCast(@alignCast(self));
    }

    fn implConst(self: *const Self) *const Impl {
        return @ptrCast(@alignCast(self));
    }
};

test "secret bytes wipe allocation and wrapper" {
    var checking = WipeCheckingAllocator{ .backing = std.testing.allocator };
    const secret = try SecretBytes.create(checking.allocator(), 32);
    @memset(secret.mutable(), 0xa5);
    secret.deinit();
    try std.testing.expectEqual(@as(usize, 2), checking.frees);
    try std.testing.expectEqual(@as(usize, 0), checking.nonzero_frees);

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    try std.testing.expectError(error.OutOfMemory, SecretBytes.create(failing.allocator(), 32));
}

const WipeCheckingAllocator = struct {
    backing: std.mem.Allocator,
    frees: usize = 0,
    nonzero_frees: usize = 0,

    fn allocator(self: *WipeCheckingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        return self.backing.rawAlloc(len, alignment, return_address);
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        return self.backing.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        return self.backing.rawRemap(memory, alignment, new_len, return_address);
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        for (memory) |byte| {
            if (byte != 0) {
                self.nonzero_frees += 1;
                break;
            }
        }
        self.frees += 1;
        self.backing.rawFree(memory, alignment, return_address);
    }
};
