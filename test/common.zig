const std = @import("std");

pub fn bytes(comptime value: []const u8) [value.len / 2]u8 {
    var result: [value.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch unreachable;
    return result;
}

pub const WipeCheckingAllocator = struct {
    backing: std.mem.Allocator,
    allocations: usize = 0,
    frees: usize = 0,
    last_free_len: usize = 0,
    last_free_all_zero: bool = false,

    pub fn init(backing: std.mem.Allocator) WipeCheckingAllocator {
        return .{ .backing = backing };
    }

    pub fn allocator(self: *WipeCheckingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        const result = self.backing.rawAlloc(len, alignment, return_address) orelse return null;
        self.allocations += 1;
        return result;
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
        self.last_free_len = memory.len;
        self.last_free_all_zero = true;
        for (memory) |byte| {
            if (byte != 0) {
                self.last_free_all_zero = false;
                break;
            }
        }
        self.frees += 1;
        self.backing.rawFree(memory, alignment, return_address);
    }

    pub fn expectSingleZeroedFree(self: *const WipeCheckingAllocator, expected_len: usize) !void {
        try std.testing.expectEqual(@as(usize, 1), self.allocations);
        try std.testing.expectEqual(@as(usize, 1), self.frees);
        try std.testing.expectEqual(expected_len, self.last_free_len);
        try std.testing.expect(self.last_free_all_zero);
    }
};
