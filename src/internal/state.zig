const std = @import("std");
const secure_memory = @import("secure_memory.zig");

pub fn allocate(comptime T: type, allocator: std.mem.Allocator) std.mem.Allocator.Error!*T {
    const value = try allocator.create(T);
    @memset(std.mem.asBytes(value), 0);
    return value;
}

pub fn destroy(comptime T: type, allocator: std.mem.Allocator, value: *T) void {
    secure_memory.wipe(std.mem.asBytes(value));
    allocator.destroy(value);
}
