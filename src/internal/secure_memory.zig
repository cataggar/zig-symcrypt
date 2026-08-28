const std = @import("std");
const c = @import("../c.zig").raw;

var last_wipe_length: usize = 0;

pub fn wipe(bytes: []u8) void {
    if (bytes.len == 0) return;
    c.SymCryptWipe(bytes.ptr, bytes.len);
    @atomicStore(usize, &last_wipe_length, bytes.len, .release);
}

pub fn wipeValue(value: anytype) void {
    wipe(std.mem.asBytes(value));
}

pub fn testLastWipeLength() usize {
    return @atomicLoad(usize, &last_wipe_length, .acquire);
}
