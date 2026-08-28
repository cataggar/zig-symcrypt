const std = @import("std");
const symcrypt = @import("symcrypt");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x24} ** 12;

    const gcm = try symcrypt.aead.Aes128Gcm.init(allocator, &key);
    defer gcm.deinit();

    var sealed = try gcm.sealAlloc(allocator, &nonce, "example metadata", "authenticated message", 16);
    defer sealed.deinit();
    var plaintext = try gcm.openAlloc(
        allocator,
        &nonce,
        "example metadata",
        sealed.ciphertext(),
        sealed.tag(),
    );
    defer plaintext.deinit();

    std.debug.assert(std.mem.eql(u8, plaintext.bytes, "authenticated message"));
}
