const aes_gcm = @import("aead/aes_gcm.zig");
const owned = @import("internal/owned.zig");

pub const Aes128Gcm = aes_gcm.AesGcm(16);
pub const Aes256Gcm = aes_gcm.AesGcm(32);
pub const ChaCha20Poly1305 = @import("aead/chacha20_poly1305.zig");
pub const OwnedSealed = owned.OwnedSealed;
pub const OwnedPlaintext = owned.OwnedPlaintext;

test {
    @import("std").testing.refAllDecls(@This());
}
