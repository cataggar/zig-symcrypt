const api = @import("hash_impl.zig").Api(Algorithm);

pub const Algorithm = enum {
    md5,
    sha1,
    sha256,
    sha384,
    sha512,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
};

pub const Digest = api.Digest;
pub const digest = api.digest;
pub const digestInto = api.digestInto;
pub const Context = api.Context;

pub const Md5 = Context(.md5);
pub const Sha1 = Context(.sha1);
pub const Sha256 = Context(.sha256);
pub const Sha384 = Context(.sha384);
pub const Sha512 = Context(.sha512);
pub const Sha3_224 = Context(.sha3_224);
pub const Sha3_256 = Context(.sha3_256);
pub const Sha3_384 = Context(.sha3_384);
pub const Sha3_512 = Context(.sha3_512);
