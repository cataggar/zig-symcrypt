# Safe-wrapper release coverage

The identical `test/all.zig` root is used for dynamic and static execution.
It imports every public module and preserves the success/failure tests delivered
for initialization, errors, random, hash, HMAC, HKDF, AES-GCM,
ChaCha20-Poly1305, AES-CBC, ECC/ECDH/ECDSA, X25519, RSA signatures, PSS, OAEP,
and gated legacy APIs.

Required failure coverage includes malformed sizes/encodings, invalid usage,
overlap and in-place rules, known-answer and empty-input behavior, clone and
snapshot lifecycle, allocator and post-allocation failures, exact wiping before
free, AEAD authentication tampering with full output wiping, signature/key
errors, cached version mismatch, and racing first initialization. Concurrent
tests cover independent hash/HMAC/random, shared immutable AES/GCM keys,
AEAD/CBC operations, ECC/ECDH/ECDSA, and allocator-owned teardown.
