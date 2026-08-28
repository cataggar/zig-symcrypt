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

Static callback allocation tests use a dedicated instrumented callback source
and package option, separate from the production callback source linked by
examples and consumers. They iterate failure indices until each ECC, X25519,
and RSA constructor first succeeds, with a defensive upper bound. Every
failure must be `MemoryAllocationFailure`, return no object, and leave the
callback allocation balance at zero. SymCrypt 103.13.0 does not safely
propagate `NULL` from every RSA prime-generation scratch allocation, so the
test-only RSA seam records the selected callback allocation and defers the
error until the backend call returns; the wrapper then destroys the complete
key and reports the same allocation error without entering upstream undefined
behavior. Production artifacts contain neither that branch nor any exported
`SymCryptZigTest*` controls; a symbol check enforces the separation.
