# Initialization and compatibility

All public operations call a process-global, thread-safe once initializer.
Explicit `symcrypt.init()` is recommended before starting worker threads.

Dynamic mode calls only `SymCryptModuleInitEx(103, 13)`. It does not call the
fatal `SymCryptModuleInit`. `SYMCRYPT_INVALID_ARGUMENT` becomes
`error.IncompatibleSymCryptVersion`; other failures become
`error.SymCryptInitializationFailed`. The result is published atomically and
cached for every waiter. A failed handshake prevents every later crypto call.

Static mode installs the selected upstream environment and callbacks and calls
`SymCryptInit()` once. Upstream treats a static header/archive incompatibility
as fatal, so release validation executes static initialization in its own test
process. Exact release identity cannot be queried at runtime: the dynamic
handshake permits a compatible newer minor and exposes no patch query.
Therefore releases additionally require the hash-checked provenance manifest
for exactly 103.13.0 at the pinned commit.
