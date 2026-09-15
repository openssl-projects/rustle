# Context Memory

Rustle owns the lifetime of provider operation contexts. Contexts use the
host process's C heap, allowing allocation failure to be reported to OpenSSL
instead of forcing the host process to terminate.

This allocation model also supports `no_std` without requiring a Rust global
allocator. Context types must satisfy rustle's size and alignment constraints;
types with stronger requirements need a different allocation strategy.

## Sensitive state

Clearing cryptographic state is the context implementation's responsibility.
Rustle destroys a context before releasing its storage and provides a
best-effort mitigation against optimization removing cleanup writes.

That mitigation is not a secure-erasure guarantee. Rust's `black_box`
explicitly provides no guarantees for cryptographic or security purposes,
and ordinary zeroing does not provide the guarantees intended by specialized
cleansing routines. Treat cleanup as defense in depth.
