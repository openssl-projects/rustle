# Digest Vtables

The public `rustle::digest` API follows the Linux kernel's `#[vtable]`
approach: an attribute records which trait methods an implementation supplies,
and the adapter uses that information to construct the C dispatch table.
Optional OpenSSL functions stay ordinary methods on one digest trait.

## Method presence controls registration

```rust,ignore
use rustle::digest::{Digest, DigestAlgorithm, Output, Result};
use rustle::params::Params;

#[rustle::vtable]
impl Digest for MyDigest {
    fn newctx() -> Result<Self> { /* construct owned state */ }
    fn init(&mut self, params: Option<Params<'_>>) -> Result { /* reset */ }
    fn update(&mut self, input: &[u8]) -> Result { /* absorb */ }
    fn finalize(&mut self, out: &mut Output<'_>) -> Result { /* write */ }

    rustle::gettable_params! {
        // Algorithm parameter descriptors and handlers.
    }

    fn dupctx(&self) -> Result<Self> { /* duplicate state */ }
}
```

The streaming core and algorithm parameter methods are required. Duplication
and context parameters are optional. `dupctx` is registered only when the
implementation supplies it; the trait does not require `Clone` or `Default`.
A context accessor and its descriptor method must be implemented together,
checked when the dispatch constant is evaluated. The parameter macros generate
both methods from one declaration; omitting one omits both its callbacks.

## Context parameters come in pairs

A context parameter exists for state that genuinely varies between contexts of
the same algorithm. A value fixed for the algorithm belongs in
`gettable_params!` and nowhere else — serving it per context is API surface
that upstream does not have.

Where a name is per-context, the directions are not independent. Upstream
digests that serve a context getter always serve the matching setter as well:
SHAKE and cSHAKE's `xoflen` and `size`, blake2's `size`, ML-DSA-mu's context
parameters. The reverse is not required — `SHA-1`'s `ssl3-ms` and MDC2's
`pad-type` are write-only configuration with nothing to read back. So
`gettable_ctx_params!` without `settable_ctx_params!` fails when the dispatch
constant is evaluated; the other order is allowed.

Verify any claim about what upstream registers by fetching the algorithm and
calling `EVP_MD_gettable_ctx_params`/`EVP_MD_settable_ctx_params` on it, not by
reading upstream's sources.

Initialization belongs to the implementation. The adapter does not replace
the context with a default value. Implementations that accept context
parameters can call `self.apply_ctx_params(params)` after resetting their
state. A null array means no parameters. The helper preserves first-match
lookup and ignores names that the descriptor table does not list.

The attribute generates `HAS_*` constants and a required marker that catches
forgotten implementation attributes. Direct method declarations and their
presence constants have matching conditional-compilation attributes. The
parameter macros cooperate by generating their own constants alongside the
methods: an outer attribute cannot see the expansion of a nested macro.
Other implementation-item macros are rejected rather than silently omitted;
a macro can instead generate an entire attributed implementation. Handwritten
presence overrides are rejected by the attribute.

## Keep the unsafe boundary inside rustle

The attribute generates safe Rust metadata, not C wrappers. The generic
adapters remain in rustle and all callbacks in a table share the same context
type. They return the opaque `DigestFunctions` type; raw dispatch fields and
callback constructors remain inaccessible to provider authors.

The builder packs present entries into a static array, followed by `END`.
An absent optional callback cannot leave an early terminator that hides later
callbacks. The backing array has spare terminators after its used portion;
OpenSSL stops at the first one. No runtime allocation builds the table.

Metadata controls registration but is not a memory-safety proof. Optional
methods retain safe failure defaults. Errors become C failure; they do not
panic or unwind into OpenSSL. Rustle allocates contexts with the C allocator
and supplies destruction automatically.

## Output and errors

`Output` borrows potentially uninitialized storage and tracks successful
writes. `write` copies bytes without reading the destination. `write_with`
checks space before invoking a callback and zero-initializes that region
before lending it as `&mut [u8]`. This lets existing safe crypto APIs write
into C buffers without assuming those buffers were initialized. Its cost is
one initialization pass over the requested output region.

Only successful writes advance the reported length. Finalization returns that
length through OpenSSL's output slot. There is no fixed digest-length
assumption in the adapter; the implementation chooses how much to write.
Errors distinguish unsupported operations, insufficient output space, and
invalid parameters. The adapter currently reports C failure without adding an
OpenSSL error-stack entry.

## bc-rust implementation

`BcDigest<H>` implements the trait once for all eight registered SHA2 and
SHA3 hashes. It uses explicit construction, reset, and duplication, and
finalizes through `write_with`. These hashes have no per-context state, so
their tables omit context parameters in both directions. This matches the
default provider's fixed-length digest interface, whose
`EVP_MD_gettable_ctx_params` and `EVP_MD_settable_ctx_params` are both null.

## Current scope

The adapter supports the streaming core, algorithm parameters, duplication,
and static context parameter descriptors in both directions. It does not yet
expose one-shot callbacks, squeeze, copyctx, or serialization. Those
operations require safe signatures and audited adapters, while reusing the
same method-presence detection. Dynamic descriptor selection and
one-shot-only implementations are also outside the current interface.

`rustle-macros` runs on the host, including for cross-compilation. Its parser
dependencies are build tooling and do not become runtime dependencies of the
`no_std` provider ABI layer. The implementation is independent of the
kernel source; the shared idea is described in the
[kernel vtable documentation](https://www.kernel.org/doc/rustdoc/latest/macros/attr.vtable.html).
