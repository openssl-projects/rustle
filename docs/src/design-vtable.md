# Vtable

A vtable tells OpenSSL which callbacks an implementation provides.
`#[rustle::vtable]` connects the methods written by a provider author to the
callbacks advertised to OpenSSL.

## Method presence

The attribute is applied to a trait and its implementations. It records which
methods an implementation explicitly supplies. An omitted optional method
keeps its Rust default but is not advertised as an OpenSSL callback.

This distinction matters: having a callable default does not mean an
implementation supports the operation. Recording presence keeps the advertised
capabilities aligned with the methods the author chose to implement.

Consider context duplication. One implementation supplies `dupctx`; another
leaves the default method in place. Both satisfy the Rust trait, but only the
first should advertise duplication to OpenSSL. Registering the second would
make an unsupported operation appear available until an application tried
to use it.

The attribute expresses that distinction through generated presence metadata:

| Implementation choice | Presence metadata | Optional callback |
|-----------------------|-------------------|-------------------|
| Defines `dupctx` | `HAS_DUPCTX = true` | Included |
| Omits `dupctx` | `HAS_DUPCTX = false` | Omitted |
| Defines `squeeze` | `HAS_SQUEEZE = true` | Included |
| Omits `squeeze` | `HAS_SQUEEZE = false` | Omitted |

Squeezing uses the same `Digest` interface and opaque table as fixed-length
digests. Its default returns `Unsupported`; fixed-length implementations
omit the method and therefore advertise no `OSSL_FUNC_DIGEST_SQUEEZE` entry.

Authors implement methods rather than maintaining a second list of capability
flags. The attribute rejects handwritten overrides of its presence metadata
and adds a required marker to catch implementations that forget the attribute.
Required trait methods remain subject to ordinary Rust trait checking.

## Conditional and generated methods

Conditional methods participate only when enabled. Rustle's parameter macros
cooperate with the attribute so their generated methods are recognized too.
Other macros must expose their methods through a complete attributed
implementation rather than hide them inside it.

The reason is macro expansion order: the attribute sees a nested macro
invocation before that macro has produced its methods. Rustle's parameter
macros explicitly cooperate by producing matching presence metadata. Rejecting
other nested implementation macros avoids silently omitting callbacks that
an author expected to register.

Configuration attributes follow the methods' metadata. If a conditional
method is disabled, its presence override is disabled too. The advertised
capabilities therefore describe the implementation that was actually built.

## Dispatch construction

Rustle builds the OpenSSL dispatch table at compile time. Required callbacks
are always present; optional callbacks follow the recorded method presence.
The table is terminated for OpenSSL's traversal and keeps every callback tied
to the same context type.

OpenSSL identifies callbacks by operation-specific function IDs. The table
associates those IDs with rustle's adapters for the selected implementation.
For example, `HAS_DUPCTX` controls whether the duplication entry is included.
The presence metadata chooses the entry; it does not change the adapter's
signature or create a different context type.

Absent callbacks are omitted rather than represented by holes: an early
terminator would hide every entry after it from OpenSSL. The resulting table
is exposed as a complete `DigestFunctions` value so provider code cannot mix
callbacks from unrelated implementations.

The builder checks relationships between callbacks, such as operations that
must be supplied together. The attribute records presence; the operation's
builder decides what constitutes a valid combination.

This separates two questions: **was the method implemented?** and **does this
set of methods form a supported interface?** Presence detection answers the
first uniformly, while each operation's builder applies its own rules for
the second. The same mechanism can therefore serve interfaces with different
requirements.

This mechanism selects callbacks, rather than implementing them. FFI handling
remains in rustle's adapters. It is separate from Rust's trait-object vtables.
