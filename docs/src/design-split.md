# The Crate Split

The workspace separates OpenSSL integration from cryptography so that a
provider author can work entirely in safe Rust.

## Responsibilities

| Crate | Responsibility |
|-------|----------------|
| `rustle` | Safe provider interfaces, OpenSSL callbacks, context lifetime, and FFI validation |
| `rustle-macros` | Build-time support for optional callback registration |
| `bc-rust-provider` | Algorithm selection and cryptography supplied by bc-rust |

All unsafe code belongs in `rustle`. The provider crate forbids unsafe code
and supplies cryptographic behavior through safe interfaces. This keeps the
FFI boundary in one place and lets implementations share the same integration
rules.

The separation is also a division of knowledge. Rustle knows how to speak
OpenSSL's provider ABI, but implements no cryptography. The provider knows
which hash to use and how to operate it, but does not need to construct raw
callback tables or interpret C pointers. A new digest can reuse the same ABI
handling rather than reproduce it for each algorithm.

`rustle` supports both `std` and `no_std` and has no target runtime
dependencies. Macro tooling runs on the build host. The provider depends on
`rustle` and bc-rust.

## Provider interface

A digest implementation supplies construction, initialization, streaming
input, finalization, and algorithm properties. Additional operations are
optional. The [vtable mechanism](./design-vtable.md) advertises only the
callbacks an implementation supplies.

The main types express different parts of that relationship:

| Type | Role |
|------|------|
| `Digest` | The safe interface implemented by a digest context |
| `DigestAlgorithm<D>` | Adapts that context type to OpenSSL's callbacks |
| `DigestFunctions` | An opaque callback table for one context type |
| `OSSL_ALGORITHM` | Associates algorithm names and properties with that table |
| `ProviderDesc` | Describes the provider and its advertised algorithms |

An application fetches an algorithm by name and properties. OpenSSL finds
the corresponding provider entry and invokes its callbacks. Rustle translates
those calls into methods on the selected digest context. The provider author
works with the safe interface throughout this path.

Keeping the callback table opaque preserves the relationship between context
creation, use, and destruction. Checking each callback's signature alone would
not prevent mixing methods from different context types.

## Algorithm properties and context parameters

Algorithm properties describe fixed characteristics such as digest and block
sizes. Context parameters are reserved for configurable state. Readable
context parameters must also be settable; genuinely write-only settings may
have setters alone.

For example, every SHA-256 computation has the same digest length, so that
length belongs to the algorithm. Exposing a context setter that only confirms
the fixed length would suggest configurability that does not exist. A setting
that genuinely varies between computations belongs to the context instead.

Parameter descriptors tell OpenSSL which names and types are supported;
handlers supply or accept their values. Rustle's parameter macros keep those
two parts together. A readable context setting requires both reading and
writing support, whereas a write-only setting has no value to expose through
a getter. These relationships are checked when the dispatch table is built.

## Ownership and the FFI boundary

Rustle manages context allocation and destruction, validates FFI arguments,
and bounds output writes. Implementations control their cryptographic state,
parameter validation, and reset policy. Recoverable failures are reported to
OpenSSL; panics must not unwind into the host process.

Each computation has its own owned context. OpenSSL holds an opaque handle,
while rustle lends the implementation access for the duration of a callback.
The provider does not take ownership of the caller's input, output, or
parameter storage. This distinction lets rustle manage lifetime at the ABI
boundary without dictating the internal representation of a hash.

Output storage may arrive uninitialized. The safe output interface bounds
writes and records how much data was produced, so a provider can write results
without reading the previous buffer contents. Parameter wrappers similarly
separate reading input values from filling output values. These checks rely
on OpenSSL supplying valid memory under its callback contract; raw pointers
cannot establish memory validity by themselves.

## Digest state

Duplication creates an independent context. Copying replaces an existing
context's computation while preserving its allocation. Both leave the source
usable. Copying supplements duplication and must complete without a
recoverable failure; implementations that cannot provide that behavior can
offer duplication alone.

Both operations copy the computation so far, including any buffered input.
The resulting contexts can continue with different messages. Copying is useful
when a destination already exists: it avoids allocating another outer context
merely to replace the old one. The callback has no error return, which is why
its contract is stricter than fallible duplication.

Serialization saves a computation so it can be restored into an initialized
context of the same algorithm. The bc-rust provider leaves the source usable
after serialization and preserves the destination's state when restoration
is rejected.

Unlike copying, serialization produces bytes that can outlive the source
context. Callers first query the required storage and then export the state.
Those bytes represent an unfinished computation, not its final digest. The
ability to resume it is distinct from any promise about portability of the
saved representation.

Serialized state is provider-specific. The bc-rust provider guarantees round
trips with the same build and algorithm, but does not promise compatibility
across upgrades or interchange with other providers. Callers must retain the
algorithm identity alongside saved state: restoring with the wrong algorithm
is not reliably detected. Saved state includes buffered input and provides
no authentication.

For the underlying OpenSSL API contracts, see
[provider-digest(7)](https://docs.openssl.org/master/man7/provider-digest/).
