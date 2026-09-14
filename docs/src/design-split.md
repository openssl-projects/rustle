# The Crate Split

The point of the split is that a provider author writes only safe Rust.

`crates/rustle` contains **every** `unsafe` block in the workspace, behind
safe APIs. `crates/bc-rust-provider` is declared `#![forbid(unsafe_code)]`
and still exports a working `OSSL_provider_init`.

## What a provider author writes

Implement `rustle::digest::Digest` for a hash type. Construction, reset,
streaming, and finalization are explicit. Mark the implementation with
`#[rustle::vtable]` so the generated table registers only the optional
methods it supplies:

```rust,ignore
#[rustle::vtable]
impl<H: Hash + HashAlgParams + Clone + 'static> Digest for BcDigest<H> {
    fn newctx() -> Result<Self> {
        Ok(Self(H::default()))
    }

    fn init(&mut self, _params: Option<Params<'_>>) -> Result {
        self.0 = H::default();
        Ok(())
    }

    rustle::gettable_params! {
        c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(H::BLOCK_LEN),
        c"size":      UNSIGNED_INTEGER => |p| p.set_size_t(H::OUTPUT_LEN),
    }

    fn update(&mut self, data: &[u8]) -> Result {
        self.0.do_update(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write_with(H::OUTPUT_LEN, |bytes| {
            core::mem::take(&mut self.0).do_final_out(bytes);
            Ok(())
        })
    }

    fn dupctx(&self) -> Result<Self> {
        Ok(Self(self.0.clone()))
    }
}
```

Then place `DigestAlgorithm::<MyHash>::functions()` in an `OSSL_ALGORITHM`
table, wrap it in a `ProviderDesc`, and export the entry point:

```rust,ignore
static PROVIDER: Provider = Provider::from_desc(ProviderDesc {
    name: c"bc_rust",
    version: c"0.1.0",
    buildinfo: c"0.1.0-dev",
    digests: &DIGESTS,
});

rustle::provider_init!(PROVIDER);
```

`DigestAlgorithm<D>` is never instantiated. It exists so each hash type gets
its own monomorphized, `END`-terminated `OSSL_FUNC_digest_*` dispatch
table. Required callbacks are always present. Optional callbacks are packed
into the table according to the methods recorded by `#[rustle::vtable]`.

`OSSL_DISPATCH` keeps its identifier and erased function pointer private.
Its typed callback constructors are crate-private, and the erasure helper
is private to the bindings module. External code cannot change either field
or register its own callback through these constructors. The C layout is
unchanged.

The constructor's function-pointer type checks the callback signature; it
cannot prove that the callback handles pointers or contexts correctly. Those
callbacks therefore live inside `rustle`, where their unsafe operations can
be reviewed together. Provider implementations supply the safe `Digest`
methods that the callbacks invoke.

Matching individual signatures is not enough. Combining one digest's
`newctx` with another digest's `update` would interpret the allocated context
as the wrong Rust type, even though both callbacks have the correct C
signatures. `DigestAlgorithm::<D>::functions()` therefore returns an opaque
`DigestFunctions` value, and `OSSL_ALGORITHM::new` accepts that value instead
of an arbitrary dispatch slice. Only the digest module constructs it, with
all callbacks generated for the same `D`. It exposes no entries or public
raw pointer; copying it preserves the complete table. Provider algorithm
declarations keep their existing syntax.

## What the abstraction absorbs

Everything that has to cross the FFI boundary:

- **Context lifetime.** `newctx` and optional `dupctx` return owned `D`
  values; the adapters allocate them behind `*mut c_void`, and `freectx`
  drops them. See [Context Memory](./design-memory.md).
- **Raw pointer discipline.** Null checks, `from_raw_parts` over the core's
  `(ptr, len)` pairs, out-pointer writes. Every block carries a `SAFETY:`
  justification, enforced by `clippy::undocumented_unsafe_blocks`.
- **Parameter arrays.** `OSSL_PARAM` is a C struct of type-erased `void *`
  fields; `Params`/`ParamsMut` wrap the `END`-terminated arrays and the
  `gettable_params!`/`settable_ctx_params!`/`gettable_ctx_params!` macros
  generate the descriptor table and the handler from one list, so a descriptor
  can never drift out of sync with its handler.
- **The unmangled entry point.** `provider_init!` expands to the one
  `unsafe extern "C"` symbol a provider inherently needs. The tokens live in
  `rustle`, so the macro can be invoked from a crate that forbids unsafe.

`Params::from_ptr` and `ParamsMut::from_ptr` are crate-private unsafe
constructors. Only the FFI layer inside `rustle` can call them; provider
implementations work with borrowed parameters through safe methods. A raw
pointer cannot prove array termination, storage validity, lifetime, or
aliasing. The FFI callbacks establish those requirements from the core's
contract before constructing a view. The read-only view requires its array,
keys, and data to remain valid and unchanged for the borrow; the mutable
view additionally requires exclusive access to the array and compatible
access to its data buffers. Parameter lookup and dispatch then use the
borrowed views through safe methods.

Mutable lookup returns a `ParamMut<'_>` cell, and `Digest::get_param` takes
`&mut ParamMut<'_>`. Both getter macros use that same signature, so existing
`|p| p.set_size_t(...)` handlers keep their shape; the context getter takes
`&self` alongside it, since reading a context parameter never mutates one. The wrapper exposes the
parameter name, type checks, and setters; its raw `&mut OSSL_PARAM` stays
private. It provides no mutable dereference or conversion back to the raw
cell. Returning the raw reference would allow `mem::replace` to extract an
owned `OSSL_PARAM` containing pointers to temporary core buffers. Moving a
`ParamMut` instead retains its lifetime, keeping it within the array borrow.

Output buffers need only be writable: `ParamMut` offers no data getters
that could read an uninitialized output buffer. Input parameters continue
to use the read-only view and its data getters. Descriptor tables retain
the raw ABI representation behind `ParamTable`, separate from borrowed
writable cells.

The integer output helpers support only their native widths: `set_int`
requires an `INTEGER` buffer of `sizeof(int)`, and `set_size_t` an
`UNSIGNED_INTEGER` buffer of `sizeof(size_t)`. Other buffer sizes fail
without writing; unlike OpenSSL's general setters, these helpers do not
convert integer widths. Null data remains a size query regardless of
`data_size`. For a matching type, `return_size` reports the native width
on both queries and size failures; a type mismatch resets it to zero.

## Const validation

Table termination is checked at `const`-evaluation time. A `ProviderDesc`
whose `digests` table lacks its `OSSL_ALGORITHM::END` fails to compile:

```rust,ignore
assert!(
    !desc.digests.is_empty() && desc.digests[desc.digests.len() - 1].is_end(),
    "algorithm table must be OSSL_ALGORITHM::END-terminated"
);
```

Digest dispatch termination is checked when the digest module constructs
its associated `DigestFunctions` constant. The OpenSSL core walks these
arrays looking for the terminator; an unterminated one would read beyond
the table. The private construction path preserves that check together with
the requirement that every callback uses the same context type.

Parameter descriptors use a validated `ParamTable`. `Digest::gettable_params`,
`Digest::settable_ctx_params` and `Digest::gettable_ctx_params` all return this
type, so a hand-written implementation cannot return an arbitrary slice to the
FFI callbacks. Its private backing slice is static; `ParamTable::new`
returns `None` for an empty slice or a table without a final `OSSL_PARAM::END`.
An empty descriptor table contains only `END`. Duplicate names retain
first-match lookup, and consumers still stop at an earlier `END` if present.

`param_table!` appends `END` and validates the result in a const initializer.
A malformed generated table is therefore a compile error; direct calls to
the constructor can handle `None` without aborting the host. The getter and
setter macros return the validated wrapper, and the provider's own metadata
table uses it too. Pointer access remains inside `rustle`.

Termination alone does not make descriptor names valid. `OSSL_PARAM::defn`
requires a `&'static CStr`, matching the C-string literals used by the macros.
The descriptor can then store the key pointer without losing its lifetime.

## Method-driven dispatch

`#[rustle::vtable]` records which optional digest methods an implementation
supplies. This avoids capability-trait combinations while keeping one
strongly typed context and one audited set of FFI adapters. See
[Digest Vtables](./design-vtable.md) for the interface and its current scope.

## Minimal dependencies

`rustle` has no target runtime dependencies. Its `rustle-macros` dependency
uses `syn`, `quote`, and `proc-macro2` on the build host to generate safe
method-presence metadata. That tooling is not linked into the provider.
`bc-rust-provider` depends only on `rustle` and bc-rust. Keeping host macro
tooling separate preserves the runtime's `no_std` support.
