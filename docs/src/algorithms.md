# Registered Algorithms

A provider serves one algorithm table per operation id. The core asks for
them through `query_operation`, which hands back the table for the id it was
given, or a null pointer for an operation this provider does not implement.

`bc-rust-provider` serves one table today.

## `OSSL_OP_DIGEST`

**bc-rust** hashes:

| Algorithm | Registered names |
|-----------|------------------|
| SHA2-224 | `SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4` |
| SHA2-256 | `SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1` |
| SHA2-384 | `SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2` |
| SHA2-512 | `SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3` |
| SHA3-224 | `SHA3-224:2.16.840.1.101.3.4.2.7` |
| SHA3-256 | `SHA3-256:2.16.840.1.101.3.4.2.8` |
| SHA3-384 | `SHA3-384:2.16.840.1.101.3.4.2.9` |
| SHA3-512 | `SHA3-512:2.16.840.1.101.3.4.2.10` |

All are registered with the property `provider=bc_rust`, so a fetch can be
pinned to this provider with `-propquery "?provider=bc_rust"`.

The table is the `DIGESTS` static in `bc-rust-provider`, reached by the core
through `ProviderDesc::digests`. Each entry pairs a name list with the
opaque `DigestFunctions` table `DigestAlgorithm::<H>::functions()` generates
for that hash. The table keeps all callbacks tied to that hash's context
type; provider code cannot combine callbacks from different implementations.

Method presence decides which optional callbacks each dispatch table contains.
These fixed-length hashes have no per-context state, so they register context
parameters in neither direction — as the default provider's own fixed-length
digests do not. See [Digest Vtables](./design-vtable.md).

## Operations not served

`query_operation` returns a null pointer for every other operation id, which
the core reads as "this provider implements none of these".

## Adding an algorithm

An entry is a `const`-evaluated `OSSL_ALGORITHM`:

```rust,ignore
OSSL_ALGORITHM::new(
    c"SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1",
    PROPERTIES,
    DigestAlgorithm::<BcSha2_256>::functions(),
    c"bc-rust SHA-256",
),
```

The table must end with `OSSL_ALGORITHM::END`. That is checked at
`const`-evaluation time inside `Provider::from_desc`, so a missing terminator
is a compile error rather than an out-of-bounds read in the OpenSSL core.
