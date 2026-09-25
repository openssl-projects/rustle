# rustle

Rust crates for building OpenSSL 3.4+ [loadable
providers](https://docs.openssl.org/master/man7/provider/) — dynamically
loaded modules that supply cryptographic algorithm implementations to
libcrypto.

The workspace splits the problem in two, so that *speaking the provider ABI*
and *implementing cryptography* never live in the same crate:

| Crate | Role |
|-------|------|
| [`crates/rustle`](crates/rustle) | Safe abstraction over the provider FFI — contains every `unsafe` block in the workspace, behind safe APIs |
| [`crates/rustle-macros`](crates/rustle-macros) | Host-side method-presence macro for optional provider callbacks |
| [`crates/bc-rust-provider`](crates/bc-rust-provider) | The loadable provider module (`cdylib`) — `#![forbid(unsafe_code)]`, crypto from bc-rust |


## Quick start

Needs a Rust toolchain with edition 2024 and OpenSSL 3.4 or newer.
Cargo fetches bc-rust automatically from Git.

```sh
cargo build -p bc-rust-provider
```

```sh
printf abc | openssl dgst -sha256 -provider-path target/debug -provider libbc_rust
```

```sh
make test
```

## Documentation

The book covers the design, the algorithm tables, and the build invariants:

```sh
mdbook serve docs
```


## License

Apache License 2.0, the same terms as OpenSSL itself — see
[LICENSE.txt](LICENSE.txt).
