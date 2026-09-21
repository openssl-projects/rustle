# Getting Started

## Requirements

- A Rust toolchain with edition 2024.
- An OpenSSL installation for the CLI.
- clang-format 22.1.8

## Build the module

```sh
cargo build -p bc-rust-provider
```

This produces `target/debug/libbc_rust.dylib` (Linux: `libbc_rust.so`), a
provider named `bc_rust`. OpenSSL resolves it by the file stem, so the module
name to pass on the command line is `libbc_rust`.

## List what it registers

```sh
openssl list -provider-path target/debug -provider libbc_rust -digest-algorithms \
    -propquery "?provider=bc_rust"
```

```text
Provided:
  { 2.16.840.1.101.3.4.2.1, SHA-256, SHA2-256, SHA256 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.6, SHA-512/256, SHA2-512/256, SHA512-256 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.4, SHA-224, SHA2-224, SHA224 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.7, SHA3-224 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.9, SHA3-384 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.3, SHA-512, SHA2-512, SHA512 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.5, SHA-512/224, SHA2-512/224, SHA512-224 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.2, SHA-384, SHA2-384, SHA384 } @ libbc_rust
  { 1.2.156.10197.1.401, SM3 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.8, SHA3-256 } @ libbc_rust
  { 2.16.840.1.101.3.4.2.10, SHA3-512 } @ libbc_rust
```

## Hash something through it

```sh
printf abc | openssl dgst -sha256 -provider-path target/debug -provider libbc_rust
```

```text
SHA2-256(stdin)= ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Passing `-provider` without `-provider default` loads *only* this provider,
so a correct answer here can only have come from bc-rust.

## Run the tests

```sh
make test
```

This runs the Rust tests and doctests (`make cargo-test`) and the C suite
under `prove` (`make c-test`). The C suite drives the provider through
libcrypto's EVP API.

To select a custom configured OpenSSL build tree for the C suite:

```sh
make OPENSSL_ROOT_DIR=/path/to/openssl test
```

See [Building and Verifying](./building.md) for what each suite covers and
how to run one of them alone.

## Writing your own provider

Implement [`rustle::digest::Digest`](./design-split.md) for a hash type,
place `DigestAlgorithm::<MyHash>::functions()` in a const-validated
`OSSL_ALGORITHM` table, and let `provider_init!` export the
`OSSL_provider_init` entry point. See [The Crate Split](./design-split.md)
for the full shape.
