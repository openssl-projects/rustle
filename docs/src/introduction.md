# Introduction

`rustle` is a Rust workspace for building OpenSSL 3.4+ [loadable
providers](https://docs.openssl.org/master/man7/provider/) — dynamically
loaded modules that supply cryptographic algorithm implementations to
libcrypto.

The workspace splits the problem in two, so that *speaking the provider ABI*
and *implementing cryptography* never live in the same crate:

| Crate | Role | Safety posture |
|-------|------|----------------|
| `crates/rustle` | Safe abstraction over the provider FFI | Contains every `unsafe` block in the workspace, behind safe APIs; `no_std` by default; no target runtime dependencies |
| `crates/rustle-macros` | Host-side method-presence macro | Generates safe metadata; its parser dependencies are not linked into providers |
| `crates/bc-rust-provider` | The loadable provider module (`cdylib`) | `#![forbid(unsafe_code)]`; crypto from bc-rust (BouncyCastle's Rust port) |

## Where to go next

- [Getting Started](./getting-started.md) — build the module and drive it
  from the `openssl` CLI.
- [Registered Algorithms](./algorithms.md) — what the provider exposes, and
  why the alias lists matter.
- [Design](./design.md) — the crate split, context memory, and the panic
  posture.
- [Building and Verifying](./building.md) — the feature matrix and the
  invariants to check before committing.
