# Building and Verifying

## Crate features (`rustle`)

The `rustle-macros` proc-macro crate and its parser dependencies compile for
the build host. They require the host Rust standard library even when the
target build uses `no_std`; they are not linked into the provider module.

| Feature | Effect |
|---------|--------|
| *(default)* | `no_std`: only `core`, contexts on the C heap |
| `std` | Link the standard library (required by bc-rust, drops the panic handler) |
| `abort` | Provide the `no_std` `#[panic_handler]`; enable from the final `no_std` artifact, inert when `std` is on |
| `debug` | Bring-up tracing to stderr; disabled when off |

`abort` is separate from the default on purpose. Only the *final* artifact in
a link may define a `#[panic_handler]`, so a crate that might be linked
alongside another `no_std` component must be able to leave it out.

`debug` is a developer aid for bringing up a provider. It is separate from
OpenSSL's error reporting.

## The invariants

`rustle` must always compile under **both** of its configurations. The
`Makefile` at the workspace root drives everything a change has to pass:

```sh
make check
```

which is these steps, each also a target of its own:

| Step | Target |
|------|--------|
| `cargo build -p rustle --no-default-features --features abort` (`no_std`) | `build-no-std` |
| `cargo build -p rustle --features std` | `build-std` |
| `cargo build -p bc-rust-provider` (the module) | `module` |
| Build the C test programs without running them | `build-test` |
| `cargo fmt --check` | `rust-fmt-check` |
| `clang-format --dry-run --Werror` over the C test sources | `c-fmt-check` |
| `cargo test` — Rust tests and doctests | `cargo-test` |
| `prove` over `test/recipes/` — C-side KATs | `c-test` |

`fmt-check` runs both formatting checks, and `make test` runs the last two
together. `PROFILE` accepts `debug` (the default) or `release` and selects both
the Cargo profile and the module directory (`target/debug` or `target/release`).
For example, `make PROFILE=release c-test` runs the C suite against the release
module. Other profile names are rejected;
`CARGO_FLAGS` is no longer used.
`PROVE_FLAGS` passes through to the TAP harness. `make help` lists the rest.

The C formatting targets require clang-format; CI pins 22.1.8 for reproducible
results. Set `CLANG_FORMAT` when that binary is installed under a versioned or
non-standard name.

OpenSSL 3.4 is the oldest supported libcrypto. C builds check that
`pkg-config` finds a `libcrypto` at least that new before compiling any C
source, and stop with its diagnostic otherwise. Rust-only targets,
`help`, and `clean` do not require `pkg-config` or libcrypto.

On macOS, the system `openssl` is LibreSSL and Homebrew keeps `openssl@3`
keg-only, so `pkg-config` finds no `libcrypto.pc` by default. Point it at the
keg — what CI does:

```sh
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
```

GitHub Actions checks formatting before testing on Ubuntu and macOS, on both
x86_64 and arm64. The Ubuntu jobs use 26.04, whose packaged OpenSSL meets the
minimum; 24.04's does not. CI jobs run only in `openssl-projects/rustle`; pull requests
from forks targeting upstream remain eligible to run there.

To build and test against a configured OpenSSL build tree instead of the
system OpenSSL, pass its root once:

```sh
make OPENSSL_ROOT_DIR=/path/to/openssl check
```

This selects the libcrypto build used by the C tests. Switching roots does not
require `make clean`.

The `no_std` build is the one that breaks silently: `bc-rust-provider` pulls
in `std`, so building only the module will never tell you that `rustle`
stopped being `no_std`-clean.

## Why two test suites

A provider sits between two ecosystems, so it needs a test boundary on each
side. The Cargo suite checks Rust behavior and API examples. The C suite is an independent native
consumer of the provider ABI, which catches integration mistakes that a test
running only from the Rust side could share or overlook.

Neither suite substitutes for the other: together they check that the Rust
implementation builds as a Rust component and behaves as a C component once
loaded by OpenSSL.

### Running C tests

Requested C test programs are rebuilt on every build or test invocation,
including their shared sources. The suite is small enough that rebuilding is
cheap; this avoids tracking header dependencies and configuration changes.
Each source is compiled separately, so compilation-database tools still work.
All build rules live in the root `Makefile`: shared objects and providers are
built once per invocation, including under `make -j check`.
Add C programs to `TEST_SRCS` there and their TAP recipes under `test/recipes/`.

The C rules honor `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, and `LDLIBS`.
`CFLAGS` defaults to `-O2 -g` and is passed during both compilation and linking;
`CPPFLAGS` applies to compilation, while `LDFLAGS` and `LDLIBS` apply to linking.
Project include paths, test definitions, and warning flags are kept separately,
so overriding `CFLAGS` does not discard them. For example:

```sh
make CFLAGS='-O0 -g' c-test
```

The `prove` harness collects results across the C test programs. Use `-v`
for verbose output or `-j` to run recipes in parallel:

```sh
make PROVE_FLAGS=-v c-test
```

After building, a single recipe can also run directly:

```sh
prove -v test/recipes/02-test_evp_md.t
```

When a failure needs picking apart, `make run` runs the same programs
without the harness in the way, and a program run directly takes `-list`,
`-test N` and `-iter N` to narrow down to a single case.

### C sanitizers

Pass sanitizer flags when compiling and linking the C tests:

```sh
make CFLAGS='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined' \
     LDFLAGS='-fsanitize=address,undefined' c-test
```

On macOS and Linux, the shared driver supplies `__asan_default_options`
with `detect_leaks=1`. A LeakSanitizer-capable ASan runtime therefore checks
for leaks at normal process exit, including when a test is run directly.
No environment setting is needed. `ASAN_OPTIONS` overrides these defaults;
for example, `ASAN_OPTIONS=detect_leaks=0 ./test/evp_xof_test` disables the
exit-time leak check for that invocation. Unsanitized builds do not use the
hook.

These flags instrument the C tests and shared test utilities. Instrumenting
OpenSSL or the Rust provider requires building those components separately
with their sanitizer settings. LeakSanitizer can still track intercepted
heap allocations from libraries without compiler instrumentation.

## Layout

```text
Makefile                   top-level entry point (`make help`)
crates/rustle/             safe provider-ABI layer (lib; no_std by default)
crates/rustle-macros/      host-side method-presence attribute (proc-macro)
crates/bc-rust-provider/   the loadable provider module (cdylib), zero unsafe
test/                      C tests against the module, OpenSSL's test layout
test/recipes/              one prove recipe per test program
test/perl/                 what the recipes share
docs/                      this book
```

## Building this book

```sh
mdbook build docs
mdbook serve docs   # live-reloading preview on localhost:3000
```
