# Panics and Lints

A provider runs inside another application's process. Rust panics must never
unwind across its C boundary.

## Failure policy

Development and release builds use `panic = "abort"`. The optional `abort`
feature supplies panic handling for a final `no_std` artifact; a build using
`std` relies on the standard library instead.

Aborting terminates the host process, so it is a backstop rather than normal
error handling. Expected failures should be returned through the provider API.

## Lint policy

Workspace lints encourage fallible access, checked arithmetic, documented
unsafe operations, and compatibility with `no_std`. They also check API
documentation and discourage calls that may unwind through FFI.

Many of these checks are warnings, while selected language-safety rules are
denied. A justified exception should explain its rationale in a source
comment. The exact lint configuration lives in the workspace `Cargo.toml`;
passing it supports review but does not prove the absence of panics or bugs.
