// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `bc-rust-provider` — a safe OpenSSL loadable provider backed by bc-rust
//! (BouncyCastle's Rust port).
//!
//! Builds as a `cdylib`; OpenSSL calls the `OSSL_provider_init` exported by
//! [`provider_init!`](rustle::provider_init) at load time.
//!
//! The crate contains **no unsafe code** (enforced below): all FFI is done
//! through `rustle`'s safe abstractions, and all crypto comes from bc-rust.

#![forbid(unsafe_code)]

pub mod digests;
pub mod shakes;

use core::ffi::CStr;

use rustle::bindings::OSSL_ALGORITHM;
use rustle::digest::DigestAlgorithm;
use rustle::provider::{Provider, ProviderDesc};

use crate::digests::*;
use crate::shakes::{BcShake128, BcShake256};

/// Property set identifying this provider's algorithms
/// (fetchable via `-propquery provider=bc_rust`).
const PROPERTIES: &CStr = c"provider=bc_rust";

/// Digest algorithm table (`OSSL_OP_DIGEST`).
///
/// Each name list carries the legacy aliases the default provider registers
/// (short name, dashed name, SSL3 alias, and the OID) so the namemap groups
/// merge regardless of provider load order — without them, loading this
/// provider before `default` creates a rival name group and the conflict
/// makes the digest unfetchable from either provider.
static DIGESTS: [OSSL_ALGORITHM; 14] = [
    OSSL_ALGORITHM::new(
        c"SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4",
        PROPERTIES,
        DigestAlgorithm::<BcSha2_224>::functions(),
        c"bc-rust SHA-224",
    ),
    OSSL_ALGORITHM::new(
        c"SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1",
        PROPERTIES,
        DigestAlgorithm::<BcSha2_256>::functions(),
        c"bc-rust SHA-256",
    ),
    OSSL_ALGORITHM::new(
        c"SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2",
        PROPERTIES,
        DigestAlgorithm::<BcSha2_384>::functions(),
        c"bc-rust SHA-384",
    ),
    OSSL_ALGORITHM::new(
        c"SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3",
        PROPERTIES,
        DigestAlgorithm::<BcSha2_512>::functions(),
        c"bc-rust SHA-512",
    ),
    OSSL_ALGORITHM::new(
        c"SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5",
        PROPERTIES,
        DigestAlgorithm::<BcSha2_512_224>::functions(),
        c"bc-rust SHA-512/224",
    ),
    OSSL_ALGORITHM::new(
        c"SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6",
        PROPERTIES,
        DigestAlgorithm::<BcSha2_512_256>::functions(),
        c"bc-rust SHA-512/256",
    ),
    OSSL_ALGORITHM::new(
        c"SHA3-224:2.16.840.1.101.3.4.2.7",
        PROPERTIES,
        DigestAlgorithm::<BcSha3_224>::functions(),
        c"bc-rust SHA3-224",
    ),
    OSSL_ALGORITHM::new(
        c"SHA3-256:2.16.840.1.101.3.4.2.8",
        PROPERTIES,
        DigestAlgorithm::<BcSha3_256>::functions(),
        c"bc-rust SHA3-256",
    ),
    OSSL_ALGORITHM::new(
        c"SHA3-384:2.16.840.1.101.3.4.2.9",
        PROPERTIES,
        DigestAlgorithm::<BcSha3_384>::functions(),
        c"bc-rust SHA3-384",
    ),
    OSSL_ALGORITHM::new(
        c"SHA3-512:2.16.840.1.101.3.4.2.10",
        PROPERTIES,
        DigestAlgorithm::<BcSha3_512>::functions(),
        c"bc-rust SHA3-512",
    ),
    OSSL_ALGORITHM::new(
        c"SM3:1.2.156.10197.1.401",
        PROPERTIES,
        DigestAlgorithm::<BcSm3>::functions(),
        c"bc-rust SM3",
    ),
    OSSL_ALGORITHM::new(
        c"SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11",
        PROPERTIES,
        DigestAlgorithm::<BcShake128>::functions(),
        c"bc-rust SHAKE-128",
    ),
    OSSL_ALGORITHM::new(
        c"SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12",
        PROPERTIES,
        DigestAlgorithm::<BcShake256>::functions(),
        c"bc-rust SHAKE-256",
    ),
    OSSL_ALGORITHM::END,
];

/// The provider descriptor OpenSSL sees: identity params plus the algorithm
/// table above.
static PROVIDER: Provider = Provider::from_desc(ProviderDesc {
    name: c"bc_rust",
    version: c"0.1.0",
    buildinfo: c"0.1.0-dev",
    digests: &DIGESTS,
});

rustle::provider_init!(PROVIDER);
