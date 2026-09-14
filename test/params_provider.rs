// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only provider exposing inline string parameters to the C tests.
//! Its dummy digest exists only to exercise the parameter callbacks.

#![forbid(unsafe_code)]

use rustle::bindings::OSSL_ALGORITHM;
use rustle::digest::{Digest, DigestAlgorithm, Output, Result};
use rustle::params::Params;
use rustle::provider::{Provider, ProviderDesc};

struct TestDigest(u8);

#[rustle::vtable]
impl Digest for TestDigest {
    fn newctx() -> Result<Self> {
        Ok(Self(0))
    }

    fn init(&mut self, params: Option<Params<'_>>) -> Result {
        self.0 = 0;
        self.apply_ctx_params(params)
    }

    rustle::gettable_params! {
        c"size": UNSIGNED_INTEGER => |p| p.set_size_t(1),
        c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(1),
        c"test-text": UTF8_STRING => |p| p.set_utf8_string("abc"),
        c"test-empty": UTF8_STRING => |p| p.set_utf8_string(""),
    }

    rustle::settable_ctx_params! {
        c"test-value": INTEGER => |this, p| match p.get_int().and_then(|n| u8::try_from(n).ok()) {
            Some(value) => { this.0 = value; true }
            None => false,
        },
    }

    // Paired with the setter above, as upstream pairs a digest's context
    // getter with its setter.
    rustle::gettable_ctx_params! {
        c"test-value": INTEGER => |this, p| p.set_int(this.0.into()),
    }

    fn update(&mut self, _data: &[u8]) -> Result {
        Ok(())
    }

    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write(&[self.0])
    }
}

static ALGORITHMS: [OSSL_ALGORITHM; 2] = [
    OSSL_ALGORITHM::new(
        c"RUSTLE-PARAMS-TEST",
        c"provider=rustle_params_test",
        DigestAlgorithm::<TestDigest>::functions(),
        c"Parameter test fixture; not a cryptographic digest",
    ),
    OSSL_ALGORITHM::END,
];

static PROVIDER: Provider = Provider::from_desc(ProviderDesc {
    name: c"rustle_params_test",
    version: c"0",
    buildinfo: c"test fixture",
    digests: &ALGORITHMS,
});

rustle::provider_init!(PROVIDER);
