// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Adapter slotting bc-rust hashes into `rustle`'s safe [`Digest`] trait.
//!
//! bc-rust's [`Hash`] finalizers consume the hash value, while the provider
//! contract finalizes through a mutable context; [`BcDigest`] bridges that
//! with [`core::mem::take`] (finalize the current state, leave a fresh one).

use bouncycastle::core::traits::{Hash, HashAlgParams, Suspendable};
use bouncycastle::{sha2, sha3};
use rustle::digest::{Digest, Error, Output, Result};
use rustle::params::Params;

/// A bc-rust hash behind the provider's [`Digest`] trait.
///
/// Works for any cloneable bc-rust hash: [`Hash`] supplies construction and
/// the streaming API, while [`HashAlgParams`] supplies the digest/block
/// lengths as consts.
pub struct BcDigest<H, const SLEN: usize>(H);

#[rustle::vtable]
impl<H, const SLEN: usize> Digest for BcDigest<H, SLEN>
where
    H: Hash + HashAlgParams + Clone + 'static,
    H: Suspendable<SLEN>,
{
    fn newctx() -> Result<Self> {
        Ok(Self(H::default()))
    }

    fn init(&mut self, _params: Option<Params<'_>>) -> Result {
        self.0 = H::default();
        Ok(())
    }

    // The values are per-`H`, but the table of names/types is not; the macro
    // puts it in one shared fn-local static.
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

    fn copyctx(&mut self, source: &Self) {
        self.0.clone_from(&source.0);
    }

    fn serialize(&self, out: Option<&mut Output<'_>>) -> Result<usize> {
        let Some(out) = out else {
            return Ok(SLEN);
        };

        out.write(&self.0.clone().suspend())?;

        Ok(out.written())
    }

    fn deserialize(&mut self, input: &[u8]) -> Result {
        let Ok(state) = <[u8; SLEN]>::try_from(input) else {
            return Err(Error::InvalidParameter);
        };

        self.0 = H::from_suspended(state).map_err(|_| Error::InvalidParameter)?;
        Ok(())
    }
}

const SHA256_LEN: usize = sha2::SUSPENDED_SHA256_STATE_LEN;
const SHA512_LEN: usize = sha2::SUSPENDED_SHA512_STATE_LEN;
const SHA3_LEN: usize = sha3::SUSPENDED_SHA3_STATE_LEN;

/// bc-rust's SHA2-224 as a provider digest.
pub type BcSha2_224 = BcDigest<sha2::SHA224, SHA256_LEN>;
/// bc-rust's SHA2-256 as a provider digest.
pub type BcSha2_256 = BcDigest<sha2::SHA256, SHA256_LEN>;
/// bc-rust's SHA2-384 as a provider digest.
pub type BcSha2_384 = BcDigest<sha2::SHA384, SHA512_LEN>;
/// bc-rust's SHA2-512 as a provider digest.
pub type BcSha2_512 = BcDigest<sha2::SHA512, SHA512_LEN>;
/// bc-rust's SHA2-512/224 as a provider digest.
pub type BcSha2_512_224 = BcDigest<sha2::SHA512_224, SHA512_LEN>;

/// bc-rust's SHA3-224 as a provider digest.
pub type BcSha3_224 = BcDigest<sha3::SHA3_224, SHA3_LEN>;
/// bc-rust's SHA3-256 as a provider digest.
pub type BcSha3_256 = BcDigest<sha3::SHA3_256, SHA3_LEN>;
/// bc-rust's SHA3-384 as a provider digest.
pub type BcSha3_384 = BcDigest<sha3::SHA3_384, SHA3_LEN>;
/// bc-rust's SHA3-512 as a provider digest.
pub type BcSha3_512 = BcDigest<sha3::SHA3_512, SHA3_LEN>;
