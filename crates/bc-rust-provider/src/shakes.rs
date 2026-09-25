// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! SHAKE adapters retaining the live sponge across incremental output calls.

use bouncycastle::core::traits::XOF;
use bouncycastle::sha3;
use rustle::digest::{Digest, Error, Output, Result};
use rustle::params::{OSSL_PARAM, Params};

/// SHAKE128 with a 168-byte sponge rate and an explicitly selected final length.
pub type BcShake128 = BcShake<sha3::SHAKE128, 168>;
/// SHAKE256 with a 136-byte sponge rate and an explicitly selected final length.
pub type BcShake256 = BcShake<sha3::SHAKE256, 136>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Absorbing,
    Squeezing,
    Finalized,
}

/// A cloneable bc-rust XOF with OpenSSL's SHAKE length and phase semantics.
#[derive(Clone)]
pub struct BcShake<X, const RATE: usize> {
    state: X,
    xoflen: usize,
    phase: Phase,
}

impl<X: XOF, const RATE: usize> BcShake<X, RATE> {
    fn set_length(&mut self, param: &OSSL_PARAM) -> bool {
        let Some(len) = param.get_size_t() else {
            return false;
        };
        self.xoflen = len;
        true
    }

    fn write_output(&mut self, out: &mut Output<'_>, len: usize) -> Result {
        out.write_with(len, |bytes| {
            // Capacity is checked before either the sponge or phase advances.
            self.phase = Phase::Squeezing;
            if self.state.squeeze_out(bytes) != len {
                return Err(Error::InvalidState);
            }
            Ok(())
        })
    }
}

#[rustle::vtable]
impl<X: XOF + Clone + 'static, const RATE: usize> Digest for BcShake<X, RATE> {
    fn newctx() -> Result<Self> {
        Ok(Self {
            state: X::default(),
            // Match OpenSSL's unset-length sentinel; zero is an explicit length.
            xoflen: usize::MAX,
            phase: Phase::Absorbing,
        })
    }

    fn init(&mut self, params: Option<Params<'_>>) -> Result {
        self.state = X::default();
        self.phase = Phase::Absorbing;
        self.apply_ctx_params(params)
    }

    rustle::gettable_params! {
        c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(RATE),
        c"size":      UNSIGNED_INTEGER => |p| p.set_size_t(0),
        c"xof":       INTEGER          => |p| p.set_int(1),
    }

    rustle::gettable_ctx_params! {
        c"xoflen": UNSIGNED_INTEGER => |this, p| p.set_size_t(this.xoflen),
        c"size":   UNSIGNED_INTEGER => |this, p| p.set_size_t(this.xoflen),
    }

    rustle::settable_ctx_params! {
        c"xoflen": UNSIGNED_INTEGER => |this, p| this.set_length(p),
        c"size":   UNSIGNED_INTEGER => |this, p| this.set_length(p),
    }

    fn apply_ctx_params(&mut self, params: Option<Params<'_>>) -> Result {
        let Some(params) = params else { return Ok(()) };
        let mut length = None;
        for param in params.iter() {
            if let Some(key) = param.key()
                && (key == c"xoflen" || key == c"size")
            {
                // Aliases and repeated names must be rejected before mutation,
                // matching OpenSSL's SHAKE parameter decoder.
                if length.replace(param).is_some() {
                    return Err(Error::InvalidParameter);
                }
            }
        }
        if let Some(param) = length
            && !self.set_length(param)
        {
            return Err(Error::InvalidParameter);
        }
        Ok(())
    }

    fn update(&mut self, input: &[u8]) -> Result {
        if input.is_empty() {
            return Ok(());
        }
        if self.phase != Phase::Absorbing {
            return Err(Error::InvalidState);
        }
        self.state.absorb(input).map_err(|_| Error::InvalidState)
    }

    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        if self.xoflen == usize::MAX {
            return Err(Error::InvalidParameter);
        }
        if self.phase != Phase::Absorbing {
            return Err(Error::InvalidState);
        }
        // OpenSSL's zero-byte final leaves the sponge phase untouched.
        // EVP tracks its own finalized flag separately (crypto/evp/digest.c).
        if self.xoflen == 0 {
            return Ok(());
        }
        self.write_output(out, self.xoflen)?;
        self.phase = Phase::Finalized;
        Ok(())
    }

    fn squeeze(&mut self, out: &mut Output<'_>, len: usize) -> Result {
        if self.phase == Phase::Finalized {
            return Err(Error::InvalidState);
        }
        self.write_output(out, len)
    }

    fn dupctx(&self) -> Result<Self> {
        Ok(self.clone())
    }

    fn copyctx(&mut self, source: &Self) {
        self.clone_from(source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    fn next_bytes<X: XOF + Clone>(state: &X) -> [u8; 32] {
        let mut bytes = [0; 32];
        assert_eq!(state.clone().squeeze_out(&mut bytes), bytes.len());
        bytes
    }

    fn short_output_preserves_state<X: XOF + Clone + 'static, const RATE: usize>() -> Result {
        let mut ctx = BcShake::<X, RATE>::newctx()?;
        ctx.update(b"abc")?;
        ctx.xoflen = 32;
        let mut short = [MaybeUninit::uninit(); 1];
        let expected = next_bytes(&ctx.state);
        let mut out = Output::new(&mut short);
        assert_eq!(ctx.finalize(&mut out), Err(Error::BufferTooSmall));
        assert_eq!(out.written(), 0);
        assert!(matches!(ctx.phase, Phase::Absorbing));
        assert_eq!(next_bytes(&ctx.state), expected);

        let mut prefix = [MaybeUninit::uninit(); 7];
        ctx.squeeze(&mut Output::new(&mut prefix), 7)?;
        let expected = next_bytes(&ctx.state);
        let mut out = Output::new(&mut short);
        assert_eq!(ctx.squeeze(&mut out, 32), Err(Error::BufferTooSmall));
        assert_eq!(out.written(), 0);
        assert!(matches!(ctx.phase, Phase::Squeezing));
        assert_eq!(next_bytes(&ctx.state), expected);
        Ok(())
    }

    #[test]
    fn shake128_short_output_preserves_state() -> Result {
        short_output_preserves_state::<sha3::SHAKE128, 168>()
    }

    #[test]
    fn shake256_short_output_preserves_state() -> Result {
        short_output_preserves_state::<sha3::SHAKE256, 136>()
    }
}
