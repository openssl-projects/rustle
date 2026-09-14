// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Digest operation: a safe, method-driven Digest interface and the FFI glue
//! that adapts implementations to OpenSSL.
//!
//! A provider implements Digest, marks the implementation with the vtable
//! attribute, and uses DigestAlgorithm::functions in its algorithm table.
//! Optional OpenSSL callbacks are registered only when their methods exist.

#[cfg(test)]
mod tests;

use core::{ffi, marker::PhantomData, mem::MaybeUninit};

use crate::bindings::OSSL_DISPATCH;
use crate::heap;
use crate::params::{OSSL_PARAM, ParamMut, ParamTable, Params, ParamsMut};

/// A digest dispatch table whose callbacks share one context type.
///
/// Obtained only from DigestAlgorithm::functions. Its private entries keep
/// every registered callback tied to the same Digest implementation.
///
/// An arbitrary dispatch slice cannot be wrapped by external code.
#[derive(Clone, Copy)]
pub struct DigestFunctions {
    entries: &'static [OSSL_DISPATCH],
}

impl DigestFunctions {
    const fn new(entries: &'static [OSSL_DISPATCH]) -> Self {
        assert!(
            matches!(entries.last(), Some(last) if last.is_end()),
            "dispatch table must be OSSL_DISPATCH::END-terminated"
        );
        Self { entries }
    }

    pub(crate) const fn as_ptr(&self) -> *const OSSL_DISPATCH {
        self.entries.as_ptr()
    }
}

/// Errors that the digest adapters translate to C failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The operation is not implemented.
    Unsupported,
    /// The caller's output buffer cannot hold the requested bytes.
    BufferTooSmall,
    /// A context parameter was rejected.
    InvalidParameter,
}

/// A fallible operation on a digest context.
pub type Result<T = ()> = core::result::Result<T, Error>;

/// Borrowed output storage that tracks the bytes initialized by a digest.
///
/// C output need not be initialized. `write_with` initializes only the region
/// requested by the implementation before lending it to existing Rust crypto
/// APIs. No raw pointer or mutable access to the written length is exposed.
pub struct Output<'a> {
    storage: &'a mut [MaybeUninit<u8>],
    written: usize,
}

impl<'a> Output<'a> {
    /// Wrap exclusive output storage, initially reporting no bytes written.
    pub fn new(storage: &'a mut [MaybeUninit<u8>]) -> Self {
        Self {
            storage,
            written: 0,
        }
    }

    /// Append bytes without reading the previous contents of the buffer.
    ///
    /// # Errors
    /// Returns [`Error::BufferTooSmall`] without writing if the bytes do not fit.
    pub fn write(&mut self, bytes: &[u8]) -> Result {
        let end = self
            .written
            .checked_add(bytes.len())
            .ok_or(Error::BufferTooSmall)?;
        let dst = self
            .storage
            .get_mut(self.written..end)
            .ok_or(Error::BufferTooSmall)?;
        for (slot, byte) in dst.iter_mut().zip(bytes) {
            slot.write(*byte);
        }
        self.written = end;
        Ok(())
    }

    /// Append `len` bytes using an existing API that needs initialized storage.
    ///
    /// The callback is not invoked when capacity is insufficient. The region
    /// is zeroed first; the written length advances only if the callback succeeds.
    ///
    /// # Errors
    /// Returns [`Error::BufferTooSmall`] if the region does not fit, or propagates
    /// the callback's error without advancing the written length.
    pub fn write_with(&mut self, len: usize, fill: impl FnOnce(&mut [u8]) -> Result) -> Result {
        let end = self.written.checked_add(len).ok_or(Error::BufferTooSmall)?;
        let dst = self
            .storage
            .get_mut(self.written..end)
            .ok_or(Error::BufferTooSmall)?;
        for slot in dst.iter_mut() {
            slot.write(0);
        }
        // SAFETY: every byte in this exclusive region was initialized above;
        // MaybeUninit<u8> has u8's layout, and the borrow lasts through fill.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), dst.len()) };
        fill(bytes)?;
        self.written = end;
        Ok(())
    }

    /// Number of initialized output bytes committed by successful writes.
    #[must_use]
    pub fn written(&self) -> usize {
        self.written
    }
}

/// A streaming digest with explicit construction and optional operations.
///
/// Implement with [`crate::vtable`]. The required core remains ordinary Rust
/// methods; optional methods have safe failure defaults and are registered only
/// when implemented. Presence metadata is never used as a memory-safety proof.
#[crate::vtable]
pub trait Digest: Sized + 'static {
    /// Construct owned state; rustle allocates and frees its C context.
    ///
    /// # Errors
    /// Return an error if implementation-specific construction fails.
    fn newctx() -> Result<Self>;

    /// Start or restart a computation. `None` represents a null parameter array.
    ///
    /// Implementations with context setters can call `Self::apply_ctx_params`
    /// after resetting their state. Reset policy belongs to the implementation.
    ///
    /// # Errors
    /// Return an error if resetting state or applying parameters fails.
    fn init(&mut self, params: Option<Params<'_>>) -> Result;

    /// Absorb input into an initialized computation.
    ///
    /// # Errors
    /// Return an error if the implementation cannot absorb the input.
    fn update(&mut self, input: &[u8]) -> Result;

    /// Write the digest, checking capacity before consuming the hash state.
    ///
    /// # Errors
    /// Return an error if output space is insufficient or finalization fails.
    fn finalize(&mut self, out: &mut Output<'_>) -> Result;

    /// Describe algorithm-wide parameters. May be generated by `gettable_params!`.
    fn gettable_params() -> ParamTable;

    /// Fill one described algorithm-wide parameter.
    fn get_param(name: &ffi::CStr, param: &mut ParamMut<'_>) -> bool;

    /// Optionally duplicate a context, including any partial computation.
    ///
    /// # Errors
    /// The default returns [`Error::Unsupported`]. Implementations can report
    /// failure to duplicate their state through an error.
    fn dupctx(&self) -> Result<Self> {
        Err(Error::Unsupported)
    }

    /// Optional descriptor table, paired with `set_ctx_param`.
    #[must_use]
    fn settable_ctx_params() -> ParamTable {
        crate::param_table! {}
    }

    /// Apply one described context parameter. Unknown names are not dispatched.
    fn set_ctx_param(&mut self, _name: &ffi::CStr, _param: &OSSL_PARAM) -> bool {
        false
    }

    /// Optional descriptor table, paired with `get_ctx_param`.
    ///
    /// Only genuinely per-context state belongs here; a value fixed for the
    /// algorithm belongs in `gettable_params` instead.
    #[must_use]
    fn gettable_ctx_params() -> ParamTable {
        crate::param_table! {}
    }

    /// Optional: Fill one described context parameter. Unknown names are not dispatched.
    fn get_ctx_param(&self, _name: &ffi::CStr, _param: &mut ParamMut<'_>) -> bool {
        false
    }

    /// Apply supported parameters during initialization or a setter callback.
    ///
    /// A null array succeeds. Unrecognized names are ignored, preserving the
    /// existing parameter dispatch convention. Absence of setters is expressed
    /// by omitting their C callbacks, independently of this init helper.
    ///
    /// # Errors
    /// Returns [`Error::InvalidParameter`] when a handler rejects a value.
    fn apply_ctx_params(&mut self, params: Option<Params<'_>>) -> Result {
        let Some(params) = params else { return Ok(()) };
        if !Self::HAS_SET_CTX_PARAM {
            return Ok(());
        }
        for descriptor in Self::settable_ctx_params().iter() {
            let Some(name) = descriptor.key() else { break };
            if let Some(param) = params.locate(name)
                && !self.set_ctx_param(name, param)
            {
                return Err(Error::InvalidParameter);
            }
        }
        Ok(())
    }
}

/// Adapts one digest implementation to the OpenSSL ABI.
///
/// Context setter and descriptor methods must be implemented together.
/// An incomplete pair fails when the dispatch constant is evaluated.
pub struct DigestAlgorithm<D>(PhantomData<D>);

impl<D: Digest> DigestAlgorithm<D> {
    // The upper bound includes every callback currently supported and END.
    // Const slice indexing is not available on the minimum toolchain. Both
    // indices are bounded by the candidate count and the extra END slot.
    #[allow(clippy::indexing_slicing)]
    const ENTRIES: [OSSL_DISPATCH; 13] = {
        assert!(
            D::HAS_SET_CTX_PARAM == D::HAS_SETTABLE_CTX_PARAMS,
            "context setter and descriptor methods must be implemented together"
        );
        assert!(
            D::HAS_GET_CTX_PARAM == D::HAS_GETTABLE_CTX_PARAMS,
            "context getter and descriptor methods must be implemented together"
        );
        assert!(
            !D::HAS_GET_CTX_PARAM || D::HAS_SET_CTX_PARAM,
            "a gettable context parameter must be settable too"
        );
        let candidates = [
            Some(OSSL_DISPATCH::digest_newctx(Self::newctx)),
            Some(OSSL_DISPATCH::digest_freectx(Self::freectx)),
            Some(OSSL_DISPATCH::digest_init(Self::init)),
            Some(OSSL_DISPATCH::digest_update(Self::update)),
            Some(OSSL_DISPATCH::digest_final(Self::finalize)),
            Some(OSSL_DISPATCH::digest_get_params(Self::get_params)),
            Some(OSSL_DISPATCH::digest_gettable_params(Self::gettable_params)),
            if D::HAS_DUPCTX {
                Some(OSSL_DISPATCH::digest_dupctx(Self::dupctx))
            } else {
                None
            },
            if D::HAS_SET_CTX_PARAM {
                Some(OSSL_DISPATCH::digest_set_ctx_params(Self::set_ctx_params))
            } else {
                None
            },
            if D::HAS_SETTABLE_CTX_PARAMS {
                Some(OSSL_DISPATCH::digest_settable_ctx_params(
                    Self::settable_ctx_params,
                ))
            } else {
                None
            },
            if D::HAS_GET_CTX_PARAM {
                Some(OSSL_DISPATCH::digest_get_ctx_params(Self::get_ctx_params))
            } else {
                None
            },
            if D::HAS_GETTABLE_CTX_PARAMS {
                Some(OSSL_DISPATCH::digest_gettable_ctx_params(
                    Self::gettable_ctx_params,
                ))
            } else {
                None
            },
        ];
        let mut entries = [OSSL_DISPATCH::END; 13];
        let mut source = 0;
        let mut dest = 0;
        // Each candidate contributes at most one entry, leaving room for END.
        while source < candidates.len() {
            if let Some(entry) = candidates[source] {
                entries[dest] = entry;
                dest += 1;
            }
            source += 1;
        }
        entries
    };

    /// The opaque, static dispatch table, with absent operations omitted.
    #[must_use]
    pub const fn functions() -> DigestFunctions {
        DigestFunctions::new(&Self::ENTRIES)
    }

    unsafe extern "C" fn newctx(_provctx: *mut ffi::c_void) -> *mut ffi::c_void {
        match D::newctx() {
            Ok(ctx) => heap::alloc(ctx).cast(),
            Err(_) => core::ptr::null_mut(),
        }
    }

    unsafe extern "C" fn freectx(dctx: *mut ffi::c_void) {
        // SAFETY: this table's contexts come only from its newctx/dupctx.
        unsafe { heap::free(dctx.cast::<D>()) };
    }

    unsafe extern "C" fn dupctx(dctx: *mut ffi::c_void) -> *mut ffi::c_void {
        if dctx.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: OpenSSL lends a live D created by this table's allocator.
        let ctx = unsafe { &*dctx.cast::<D>() };
        match ctx.dupctx() {
            Ok(copy) => heap::alloc(copy).cast(),
            Err(_) => core::ptr::null_mut(),
        }
    }

    unsafe extern "C" fn init(dctx: *mut ffi::c_void, params: *const OSSL_PARAM) -> ffi::c_int {
        if dctx.is_null() {
            return 0;
        }
        // SAFETY: OpenSSL lends this live D exclusively for initialization.
        let ctx = unsafe { &mut *dctx.cast::<D>() };
        // SAFETY: the core supplies a null or END-terminated readable array,
        // whose keys and typed storage remain valid for this call.
        let params = unsafe { Params::from_ptr(params) };
        ffi::c_int::from(ctx.init(params).is_ok())
    }

    unsafe extern "C" fn update(
        dctx: *mut ffi::c_void,
        input: *const u8,
        len: usize,
    ) -> ffi::c_int {
        if dctx.is_null() || isize::try_from(len).is_err() || (input.is_null() && len != 0) {
            return 0;
        }
        // SAFETY: OpenSSL lends this live D exclusively during update.
        let ctx = unsafe { &mut *dctx.cast::<D>() };
        let input = if len == 0 {
            &[]
        } else {
            // SAFETY: the non-null input is readable for len bytes per the
            // callback contract; its length fits the Rust slice limit.
            unsafe { core::slice::from_raw_parts(input, len) }
        };
        ffi::c_int::from(ctx.update(input).is_ok())
    }

    unsafe extern "C" fn finalize(
        dctx: *mut ffi::c_void,
        out: *mut u8,
        outl: *mut usize,
        capacity: usize,
    ) -> ffi::c_int {
        if dctx.is_null()
            || outl.is_null()
            || isize::try_from(capacity).is_err()
            || (out.is_null() && capacity != 0)
        {
            return 0;
        }
        // SAFETY: OpenSSL lends this live D exclusively during finalization.
        let ctx = unsafe { &mut *dctx.cast::<D>() };

        let storage = if capacity == 0 {
            &mut []
        } else {
            // SAFETY: the core lends capacity writable bytes exclusively;
            // MaybeUninit permits their contents to be uninitialized.
            unsafe { core::slice::from_raw_parts_mut(out.cast::<MaybeUninit<u8>>(), capacity) }
        };

        let mut output = Output::new(storage);
        if ctx.finalize(&mut output).is_err() {
            return 0;
        }
        // SAFETY: outl is a valid output slot; Output tracks only initialized
        // bytes, bounded by the caller's capacity.
        unsafe { *outl = output.written() };
        1
    }

    unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> ffi::c_int {
        // SAFETY: the core lends a null or END-terminated array with writable
        // typed output storage and valid keys, exclusively for this call.
        let Some(mut params) = (unsafe { ParamsMut::from_ptr(params) }) else {
            return 1;
        };
        for descriptor in D::gettable_params().iter() {
            let Some(name) = descriptor.key() else { break };
            if let Some(mut param) = params.locate(name)
                && !D::get_param(name, &mut param)
            {
                return 0;
            }
        }
        1
    }

    unsafe extern "C" fn gettable_params(_provctx: *mut ffi::c_void) -> *const OSSL_PARAM {
        D::gettable_params().as_ptr()
    }

    unsafe extern "C" fn set_ctx_params(
        dctx: *mut ffi::c_void,
        params: *const OSSL_PARAM,
    ) -> ffi::c_int {
        if dctx.is_null() || !D::HAS_SET_CTX_PARAM {
            return 0;
        }
        // SAFETY: OpenSSL lends this live D exclusively during mutation.
        let ctx = unsafe { &mut *dctx.cast::<D>() };
        // SAFETY: the core supplies a null or END-terminated readable array,
        // with live keys and correctly typed data for this call.
        let params = unsafe { Params::from_ptr(params) };
        ffi::c_int::from(ctx.apply_ctx_params(params).is_ok())
    }

    unsafe extern "C" fn settable_ctx_params(
        _dctx: *mut ffi::c_void,
        _provctx: *mut ffi::c_void,
    ) -> *const OSSL_PARAM {
        D::settable_ctx_params().as_ptr()
    }

    unsafe extern "C" fn get_ctx_params(
        dctx: *mut ffi::c_void,
        params: *mut OSSL_PARAM,
    ) -> ffi::c_int {
        if dctx.is_null() || !D::HAS_GET_CTX_PARAM {
            return 0;
        }
        // SAFETY: the core lends a null or END-terminated array with writable
        // typed output storage and valid keys, exclusively for this call.
        let Some(mut params) = (unsafe { ParamsMut::from_ptr(params) }) else {
            return 1;
        };
        // SAFETY: OpenSSL lends a live D created by this table's allocator;
        // reading context parameters needs only shared access.
        let ctx = unsafe { &*dctx.cast::<D>() };
        for descriptor in D::gettable_ctx_params().iter() {
            let Some(name) = descriptor.key() else {
                break;
            };
            if let Some(mut param) = params.locate(name)
                && !ctx.get_ctx_param(name, &mut param)
            {
                return 0;
            }
        }
        1
    }

    unsafe extern "C" fn gettable_ctx_params(
        _dctx: *mut ffi::c_void,
        _provctx: *mut ffi::c_void,
    ) -> *const OSSL_PARAM {
        D::gettable_ctx_params().as_ptr()
    }
}
