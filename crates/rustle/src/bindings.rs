// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw FFI bindings to OpenSSL's provider core types.
//!
//! These mirror the C declarations from `<openssl/core.h>`, so the type names
//! follow their C originals rather than Rust casing conventions.

#![allow(non_camel_case_types)]

use core::ffi;
use core::marker::{PhantomData, PhantomPinned};

use crate::digest::DigestFunctions;
use crate::params::OSSL_PARAM;

/// Signature of `OSSL_FUNC_provider_teardown` — free the provider context.
pub type ProviderTeardownFn = unsafe extern "C" fn(provctx: *mut ffi::c_void);
/// Signature of `OSSL_FUNC_provider_gettable_params` — return the descriptor list.
pub type ProviderGettableParamsFn =
    unsafe extern "C" fn(provctx: *mut ffi::c_void) -> *const OSSL_PARAM;
/// Signature of `OSSL_FUNC_provider_get_params` — fill requested parameters.
pub type ProviderGetParamsFn =
    unsafe extern "C" fn(provctx: *mut ffi::c_void, params: *mut OSSL_PARAM) -> ffi::c_int;

/// Signature of `OSSL_FUNC_provider_query_operation` — return the algorithm
/// table for a given operation id, or `NULL` if unsupported.
pub type ProviderQueryOperationFn = unsafe extern "C" fn(
    provctx: *mut ffi::c_void,
    operation_id: ffi::c_int,
    no_cache: *mut ffi::c_int,
) -> *const OSSL_ALGORITHM;

// Digest operation functions (`OSSL_FUNC_digest_*_fn` in `<openssl/core_dispatch.h>`).

/// Signature of `OSSL_FUNC_digest_newctx` — allocate a fresh digest context.
pub type DigestNewctxFn = unsafe extern "C" fn(provctx: *mut ffi::c_void) -> *mut ffi::c_void;
/// Signature of `OSSL_FUNC_digest_freectx` — release a digest context.
pub type DigestFreectxFn = unsafe extern "C" fn(dctx: *mut ffi::c_void);
/// Signature of `OSSL_FUNC_digest_dupctx` — clone a digest context.
pub type DigestDupctxFn = unsafe extern "C" fn(dctx: *mut ffi::c_void) -> *mut ffi::c_void;
/// Signature of `OSSL_FUNC_digest_init` — (re)start a hash computation.
pub type DigestInitFn =
    unsafe extern "C" fn(dctx: *mut ffi::c_void, params: *const OSSL_PARAM) -> ffi::c_int;
/// Signature of `OSSL_FUNC_digest_update` — absorb `inl` bytes of input.
pub type DigestUpdateFn =
    unsafe extern "C" fn(dctx: *mut ffi::c_void, r#in: *const u8, inl: usize) -> ffi::c_int;
/// Signature of `OSSL_FUNC_digest_final` — write the digest into `out`.
pub type DigestFinalFn = unsafe extern "C" fn(
    dctx: *mut ffi::c_void,
    out: *mut u8,
    outl: *mut usize,
    outsz: usize,
) -> ffi::c_int;
/// Signature of `OSSL_FUNC_digest_get_params` — fill digest-wide parameters.
pub type DigestGetParamsFn = unsafe extern "C" fn(params: *mut OSSL_PARAM) -> ffi::c_int;
/// Signature of `OSSL_FUNC_digest_gettable_params` — return the descriptor list.
pub type DigestGettableParamsFn =
    unsafe extern "C" fn(provctx: *mut ffi::c_void) -> *const OSSL_PARAM;
/// Signature of `OSSL_FUNC_digest_set_ctx_params` — apply per-context
/// parameters (e.g. `xoflen`).
pub type DigestSetCtxParamsFn =
    unsafe extern "C" fn(dctx: *mut ffi::c_void, params: *const OSSL_PARAM) -> ffi::c_int;
/// Signature of `OSSL_FUNC_digest_settable_ctx_params` — return the descriptor
/// list [`DigestSetCtxParamsFn`] accepts.
pub type DigestSettableCtxParamsFn =
    unsafe extern "C" fn(dctx: *mut ffi::c_void, provctx: *mut ffi::c_void) -> *const OSSL_PARAM;
/// Signature of `OSSL_FUNC_digest_get_ctx_params` — read per-context
/// parameters back out of a live context.
pub type DigestGetCtxParamsFn =
    unsafe extern "C" fn(dctx: *mut ffi::c_void, params: *mut OSSL_PARAM) -> ffi::c_int;
/// Signature of `OSSL_FUNC_digest_gettable_ctx_params` — return the descriptor
/// list [`DigestGetCtxParamsFn`] can fill.
pub type DigestGettableCtxParamsFn =
    unsafe extern "C" fn(dctx: *mut ffi::c_void, provctx: *mut ffi::c_void) -> *const OSSL_PARAM;

/// Opaque handle to a provider instance, owned by the OpenSSL core.
///
/// Mirrors the C `OSSL_CORE_HANDLE` (`typedef struct ossl_core_handle_st
/// OSSL_CORE_HANDLE;`) — an incomplete type the provider only ever sees behind
/// a pointer and hands back on core upcalls. It is modelled as the canonical
/// opaque FFI type: zero-sized so it can never be dereferenced or copied,
/// impossible to construct outside this module (private fields), and `!Send` /
/// `!Sync` / `!Unpin` via the marker. A `*const OSSL_CORE_HANDLE` therefore
/// carries the correct aliasing and auto-trait semantics across the boundary
/// without pretending to be a real Rust value.
#[repr(C)]
pub struct OSSL_CORE_HANDLE {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// A single entry in a provider/core dispatch table.
///
/// Mirrors the C `OSSL_DISPATCH` (`struct ossl_dispatch_st { int function_id;
/// void (*function)(void); }`). Both the core and the provider expose their
/// callbacks as a **null-terminated array** of these: lookup is by
/// `function_id` (an `OSSL_FUNC_*` constant), and `function` is a type-erased
/// pointer the caller transmutes to the real signature that ID implies.
///
/// The terminator is an all-zero entry — `function_id == 0` and
/// `function == None` — which is why `function` is an [`Option`] of a function
/// pointer: `None` is the null pointer, and `Option<fn>` is guaranteed to share
/// the ABI of the bare pointer (null-pointer optimization).
///
/// Fields are private and typed callback constructors are crate-private.
/// Provider authors obtain opaque tables from
/// [`DigestAlgorithm::functions`](crate::digest::DigestAlgorithm::functions).
/// Individual generated callbacks stay inside `rustle`.
///
/// Neither field can be changed by external code:
///
/// ```compile_fail,E0616
/// use rustle::bindings::OSSL_DISPATCH;
/// let mut entry = OSSL_DISPATCH::END;
/// entry.function_id = OSSL_DISPATCH::OSSL_FUNC_DIGEST_UPDATE;
/// ```
///
/// ```compile_fail,E0616
/// use rustle::bindings::OSSL_DISPATCH;
/// let mut entry = OSSL_DISPATCH::END;
/// entry.function = None;
/// ```
///
/// A struct literal cannot bypass the constructors:
///
/// ```compile_fail,E0451
/// use rustle::bindings::OSSL_DISPATCH;
/// let entry = OSSL_DISPATCH { function_id: 3, function: None };
/// ```
///
/// Even a callback with the correct signature must be wired inside `rustle`:
///
/// ```compile_fail,E0624
/// use core::ffi::{c_int, c_void};
/// use rustle::bindings::OSSL_DISPATCH;
/// extern "C" fn update(_: *mut c_void, _: *const u8, _: usize) -> c_int { 1 }
/// let entry = OSSL_DISPATCH::digest_update(update);
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OSSL_DISPATCH {
    /// The `OSSL_FUNC_*` identifier selecting which callback this is.
    function_id: ffi::c_int,
    /// Type-erased callback pointer; transmute to the signature `function_id`
    /// implies before calling. `None` marks the end-of-table terminator.
    function: Option<unsafe extern "C" fn()>,
}

impl OSSL_DISPATCH {
    // Base functions a provider returns to the core in its `out` table
    // (`OSSL_FUNC_PROVIDER_*`, reserved IDs 1024-1535 in `<openssl/core_dispatch.h>`).
    /// Free the provider context; called when the provider is unloaded.
    pub const OSSL_FUNC_PROVIDER_TEARDOWN: ffi::c_int = 1024;
    /// Return the `OSSL_PARAM` descriptor list that [`get_params`] can fill.
    ///
    /// [`get_params`]: Self::OSSL_FUNC_PROVIDER_GET_PARAMS
    pub const OSSL_FUNC_PROVIDER_GETTABLE_PARAMS: ffi::c_int = 1025;
    /// Populate requested provider parameters (name, version, buildinfo, status).
    pub const OSSL_FUNC_PROVIDER_GET_PARAMS: ffi::c_int = 1026;
    /// Return the `OSSL_ALGORITHM` array implementing a given operation id.
    pub const OSSL_FUNC_PROVIDER_QUERY_OPERATION: ffi::c_int = 1027;
    /// Release whatever [`query_operation`] returned.
    ///
    /// [`query_operation`]: Self::OSSL_FUNC_PROVIDER_QUERY_OPERATION
    pub const OSSL_FUNC_PROVIDER_UNQUERY_OPERATION: ffi::c_int = 1028;
    /// Return the provider's error reason-string table (`OSSL_ITEM` array).
    pub const OSSL_FUNC_PROVIDER_GET_REASON_STRINGS: ffi::c_int = 1029;
    /// Enumerate a named capability (e.g. TLS groups) through a callback.
    pub const OSSL_FUNC_PROVIDER_GET_CAPABILITIES: ffi::c_int = 1030;
    /// Run the provider's on-demand self-tests (KATs).
    pub const OSSL_FUNC_PROVIDER_SELF_TEST: ffi::c_int = 1031;
    /// Supply random bytes to the core (used as a seed source).
    pub const OSSL_FUNC_PROVIDER_RANDOM_BYTES: ffi::c_int = 1032;

    // Digest operation functions (`OSSL_FUNC_DIGEST_*`, IDs 1-15 in
    // `<openssl/core_dispatch.h>`

    /// Allocate a new digest context.
    pub const OSSL_FUNC_DIGEST_NEWCTX: ffi::c_int = 1;
    /// (Re)initialize a digest context.
    pub const OSSL_FUNC_DIGEST_INIT: ffi::c_int = 2;
    /// Feed input bytes into the hash state.
    pub const OSSL_FUNC_DIGEST_UPDATE: ffi::c_int = 3;
    /// Finalize and produce the digest value.
    pub const OSSL_FUNC_DIGEST_FINAL: ffi::c_int = 4;
    /// Free a digest context.
    pub const OSSL_FUNC_DIGEST_FREECTX: ffi::c_int = 6;
    /// Duplicate a digest context (mid-hash state included).
    pub const OSSL_FUNC_DIGEST_DUPCTX: ffi::c_int = 7;
    /// Fill digest-wide parameters (`size`, `blocksize`).
    pub const OSSL_FUNC_DIGEST_GET_PARAMS: ffi::c_int = 8;
    /// Apply per-context parameters (e.g. `xoflen` for XOF digests).
    pub const OSSL_FUNC_DIGEST_SET_CTX_PARAMS: ffi::c_int = 9;
    /// Read per-context parameters back out of a live context.
    pub const OSSL_FUNC_DIGEST_GET_CTX_PARAMS: ffi::c_int = 10;
    /// Return the descriptor list [`get_params`] can fill.
    ///
    /// [`get_params`]: Self::OSSL_FUNC_DIGEST_GET_PARAMS
    pub const OSSL_FUNC_DIGEST_GETTABLE_PARAMS: ffi::c_int = 11;
    /// Return the descriptor list [`set_ctx_params`] accepts.
    ///
    /// [`set_ctx_params`]: Self::OSSL_FUNC_DIGEST_SET_CTX_PARAMS
    pub const OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS: ffi::c_int = 12;
    /// Return the descriptor list [`get_ctx_params`] can fill.
    ///
    /// [`get_ctx_params`]: Self::OSSL_FUNC_DIGEST_GET_CTX_PARAMS
    pub const OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS: ffi::c_int = 13;

    // Operation IDs used by query_operation (core_dispatch.h).

    /// Digest operations (SHA, MD, etc.).
    pub const OSSL_OP_DIGEST: ffi::c_int = 1;

    /// The all-zero terminator that marks the end of a dispatch array.
    pub const END: Self = Self {
        function_id: 0,
        function: None,
    };

    /// Returns `true` if this is the end-of-table terminator (`function_id`
    /// of zero), i.e. iteration over the array should stop here.
    #[must_use]
    pub const fn is_end(&self) -> bool {
        self.function_id == Self::END.function_id
    }

    /// Type-erases a correctly-typed provider function into the dispatch slot.
    ///
    /// The single home of the `void (*)(void)` transmute: each crate-private
    /// constructor below feeds it the exact `OSSL_FUNC_*_fn` signature for its
    /// `function_id`, so callers build tables with no `unsafe` and no risk of
    /// pairing an ID with the wrong signature.
    const fn erase(function_id: ffi::c_int, function: *const ()) -> Self {
        Self {
            function_id,
            // SAFETY: `function` is a live function pointer (from a typed
            // constructor); a `*const ()` and `fn()` share representation, and
            // the core casts it back to the signature `function_id` implies.
            function: Some(unsafe {
                core::mem::transmute::<*const (), unsafe extern "C" fn()>(function)
            }),
        }
    }

    /// Builds the `OSSL_FUNC_PROVIDER_TEARDOWN` entry.
    #[must_use]
    pub(crate) const fn provider_teardown(f: ProviderTeardownFn) -> Self {
        Self::erase(Self::OSSL_FUNC_PROVIDER_TEARDOWN, f as *const ())
    }

    /// Builds the `OSSL_FUNC_PROVIDER_GETTABLE_PARAMS` entry.
    #[must_use]
    pub(crate) const fn provider_gettable_params(f: ProviderGettableParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, f as *const ())
    }

    /// Builds the `OSSL_FUNC_PROVIDER_GET_PARAMS` entry.
    #[must_use]
    pub(crate) const fn provider_get_params(f: ProviderGetParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_PROVIDER_GET_PARAMS, f as *const ())
    }

    /// Builds the `OSSL_FUNC_PROVIDER_QUERY_OPERATION` entry.
    #[must_use]
    pub(crate) const fn provider_query_operation(f: ProviderQueryOperationFn) -> Self {
        Self::erase(Self::OSSL_FUNC_PROVIDER_QUERY_OPERATION, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_NEWCTX` entry.
    #[must_use]
    pub(crate) const fn digest_newctx(f: DigestNewctxFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_NEWCTX, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_FREECTX` entry.
    #[must_use]
    pub(crate) const fn digest_freectx(f: DigestFreectxFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_FREECTX, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_DUPCTX` entry.
    #[must_use]
    pub(crate) const fn digest_dupctx(f: DigestDupctxFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_DUPCTX, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_INIT` entry.
    #[must_use]
    pub(crate) const fn digest_init(f: DigestInitFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_INIT, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_UPDATE` entry.
    #[must_use]
    pub(crate) const fn digest_update(f: DigestUpdateFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_UPDATE, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_FINAL` entry.
    #[must_use]
    pub(crate) const fn digest_final(f: DigestFinalFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_FINAL, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_GET_PARAMS` entry.
    #[must_use]
    pub(crate) const fn digest_get_params(f: DigestGetParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_GET_PARAMS, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_GETTABLE_PARAMS` entry.
    #[must_use]
    pub(crate) const fn digest_gettable_params(f: DigestGettableParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_GETTABLE_PARAMS, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_SET_CTX_PARAMS` entry.
    #[must_use]
    pub(crate) const fn digest_set_ctx_params(f: DigestSetCtxParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_SET_CTX_PARAMS, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS` entry.
    #[must_use]
    pub(crate) const fn digest_settable_ctx_params(f: DigestSettableCtxParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_GET_CTX_PARAMS` entry.
    #[must_use]
    pub(crate) const fn digest_get_ctx_params(f: DigestGetCtxParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_GET_CTX_PARAMS, f as *const ())
    }

    /// Builds the `OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS` entry.
    #[must_use]
    pub(crate) const fn digest_gettable_ctx_params(f: DigestGettableCtxParamsFn) -> Self {
        Self::erase(Self::OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, f as *const ())
    }
}

/// A single algorithm entry returned by `query_operation`.
///
/// Mirrors the C `OSSL_ALGORITHM` (`struct ossl_algorithm_st`): an algorithm
/// name (colon-separated aliases), an optional property set, the function table
/// implementing the algorithm, and an optional human-readable description.
///
/// All fields are private so safe code cannot fabricate an entry with bogus
/// pointers: tables are built only from [`new`](Self::new) (which demands
/// `'static` C strings and an opaque [`DigestFunctions`] table) plus the
/// [`END`](Self::END) terminator — both safe, `const`-evaluable constructors.
#[repr(C)]
pub struct OSSL_ALGORITHM {
    /// Colon-separated algorithm name(s), e.g. `"SHA2-256:SHA-256"`.
    names: *const ffi::c_char,
    /// Property set string (or `NULL` if none).
    properties: *const ffi::c_char,
    /// The `OSSL_DISPATCH` table implementing this algorithm.
    functions: *const OSSL_DISPATCH,
    /// Optional human-readable description (or `NULL`).
    description: *const ffi::c_char,
}

impl OSSL_ALGORITHM {
    /// The all-null terminator that marks the end of an algorithm table.
    pub const END: Self = Self {
        names: core::ptr::null(),
        properties: core::ptr::null(),
        functions: core::ptr::null(),
        description: core::ptr::null(),
    };

    /// Builds a digest algorithm entry from static metadata and a complete
    /// dispatch table generated by `rustle`.
    ///
    /// [`DigestAlgorithm::functions`](crate::digest::DigestAlgorithm::functions)
    /// supplies an END-terminated table whose callbacks all use the same
    /// context type. An arbitrary dispatch slice is not accepted:
    ///
    /// ```compile_fail,E0308
    /// use rustle::bindings::{OSSL_ALGORITHM, OSSL_DISPATCH};
    /// let algorithm = OSSL_ALGORITHM::new(
    ///     c"hash", c"provider=example", &[OSSL_DISPATCH::END], c"Example hash",
    /// );
    /// ```
    #[must_use]
    pub const fn new(
        names: &'static ffi::CStr,
        properties: &'static ffi::CStr,
        functions: DigestFunctions,
        description: &'static ffi::CStr,
    ) -> Self {
        Self {
            names: names.as_ptr(),
            properties: properties.as_ptr(),
            functions: functions.as_ptr(),
            description: description.as_ptr(),
        }
    }

    /// Returns `true` for the end-of-table terminator (null `names`).
    #[must_use]
    pub const fn is_end(&self) -> bool {
        self.names.is_null()
    }
}

// SAFETY: the wrapped arrays are immutable descriptor tables — all raw pointers
// are `'static` C-string keys and dispatch table pointers, never written
// through.
unsafe impl Sync for OSSL_ALGORITHM {}

/// Walks a raw, `END`-terminated [`OSSL_DISPATCH`] array.
///
/// Implemented for `*const OSSL_DISPATCH` so the `in` table a provider receives
/// can be consumed as `unsafe { ptr.iter() }`, confining the pointer arithmetic
/// to [`Dispatch`].
pub trait DispatchExt {
    /// Borrows the array as an iterator over its entries, stopping before the
    /// [`END`](OSSL_DISPATCH::END) terminator.
    ///
    /// # Safety
    /// `self` must be non-null and point to a valid, `END`-terminated
    /// `OSSL_DISPATCH` array that stays alive for `'a`.
    unsafe fn iter<'a>(self) -> Dispatch<'a>;
}

impl DispatchExt for *const OSSL_DISPATCH {
    unsafe fn iter<'a>(self) -> Dispatch<'a> {
        Dispatch {
            next: self,
            _marker: PhantomData,
        }
    }
}

/// Iterator over an `END`-terminated [`OSSL_DISPATCH`] array; see
/// [`DispatchExt::iter`].
pub struct Dispatch<'a> {
    next: *const OSSL_DISPATCH,
    _marker: PhantomData<&'a OSSL_DISPATCH>,
}

impl<'a> Iterator for Dispatch<'a> {
    type Item = &'a OSSL_DISPATCH;

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: `iter`'s contract guarantees `next` points to a valid entry
        // of the array (the terminator inclusive), so the borrow is in bounds.
        let cur = unsafe { &*self.next };
        if cur.is_end() {
            return None;
        }
        // SAFETY: `cur` is not the terminator, so the following element is still
        // within the same array.
        self.next = unsafe { self.next.add(1) };
        Some(cur)
    }
}
