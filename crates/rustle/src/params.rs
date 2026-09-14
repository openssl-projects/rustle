// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenSSL parameter descriptors and borrowed input/output views.
//!
//! [`ParamTable`] validates static descriptors. FFI callbacks construct
//! [`Params`] and [`ParamsMut`]; writable cells use [`ParamMut`] to retain
//! the borrow of the core's buffers.

#![allow(non_camel_case_types)]

use core::ffi;
use core::marker::PhantomData;

/// The C `OSSL_PARAM` layout, used for descriptors and transfer cells.
///
/// Build descriptors with [`defn`](Self::defn). Live cells arrive through FFI;
/// they cannot be copied, and mutable access stays behind [`ParamMut`].
#[repr(C)]
pub struct OSSL_PARAM {
    /// Parameter name, e.g. `c"name"`. Null only in the [`END`](Self::END)
    /// terminator.
    key: *const ffi::c_char,
    /// What `data` points at: one of the `OSSL_PARAM_*` kind constants.
    data_type: ffi::c_uint,
    /// Type-erased pointer to the value; null in a pure descriptor entry.
    data: *mut ffi::c_void,
    /// Size in bytes of the `data` buffer.
    data_size: usize,
    /// Set by the callee to the number of bytes it produced/needs.
    return_size: usize,
}

impl OSSL_PARAM {
    /// Signed integer (`OSSL_PARAM_INTEGER`).
    pub const INTEGER: ffi::c_uint = 1;
    /// Unsigned integer (`OSSL_PARAM_UNSIGNED_INTEGER`).
    pub const UNSIGNED_INTEGER: ffi::c_uint = 2;
    /// IEEE floating point (`OSSL_PARAM_REAL`).
    pub const REAL: ffi::c_uint = 3;
    /// Inline UTF-8 string, `data` is the bytes (`OSSL_PARAM_UTF8_STRING`).
    pub const UTF8_STRING: ffi::c_uint = 4;
    /// Inline byte string (`OSSL_PARAM_OCTET_STRING`).
    pub const OCTET_STRING: ffi::c_uint = 5;
    /// Pointer to a UTF-8 string; `data` is a `*const c_char` slot
    /// (`OSSL_PARAM_UTF8_PTR`).
    pub const UTF8_PTR: ffi::c_uint = 6;
    /// Pointer to a byte string (`OSSL_PARAM_OCTET_PTR`).
    pub const OCTET_PTR: ffi::c_uint = 7;

    /// The all-zero terminator ending an `OSSL_PARAM` array (`OSSL_PARAM_END`).
    pub const END: Self = Self {
        key: core::ptr::null(),
        data_type: 0,
        data: core::ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    };

    /// Creates a descriptor with a static name, a type, and no data buffer.
    ///
    /// The name must outlive the descriptor, which stores only its pointer.
    ///
    /// ```compile_fail,E0597
    /// use rustle::params::OSSL_PARAM;
    /// let descriptor = {
    ///     let key = std::ffi::CString::new("size").unwrap();
    ///     OSSL_PARAM::defn(&key, OSSL_PARAM::UNSIGNED_INTEGER)
    /// };
    /// ```
    #[must_use]
    pub const fn defn(key: &'static ffi::CStr, data_type: ffi::c_uint) -> Self {
        Self {
            key: key.as_ptr(),
            data_type,
            data: core::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        }
    }

    /// Builds a live cell over caller-owned storage.
    ///
    /// Test-only: real cells always arrive from the OpenSSL core, so the
    /// adapters can be driven without one.
    #[cfg(test)]
    pub(crate) const fn cell(
        key: &'static ffi::CStr,
        data_type: ffi::c_uint,
        data: *mut ffi::c_void,
        data_size: usize,
    ) -> Self {
        Self {
            key: key.as_ptr(),
            data_type,
            data,
            data_size,
            return_size: 0,
        }
    }

    /// Returns `true` for the end-of-array terminator (null `key`).
    const fn is_end(&self) -> bool {
        self.key.is_null()
    }

    /// This parameter's name, or `None` for the terminator.
    #[must_use]
    pub fn key(&self) -> Option<&ffi::CStr> {
        if self.is_end() {
            return None;
        }
        // SAFETY: the key is static from defn or valid for the core's borrow.
        Some(unsafe { ffi::CStr::from_ptr(self.key) })
    }

    /// Whether this cell carries a signed integer (`INTEGER`).
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.data_type == Self::INTEGER
    }

    /// Whether this cell carries an inline UTF-8 string (`UTF8_STRING`).
    #[must_use]
    pub fn is_utf8_string(&self) -> bool {
        self.data_type == Self::UTF8_STRING
    }

    /// Whether this cell carries an inline byte string (`OCTET_STRING`).
    #[must_use]
    pub fn is_octet_string(&self) -> bool {
        self.data_type == Self::OCTET_STRING
    }

    /// Reads an exact-width `INTEGER` as a C `int`.
    ///
    /// Returns `None` for a type or size mismatch, or null data.
    #[must_use]
    pub fn get_int(&self) -> Option<ffi::c_int> {
        if self.data_type != Self::INTEGER
            || self.data.is_null()
            || self.data_size != size_of::<ffi::c_int>()
        {
            return None;
        }
        // SAFETY: type, non-null, and exact size checked above; `data` is a
        // valid readable `c_int` per the view's contract.
        Some(unsafe { *(self.data as *const ffi::c_int) })
    }

    /// Reads an exact-width `UNSIGNED_INTEGER` as a `size_t`.
    ///
    /// Returns `None` for a type or size mismatch, or null data.
    #[must_use]
    pub fn get_size_t(&self) -> Option<usize> {
        if self.data_type != Self::UNSIGNED_INTEGER
            || self.data.is_null()
            || self.data_size != size_of::<usize>()
        {
            return None;
        }
        // SAFETY: type, non-null, and exact size checked above; `data` is a
        // valid readable `size_t` per the view's contract.
        Some(unsafe { *(self.data as *const usize) })
    }

    /// Borrows a `UTF8_STRING`, stripping one trailing NUL.
    ///
    /// Returns `None` for a type mismatch, null data, or invalid UTF-8.
    #[must_use]
    pub fn get_utf8_string(&self) -> Option<&str> {
        if self.data_type != Self::UTF8_STRING || self.data.is_null() {
            return None;
        }
        // SAFETY: `data_type == UTF8_STRING` with non-null `data` means the
        // core handed us `data_size` readable bytes at `data`, valid for the
        // borrow (tied to `&self`, hence to the owning view's lifetime).
        let mut bytes =
            unsafe { core::slice::from_raw_parts(self.data.cast::<u8>(), self.data_size) };
        if let [head @ .., 0] = bytes {
            bytes = head;
        }
        core::str::from_utf8(bytes).ok()
    }

    /// Borrows an `OCTET_STRING`, including an empty one.
    ///
    /// Returns `None` for a type mismatch or null data.
    #[must_use]
    pub fn get_octet_string(&self) -> Option<&[u8]> {
        if self.data_type != Self::OCTET_STRING || self.data.is_null() {
            return None;
        }
        // SAFETY: `data_type == OCTET_STRING` with non-null `data` means the
        // core handed us `data_size` readable bytes at `data`, valid for the
        // borrow (tied to `&self`, hence to the owning view's lifetime).
        Some(unsafe { core::slice::from_raw_parts(self.data.cast::<u8>(), self.data_size) })
    }
}

/// A borrowed writable parameter cell supplied by the OpenSSL core.
///
/// Returned by [`ParamsMut::locate`]. Its private reference prevents extracting
/// the raw cell; moving the wrapper retains the borrow of the core's buffers.
pub struct ParamMut<'a> {
    raw: &'a mut OSSL_PARAM,
}

impl ParamMut<'_> {
    /// This parameter's name.
    #[must_use]
    pub fn key(&self) -> Option<&ffi::CStr> {
        self.raw.key()
    }

    /// Whether this cell carries a signed integer.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.raw.is_integer()
    }

    /// Whether this cell carries an inline UTF-8 string.
    #[must_use]
    pub fn is_utf8_string(&self) -> bool {
        self.raw.is_utf8_string()
    }

    /// Whether this cell carries an inline byte string.
    #[must_use]
    pub fn is_octet_string(&self) -> bool {
        self.raw.is_octet_string()
    }

    /// Stores a static string pointer in a `UTF8_PTR` cell.
    ///
    /// Reports the byte length without NUL. Null data is a size query;
    /// a type mismatch returns `false`.
    pub fn set_utf8_ptr(&mut self, val: &'static ffi::CStr) -> bool {
        self.raw.return_size = 0;

        if self.raw.data_type != OSSL_PARAM::UTF8_PTR {
            return false;
        }

        self.raw.return_size = val.count_bytes();
        if self.raw.data.is_null() {
            return true;
        }
        // SAFETY: `data_type == UTF8_PTR` means `data` is a `*const c_char`
        // slot; it is non-null (checked) and valid per the `ParamsMut` contract.
        unsafe { *(self.raw.data as *mut *const ffi::c_char) = val.as_ptr() };
        true
    }

    fn set_string_internal(&mut self, val: &str, data_type: ffi::c_uint) -> bool {
        if self.raw.data_type != data_type {
            return false;
        }

        self.raw.return_size = val.len();
        if self.raw.data.is_null() {
            return true;
        }

        let needed = val.len();
        if self.raw.data_size < needed {
            return false;
        }

        // SAFETY: the buffer has at least val.len() writable bytes.
        let dst = unsafe { core::slice::from_raw_parts_mut(self.raw.data.cast::<u8>(), needed) };
        dst.copy_from_slice(val.as_bytes());
        if data_type == OSSL_PARAM::UTF8_STRING && self.raw.data_size > needed {
            // SAFETY: the capacity check leaves a writable byte after the text.
            unsafe {
                self.raw.data.cast::<u8>().add(val.len()).write(0);
            }
        }
        true
    }

    /// Copies into a `UTF8_STRING` cell, adding NUL when capacity allows.
    ///
    /// Reports the length without NUL. Null data is a size query; a type
    /// mismatch or insufficient capacity returns `false`.
    pub fn set_utf8_string(&mut self, val: &str) -> bool {
        self.raw.return_size = 0;

        self.set_string_internal(val, OSSL_PARAM::UTF8_STRING)
    }

    /// Writes a C `int` to an `INTEGER` cell and reports its byte size.
    ///
    /// Null data is a size query. Non-null data must have exactly the native
    /// width; a type or size mismatch returns `false` without writing.
    pub fn set_int(&mut self, val: ffi::c_int) -> bool {
        self.raw.return_size = 0;

        if self.raw.data_type != OSSL_PARAM::INTEGER {
            return false;
        }

        self.raw.return_size = size_of::<ffi::c_int>();
        if self.raw.data.is_null() {
            return true;
        }
        if self.raw.data_size != size_of::<ffi::c_int>() {
            return false;
        }
        // SAFETY: type, non-null, and exact size checked above; `data` is a
        // valid writable `c_int` per the `ParamsMut` contract.
        unsafe { *(self.raw.data as *mut ffi::c_int) = val };
        true
    }

    /// Writes a `size_t` to an `UNSIGNED_INTEGER` cell and reports its byte size.
    ///
    /// Null data is a size query. Non-null data must have exactly the native
    /// width; a type or size mismatch returns `false` without writing.
    pub fn set_size_t(&mut self, val: usize) -> bool {
        self.raw.return_size = 0;

        if self.raw.data_type != OSSL_PARAM::UNSIGNED_INTEGER {
            return false;
        }

        self.raw.return_size = size_of::<usize>();
        if self.raw.data.is_null() {
            return true;
        }
        if self.raw.data_size != size_of::<usize>() {
            return false;
        }

        // SAFETY: type, non-null, and exact size checked above; `data` is a
        // valid writable `size_t` per the `ParamsMut` contract.
        unsafe { *(self.raw.data as *mut usize) = val };
        true
    }
}

/// A writable view of a core-supplied, END-terminated parameter array.
///
/// Constructed inside `rustle`; [`locate`](Self::locate) returns borrowed cells.
pub struct ParamsMut<'a> {
    ptr: *mut OSSL_PARAM,
    _marker: PhantomData<&'a mut OSSL_PARAM>,
}

impl<'a> ParamsMut<'a> {
    /// Wraps the raw `params` pointer the core passes to a `get_params` call.
    ///
    /// # Safety
    /// `params` must be null or point to an initialized, aligned,
    /// `END`-terminated `OSSL_PARAM` array that stays valid and exclusively
    /// borrowed for `'a`. Each non-terminator key must point to a valid C
    /// string that stays alive and unchanged for `'a`. Non-null data pointers
    /// must reference writable storage, sized and aligned for their declared
    /// type and `data_size` (including a pointer slot for pointer types).
    /// That storage must stay valid for `'a` and
    /// must not be accessed through aliases while borrowed through this view.
    #[must_use]
    pub(crate) unsafe fn from_ptr(params: *mut OSSL_PARAM) -> Option<ParamsMut<'a>> {
        if params.is_null() {
            return None;
        }

        Some(Self {
            ptr: params,
            _marker: PhantomData,
        })
    }

    /// Finds the entry named `key`, the analogue of `OSSL_PARAM_locate`.
    /// Returns the first matching cell, borrowed for the duration of this
    /// view's mutable borrow, or `None` if there is no match.
    pub fn locate(&mut self, key: &ffi::CStr) -> Option<ParamMut<'_>> {
        let mut p = self.ptr;
        loop {
            // SAFETY: `from_ptr`'s contract guarantees `p` walks a valid,
            // `END`-terminated array; we stop before stepping past the end.
            let entry = unsafe { &mut *p };
            if entry.is_end() {
                return None;
            }
            // SAFETY: a non-terminator entry has a valid C-string `key`.
            if unsafe { ffi::CStr::from_ptr(entry.key) } == key {
                return Some(ParamMut { raw: entry });
            }
            // SAFETY: `entry` was not the terminator, so the next element is
            // still within the array.
            p = unsafe { p.add(1) };
        }
    }
}

/// A read-only view of a core-supplied, END-terminated parameter array.
///
/// Constructed only inside `rustle`:
///
/// ```compile_fail,E0624
/// use rustle::params::{OSSL_PARAM, Params};
/// let params = [OSSL_PARAM::END];
/// let _view = unsafe { Params::from_ptr(params.as_ptr()) };
/// ```
pub struct Params<'a> {
    ptr: *const OSSL_PARAM,
    _marker: PhantomData<&'a OSSL_PARAM>,
}

impl<'a> Params<'a> {
    /// Wraps the raw `params` pointer the core passes to a `set_ctx_params`
    /// (or `init`) call.
    ///
    /// # Safety
    /// `params` must be null or point to an initialized, aligned,
    /// `END`-terminated `OSSL_PARAM` array that stays alive and unchanged for
    /// `'a`. Each non-terminator key must point to a valid C string that
    /// stays alive and unchanged for `'a`. Non-null data pointers must
    /// reference initialized, readable storage, sized and aligned for their
    /// declared type and `data_size`. That storage must stay alive and must
    /// not be mutated for `'a`.
    #[must_use]
    pub(crate) unsafe fn from_ptr(params: *const OSSL_PARAM) -> Option<Self> {
        if params.is_null() {
            return None;
        }

        Some(Self {
            ptr: params,
            _marker: PhantomData,
        })
    }

    /// Finds the entry named `key`, the analogue of `OSSL_PARAM_locate_const`.
    /// Returns `None` if the array has no such entry.
    pub fn locate(&self, key: &ffi::CStr) -> Option<&'a OSSL_PARAM> {
        self.iter().find(|entry| entry.key() == Some(key))
    }

    /// Iterates over entries before the first END terminator.
    pub fn iter(&self) -> ParamsIter<'a> {
        ParamsIter {
            ptr: self.ptr,
            _marker: PhantomData,
        }
    }
}

/// Iterator over a core-supplied `OSSL_PARAM` array (see [`Params::iter`]).
pub struct ParamsIter<'a> {
    ptr: *const OSSL_PARAM,
    _marker: PhantomData<&'a OSSL_PARAM>,
}

impl<'a> Iterator for ParamsIter<'a> {
    type Item = &'a OSSL_PARAM;

    fn next(&mut self) -> Option<&'a OSSL_PARAM> {
        // SAFETY: `Params::from_ptr`'s contract guarantees `ptr` walks a
        // valid, `END`-terminated array; we stop at the terminator and never
        // step past it.
        let entry = unsafe { &*self.ptr };
        if entry.is_end() {
            return None;
        }
        // SAFETY: `entry` was not the terminator, so the next element is
        // still within the array.
        self.ptr = unsafe { self.ptr.add(1) };
        Some(entry)
    }
}

/// Descriptor storage that can be declared as a `static`.
///
/// Supplies `Sync` for immutable descriptors; [`ParamTable`] checks termination.
#[repr(transparent)]
pub struct ParamArray<const N: usize>(pub [OSSL_PARAM; N]);

// SAFETY: the wrapped arrays are immutable descriptor tables — the raw pointers
// are `'static` C-string keys with null data, never written through.
unsafe impl<const N: usize> Sync for ParamArray<N> {}

/// A static, END-terminated parameter descriptor table.
///
/// The private slice can only be constructed through [`new`](Self::new).
///
/// ```
/// use rustle::params::{OSSL_PARAM, ParamArray, ParamTable};
/// static RAW: ParamArray<2> = ParamArray([
///     OSSL_PARAM::defn(c"size", OSSL_PARAM::UNSIGNED_INTEGER),
///     OSSL_PARAM::END,
/// ]);
/// const TABLE: Option<ParamTable> = ParamTable::new(&RAW.0);
/// assert!(TABLE.is_some());
/// assert!(ParamTable::new(&[]).is_none());
/// ```
///
/// Tables cannot be constructed without validation:
///
/// ```compile_fail,E0451
/// use rustle::params::ParamTable;
/// let table = ParamTable { entries: &[] };
/// ```
#[derive(Clone, Copy)]
pub struct ParamTable {
    entries: &'static [OSSL_PARAM],
}

impl ParamTable {
    /// Validates a descriptor table, rejecting empty slices and tables whose
    /// final entry is not END. An empty descriptor table contains only END.
    /// Earlier END entries retain their usual meaning: consumers stop there.
    #[must_use]
    pub const fn new(entries: &'static [OSSL_PARAM]) -> Option<Self> {
        match entries.last() {
            Some(last) if last.is_end() => Some(Self { entries }),
            _ => None,
        }
    }

    /// The validated array for the C ABI, including its END terminator.
    pub(crate) fn as_ptr(&self) -> *const OSSL_PARAM {
        self.entries.as_ptr()
    }

    /// Iterates over the backing array; callers stop at the first END entry.
    pub(crate) fn iter(&self) -> core::slice::Iter<'_, OSSL_PARAM> {
        self.entries.iter()
    }
}

/// Builds a static [`ParamTable`] from a `name: type` list, appending END.
///
/// Types are unqualified [`OSSL_PARAM`] constants. Storage is shared across
/// generic instantiations; termination is validated at compile time.
///
/// ```
/// use rustle::params::ParamTable;
///
/// fn settable_ctx_params() -> ParamTable {
///     rustle::param_table! {
///         c"key":  OCTET_STRING,
///         c"salt": OCTET_STRING,
///     }
/// }
/// let table = settable_ctx_params();
/// ```
#[macro_export]
macro_rules! param_table {
    // Internal: collapse one entry to `()` so the list can be counted.
    (@unit $_name:literal) => { () };

    ($($name:literal : $ty:ident),* $(,)?) => {{
        // Counted from the entry list, so the length can never drift out of
        // sync with it. `+ 1` is the `END` terminator.
        const LEN: usize = <[()]>::len(&[$($crate::param_table!(@unit $name)),*]) + 1;
        static RAW: $crate::params::ParamArray<LEN> = $crate::params::ParamArray([
            $($crate::params::OSSL_PARAM::defn($name, $crate::params::OSSL_PARAM::$ty),)*
            $crate::params::OSSL_PARAM::END,
        ]);
        const TABLE: $crate::params::ParamTable =
            match $crate::params::ParamTable::new(&RAW.0) {
                Some(table) => table,
                None => panic!("descriptor table must be OSSL_PARAM::END-terminated"),
            };
        TABLE
    }};
}

/// Implements [`Digest`](crate::digest::Digest)'s descriptor table and getter.
///
/// Each entry binds `p` to `&mut ParamMut<'_>` and returns `bool`. `Self` is
/// available in the expression. Unlisted names return `false`.
///
/// ```
/// use rustle::digest::{Digest, Output, Result};
/// use rustle::params::Params;
///
/// struct MyHash([u8; 32]);
///
/// #[rustle::vtable]
/// impl Digest for MyHash {
///     fn newctx() -> Result<Self> { Ok(Self([0; 32])) }
///     fn init(&mut self, _: Option<Params<'_>>) -> Result {
///         self.0 = [0; 32];
///         Ok(())
///     }
///
///     rustle::gettable_params! {
///         c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(64),
///         c"size":      UNSIGNED_INTEGER => |p| p.set_size_t(32),
///     }
///
///     fn update(&mut self, _data: &[u8]) -> Result { Ok(()) }
///     fn finalize(&mut self, out: &mut Output<'_>) -> Result { out.write(&self.0) }
/// }
/// ```
#[macro_export]
macro_rules! gettable_params {
    (@vtable $($entries:tt)*) => {
        const HAS_GETTABLE_PARAMS: bool = true;
        const HAS_GET_PARAM: bool = true;
        $crate::gettable_params! { $($entries)* }
    };
    ($($name:literal : $ty:ident => |$p:ident| $fill:expr),* $(,)?) => {
        fn gettable_params() -> $crate::params::ParamTable {
            $crate::param_table! { $($name : $ty),* }
        }

        fn get_param(
            name: &::core::ffi::CStr,
            param: &mut $crate::params::ParamMut<'_>,
        ) -> bool {
            $(
                if name == $name {
                    let $p = &mut *param;
                    return $fill;
                }
            )*
            false
        }
    };
}

/// Implements [`Digest`](crate::digest::Digest)'s context table and setter.
///
/// Each entry binds `this` to `&mut Self` and `p` to `&OSSL_PARAM`, returning
/// `bool`. Unlisted names return `false`.
///
/// ```
/// use rustle::digest::{Digest, Output, Result};
/// use rustle::params::Params;
///
/// struct MyHash {
///     rounds: usize,
/// }
///
/// #[rustle::vtable]
/// impl Digest for MyHash {
///     fn newctx() -> Result<Self> { Ok(Self { rounds: 1 }) }
///     fn init(&mut self, params: Option<Params<'_>>) -> Result {
///         self.rounds = 1;
///         self.apply_ctx_params(params)
///     }
///
///     rustle::gettable_params! {
///         c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(64),
///         c"size":      UNSIGNED_INTEGER => |p| p.set_size_t(32),
///     }
///
///     rustle::settable_ctx_params! {
///         c"rounds": UNSIGNED_INTEGER => |this, p| match p.get_size_t() {
///             Some(n) => {
///                 this.rounds = n;
///                 true
///             }
///             None => false,
///         },
///     }
///
///     fn update(&mut self, _data: &[u8]) -> Result { Ok(()) }
///     fn finalize(&mut self, out: &mut Output<'_>) -> Result {
///         out.write(&[0; 32])
///     }
/// }
/// ```
#[macro_export]
macro_rules! settable_ctx_params {
    (@vtable $($entries:tt)*) => {
        const HAS_SETTABLE_CTX_PARAMS: bool = true;
        const HAS_SET_CTX_PARAM: bool = true;
        $crate::settable_ctx_params! { $($entries)* }
    };
    ($($name:literal : $ty:ident => |$this:ident, $p:ident| $apply:expr),* $(,)?) => {
        fn settable_ctx_params() -> $crate::params::ParamTable {
            $crate::param_table! { $($name : $ty),* }
        }

        fn set_ctx_param(
            &mut self,
            name: &::core::ffi::CStr,
            param: &$crate::params::OSSL_PARAM,
        ) -> bool {
            $(
                if name == $name {
                    let $this = &mut *self;
                    let $p = &*param;
                    return $apply;
                }
            )*
            false
        }
    };
}

/// Implements [`Digest`](crate::digest::Digest)'s context getter and its table.
///
/// Each entry binds `this` to `&Self` and `p` to `&mut ParamMut<'_>`, returning
/// `bool`. Unlisted names return `false`.
///
/// Serve a name here only when its value genuinely varies per context, and
/// only alongside [`settable_ctx_params!`](crate::settable_ctx_params) for the
/// same name: upstream digests register a context getter only with a matching
/// setter, and the dispatch constant rejects a getter without one. A value
/// fixed for the algorithm belongs in
/// [`gettable_params!`](crate::gettable_params) instead.
///
/// ```
/// use rustle::digest::{Digest, Output, Result};
/// use rustle::params::Params;
///
/// struct MyHash {
///     rounds: usize,
/// }
///
/// #[rustle::vtable]
/// impl Digest for MyHash {
///     fn newctx() -> Result<Self> { Ok(Self { rounds: 1 }) }
///     fn init(&mut self, params: Option<Params<'_>>) -> Result {
///         self.rounds = 1;
///         self.apply_ctx_params(params)
///     }
///
///     rustle::gettable_params! {
///         c"blocksize": UNSIGNED_INTEGER => |p| p.set_size_t(64),
///         c"size":      UNSIGNED_INTEGER => |p| p.set_size_t(32),
///     }
///
///     rustle::settable_ctx_params! {
///         c"rounds": UNSIGNED_INTEGER => |this, p| match p.get_size_t() {
///             Some(n) => {
///                 this.rounds = n;
///                 true
///             }
///             None => false,
///         },
///     }
///
///     rustle::gettable_ctx_params! {
///         c"rounds": UNSIGNED_INTEGER => |this, p| p.set_size_t(this.rounds),
///     }
///
///     fn update(&mut self, _data: &[u8]) -> Result { Ok(()) }
///     fn finalize(&mut self, out: &mut Output<'_>) -> Result {
///         out.write(&[0; 32])
///     }
/// }
/// ```
#[macro_export]
macro_rules! gettable_ctx_params {
    (@vtable $($entries:tt)*) => {
        const HAS_GETTABLE_CTX_PARAMS: bool = true;
        const HAS_GET_CTX_PARAM: bool = true;
        $crate::gettable_ctx_params! { $($entries)* }
    };
    ($($name:literal : $ty:ident => |$this:ident, $p:ident| $fill:expr),* $(,)?) => {
        fn gettable_ctx_params() -> $crate::params::ParamTable {
            $crate::param_table! { $($name : $ty),* }
        }

        fn get_ctx_param(
            &self,
            name: &::core::ffi::CStr,
            param: &mut $crate::params::ParamMut<'_>,
        ) -> bool {
            $(
                if name == $name {
                    let $this = &*self;
                    let $p = &mut *param;
                    return $fill;
                }
            )*
            false
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{OSSL_PARAM, ParamArray, ParamTable, Params, ParamsMut};
    use core::mem::MaybeUninit;

    #[test]
    fn descriptor_table_requires_final_terminator() {
        static MISSING_END: ParamArray<1> =
            ParamArray([OSSL_PARAM::defn(c"size", OSSL_PARAM::UNSIGNED_INTEGER)]);
        static EARLY_END: ParamArray<2> = ParamArray([
            OSSL_PARAM::END,
            OSSL_PARAM::defn(c"size", OSSL_PARAM::UNSIGNED_INTEGER),
        ]);
        const INVALID: Option<ParamTable> = ParamTable::new(&MISSING_END.0);
        assert!(ParamTable::new(&[]).is_none());
        assert!(INVALID.is_none());
        assert!(ParamTable::new(&EARLY_END.0).is_none());

        let empty = crate::param_table! {};
        assert_eq!(empty.iter().count(), 1);
        // SAFETY: the macro supplies a static, END-terminated descriptor
        // array with no data buffers, valid for this read-only view.
        let params = unsafe { Params::from_ptr(empty.as_ptr()) }.unwrap();
        assert_eq!(params.iter().count(), 0);
    }

    #[test]
    fn descriptor_table_preserves_names_and_first_match() {
        static RAW: ParamArray<4> = ParamArray([
            OSSL_PARAM::defn(c"size", OSSL_PARAM::UNSIGNED_INTEGER),
            OSSL_PARAM::defn(c"size", OSSL_PARAM::INTEGER),
            OSSL_PARAM::defn(c"size-extra", OSSL_PARAM::INTEGER),
            OSSL_PARAM::END,
        ]);
        let table = ParamTable::new(&RAW.0).unwrap();
        let copy = table;
        assert_eq!(copy.as_ptr(), RAW.0.as_ptr());
        // SAFETY: RAW has a final END and static keys; all data pointers
        // are null, so the array is valid for a read-only view.
        let params = unsafe { Params::from_ptr(copy.as_ptr()) }.unwrap();
        assert_eq!(params.iter().count(), 3);
        assert!(!params.locate(c"size").unwrap().is_integer());
        assert!(params.locate(c"size-extra").unwrap().is_integer());
        assert!(params.locate(c"siz").is_none());
    }

    #[test]
    fn writable_cell_preserves_first_match_and_metadata() {
        let mut first = MaybeUninit::<usize>::uninit();
        let mut second = 7usize;
        let mut raw = [
            OSSL_PARAM {
                data: first.as_mut_ptr().cast(),
                data_size: size_of::<usize>(),
                ..OSSL_PARAM::defn(c"size", OSSL_PARAM::UNSIGNED_INTEGER)
            },
            OSSL_PARAM {
                data: core::ptr::from_mut(&mut second).cast(),
                data_size: size_of::<usize>(),
                ..OSSL_PARAM::defn(c"size", OSSL_PARAM::UNSIGNED_INTEGER)
            },
            OSSL_PARAM::END,
        ];
        {
            // SAFETY: raw is END-terminated and exclusively borrowed here;
            // both usize slots are aligned and writable for the view's lifetime.
            let mut params = unsafe { ParamsMut::from_ptr(raw.as_mut_ptr()) }.unwrap();
            assert!(params.locate(c"missing").is_none());
            let mut cell = params.locate(c"size").unwrap();
            assert_eq!(cell.key(), Some(c"size"));
            assert!(!cell.set_int(42));
            assert!(cell.set_size_t(32));
        }
        // SAFETY: the successful size_t setter initialized the first slot.
        assert_eq!(unsafe { first.assume_init() }, 32);
        assert_eq!(second, 7);
        assert_eq!(raw[0].return_size, size_of::<usize>());
        assert_eq!(raw[1].return_size, 0);
        assert_eq!(raw[0].key(), Some(c"size"));
        assert!(raw[2].is_end());
    }

    #[test]
    fn string_setter_respects_buffer_bounds() {
        let mut bytes = [0xa5u8; 5];
        let mut raw = [
            OSSL_PARAM {
                data: bytes.as_mut_ptr().cast(),
                data_size: 4,
                ..OSSL_PARAM::defn(c"text", OSSL_PARAM::UTF8_STRING)
            },
            OSSL_PARAM::END,
        ];
        {
            // SAFETY: raw is END-terminated with a live key and a writable
            // four-byte buffer, exclusively borrowed for this scope.
            let mut params = unsafe { ParamsMut::from_ptr(raw.as_mut_ptr()) }.unwrap();
            let mut cell = params.locate(c"text").unwrap();
            assert!(cell.is_utf8_string());
            assert!(!cell.set_utf8_string("abcde"));
        }
        assert_eq!(bytes, [0xa5; 5]);
        assert_eq!(raw[0].return_size, 5);
        {
            // SAFETY: the same array and buffer remain valid and exclusively
            // borrowed while the new view writes the shorter string.
            let mut params = unsafe { ParamsMut::from_ptr(raw.as_mut_ptr()) }.unwrap();
            assert!(params.locate(c"text").unwrap().set_utf8_string("abc"));
        }
        assert_eq!(bytes, [b'a', b'b', b'c', 0, 0xa5]);
        assert_eq!(raw[0].return_size, 3);
    }
}
