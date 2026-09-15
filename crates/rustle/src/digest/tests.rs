// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone)]
struct Copyable {
    state: u8,
    copies: usize,
}

#[crate::vtable]
impl Digest for Copyable {
    fn newctx() -> Result<Self> {
        Ok(Self {
            state: 0,
            copies: 0,
        })
    }
    fn init(&mut self, _params: Option<Params<'_>>) -> Result {
        self.state = 0;
        Ok(())
    }
    fn update(&mut self, input: &[u8]) -> Result {
        for byte in input {
            self.state = self.state.wrapping_add(*byte);
        }
        Ok(())
    }
    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write(&[self.state])
    }
    crate::gettable_params! {
        c"size": UNSIGNED_INTEGER => |p| p.set_size_t(1),
    }
    fn dupctx(&self) -> Result<Self> {
        Ok(self.clone())
    }
    fn copyctx(&mut self, source: &Self) {
        self.state = source.state;
        self.copies = self.copies.wrapping_add(1);
    }
}

#[test]
fn copyctx_replaces_state_without_changing_source() {
    const {
        assert!(Copyable::HAS_COPYCTX);
        assert!(Copyable::HAS_DUPCTX);
        assert!(!Configurable::HAS_COPYCTX);
    }
    let entries = DigestAlgorithm::<Copyable>::ENTRIES;
    assert_eq!(
        entries.iter().take_while(|entry| !entry.is_end()).count(),
        9
    );
    assert!(entries.last().is_some_and(OSSL_DISPATCH::is_end));
    let mut source = Copyable {
        state: 42,
        copies: 0,
    };
    let mut destination = Copyable {
        state: 99,
        copies: 0,
    };
    // SAFETY: distinct live contexts of the table's type, exclusively lent.
    unsafe {
        DigestAlgorithm::<Copyable>::copyctx(
            core::ptr::from_mut(&mut destination).cast(),
            core::ptr::from_mut(&mut source).cast(),
        );
    }
    assert_eq!((destination.state, destination.copies), (42, 1));
    assert_eq!((source.state, source.copies), (42, 0));
    assert_eq!(source.update(&[1]), Ok(()));
    assert_eq!(destination.update(&[2]), Ok(()));
    assert_eq!((source.state, destination.state), (43, 44));
}

#[test]
fn copyctx_self_copy_and_null_arguments_do_not_call_implementation() {
    let mut ctx = Copyable {
        state: 42,
        copies: 0,
    };
    let ptr = core::ptr::from_mut(&mut ctx).cast();
    for (destination, source) in [
        (ptr, ptr),
        (ptr, core::ptr::null_mut()),
        (core::ptr::null_mut(), ptr),
        (core::ptr::null_mut(), core::ptr::null_mut()),
    ] {
        // SAFETY: the adapter handles null and identical pointers before
        // constructing references; the only non-null pointer is a live ctx.
        unsafe { DigestAlgorithm::<Copyable>::copyctx(destination, source) };
    }
    assert_eq!((ctx.state, ctx.copies), (42, 0));
}

struct Configurable(u8);

#[crate::vtable]
impl Digest for Configurable {
    fn newctx() -> Result<Self> {
        Ok(Self(0))
    }
    fn init(&mut self, params: Option<Params<'_>>) -> Result {
        self.apply_ctx_params(params)
    }
    fn update(&mut self, _input: &[u8]) -> Result {
        Ok(())
    }
    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write(&[self.0])
    }

    crate::gettable_params! {
        c"size": UNSIGNED_INTEGER => |p| p.set_size_t(1),
    }
    crate::settable_ctx_params! {
        c"value": INTEGER => |this, p| match p.get_int().and_then(|n| u8::try_from(n).ok()) {
            Some(value) => { this.0 = value; true }
            None => false,
        },
    }
}

/// The same state, additionally readable back through a context getter.
struct Readable(u8);

#[crate::vtable]
impl Digest for Readable {
    fn newctx() -> Result<Self> {
        Ok(Self(0))
    }
    fn init(&mut self, params: Option<Params<'_>>) -> Result {
        self.apply_ctx_params(params)
    }
    fn update(&mut self, _input: &[u8]) -> Result {
        Ok(())
    }
    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write(&[self.0])
    }

    crate::gettable_params! {
        c"size": UNSIGNED_INTEGER => |p| p.set_size_t(1),
    }
    crate::settable_ctx_params! {
        c"value": INTEGER => |this, p| match p.get_int().and_then(|n| u8::try_from(n).ok()) {
            Some(value) => { this.0 = value; true }
            None => false,
        },
    }
    crate::gettable_ctx_params! {
        c"value": INTEGER => |this, p| p.set_int(this.0.into()),
    }
}

#[test]
fn cooperating_macros_register_setters_after_an_absent_dupctx() {
    const {
        assert!(Configurable::HAS_GET_PARAM);
        assert!(Configurable::HAS_GETTABLE_PARAMS);
        assert!(Configurable::HAS_SET_CTX_PARAM);
        assert!(Configurable::HAS_SETTABLE_CTX_PARAMS);
        assert!(!Configurable::HAS_GET_CTX_PARAM);
        assert!(!Configurable::HAS_GETTABLE_CTX_PARAMS);
        assert!(!Configurable::HAS_DUPCTX);
    }
    let entries = DigestAlgorithm::<Configurable>::ENTRIES;
    // There must be no END in the hole left by the absent optional DUPCTX.
    assert_eq!(
        entries.iter().take_while(|entry| !entry.is_end()).count(),
        9
    );
    assert!(entries.last().is_some_and(OSSL_DISPATCH::is_end));
    assert_eq!(Configurable(0).dupctx().err(), Some(Error::Unsupported));
}

#[test]
fn a_context_getter_adds_both_of_its_callbacks() {
    const {
        assert!(Readable::HAS_GET_CTX_PARAM);
        assert!(Readable::HAS_GETTABLE_CTX_PARAMS);
    }
    let entries = DigestAlgorithm::<Readable>::ENTRIES;
    assert_eq!(
        entries.iter().take_while(|entry| !entry.is_end()).count(),
        11
    );
    assert!(entries.last().is_some_and(OSSL_DISPATCH::is_end));
}

#[test]
fn get_ctx_params_fills_described_names_and_ignores_the_rest() {
    let mut ctx = Readable(42);
    let mut value = MaybeUninit::<ffi::c_int>::uninit();
    let mut other = 7i32;
    let mut raw = [
        OSSL_PARAM::cell(
            c"value",
            OSSL_PARAM::INTEGER,
            value.as_mut_ptr().cast(),
            size_of::<ffi::c_int>(),
        ),
        OSSL_PARAM::cell(
            c"undescribed",
            OSSL_PARAM::INTEGER,
            core::ptr::from_mut(&mut other).cast(),
            size_of::<ffi::c_int>(),
        ),
        OSSL_PARAM::END,
    ];
    // SAFETY: ctx is a live exclusively borrowed Readable.
    let result = unsafe {
        DigestAlgorithm::<Readable>::get_ctx_params(
            core::ptr::from_mut(&mut ctx).cast(),
            raw.as_mut_ptr(),
        )
    };
    assert_eq!(result, 1);
    // SAFETY: the successful INTEGER setter initialized the described slot.
    assert_eq!(unsafe { value.assume_init() }, 42);
    // A name the descriptor table does not list is left untouched.
    assert_eq!(other, 7);

    // A null array is a no-op success; a null context is a failure.
    // SAFETY: ctx stays live; a null parameter array is permitted here.
    let result = unsafe {
        DigestAlgorithm::<Readable>::get_ctx_params(
            core::ptr::from_mut(&mut ctx).cast(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(result, 1);
    // SAFETY: a null context is rejected before any dereference.
    let result = unsafe {
        DigestAlgorithm::<Readable>::get_ctx_params(core::ptr::null_mut(), raw.as_mut_ptr())
    };
    assert_eq!(result, 0);
}

#[test]
fn get_ctx_params_fails_when_a_described_name_is_rejected() {
    let mut ctx = Readable(42);
    let mut wrong = 0usize;
    let mut raw = [
        OSSL_PARAM::cell(
            c"value",
            OSSL_PARAM::UNSIGNED_INTEGER,
            core::ptr::from_mut(&mut wrong).cast(),
            size_of::<usize>(),
        ),
        OSSL_PARAM::END,
    ];
    // SAFETY: ctx is live and exclusively borrowed
    let result = unsafe {
        DigestAlgorithm::<Readable>::get_ctx_params(
            core::ptr::from_mut(&mut ctx).cast(),
            raw.as_mut_ptr(),
        )
    };
    assert_eq!(result, 0);
    assert_eq!(wrong, 0);
}

#[test]
fn output_tracks_only_successful_bounded_writes() {
    let mut storage = [MaybeUninit::new(0xa5); 6];
    {
        let mut out = Output::new(&mut storage[1..5]);
        let mut called = false;
        assert_eq!(
            out.write_with(5, |_| {
                called = true;
                Ok(())
            }),
            Err(Error::BufferTooSmall)
        );
        assert!(!called);
        assert_eq!(out.written(), 0);
        assert_eq!(out.write(b"ab"), Ok(()));
        assert_eq!(
            out.write_with(1, |bytes| {
                assert_eq!(bytes, &[0]);
                if let Some(byte) = bytes.first_mut() {
                    *byte = b'x';
                }
                Err(Error::Unsupported)
            }),
            Err(Error::Unsupported)
        );
        assert_eq!(out.written(), 2);
        assert_eq!(
            out.write_with(1, |bytes| {
                assert_eq!(bytes, &[0]);
                if let Some(byte) = bytes.first_mut() {
                    *byte = b'c';
                }
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(out.written(), 3);
        assert_eq!(out.write(b"de"), Err(Error::BufferTooSmall));
    }
    // SAFETY: the complete allocation was initialized at construction.
    let actual = storage.map(|byte| unsafe { byte.assume_init() });
    assert_eq!(actual, [0xa5, b'a', b'b', b'c', 0xa5, 0xa5]);
}

#[test]
fn finalize_reports_length_and_preserves_guards() {
    let mut ctx = Configurable(42);
    let mut bytes = [0xa5u8; 3];
    let mut written = usize::MAX;
    // SAFETY: ctx is a live exclusively borrowed.
    let result = unsafe {
        DigestAlgorithm::<Configurable>::finalize(
            core::ptr::from_mut(&mut ctx).cast(),
            bytes.as_mut_ptr().wrapping_add(1),
            &raw mut written,
            1,
        )
    };
    assert_eq!(result, 1);
    assert_eq!(written, 1);
    assert_eq!(bytes, [0xa5, 42, 0xa5]);
    // SAFETY: ctx remains live
    let result = unsafe {
        DigestAlgorithm::<Configurable>::update(
            core::ptr::from_mut(&mut ctx).cast(),
            core::ptr::null(),
            0,
        )
    };
    assert_eq!(result, 1);
}

/// One byte of state that exports and restores a one-byte blob.
struct Serializable(u8);

#[crate::vtable]
impl Digest for Serializable {
    fn newctx() -> Result<Self> {
        Ok(Self(0))
    }
    fn init(&mut self, _params: Option<Params<'_>>) -> Result {
        Ok(())
    }
    fn update(&mut self, _input: &[u8]) -> Result {
        Ok(())
    }
    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write(&[self.0])
    }

    crate::gettable_params! {
        c"size": UNSIGNED_INTEGER => |p| p.set_size_t(1),
    }
    fn serialize(&self, out: Option<&mut Output<'_>>) -> Result<usize> {
        match out {
            None => Ok(1),
            Some(out) => {
                out.write(&[self.0])?;
                Ok(1)
            }
        }
    }
    fn deserialize(&mut self, input: &[u8]) -> Result {
        match input {
            &[value] => {
                self.0 = value;
                Ok(())
            }
            _ => Err(Error::InvalidParameter),
        }
    }
}

#[test]
fn serialization_methods_register_independently() {
    const {
        assert!(Serializable::HAS_SERIALIZE);
        assert!(Serializable::HAS_DESERIALIZE);
        assert!(!Configurable::HAS_SERIALIZE);
        assert!(!Configurable::HAS_DESERIALIZE);
    }
    let entries = DigestAlgorithm::<Serializable>::ENTRIES;
    assert_eq!(
        entries.iter().take_while(|entry| !entry.is_end()).count(),
        9
    );
    assert!(entries.last().is_some_and(OSSL_DISPATCH::is_end));

    let mut ctx = Configurable(0);
    assert_eq!(ctx.serialize(None), Err(Error::Unsupported));
    assert_eq!(
        ctx.serialize(Some(&mut Output::new(&mut []))),
        Err(Error::Unsupported)
    );
    assert_eq!(ctx.deserialize(&[]), Err(Error::Unsupported));
}

#[test]
fn serialize_queries_size_then_writes_through_output() {
    let mut ctx = Serializable(42);

    // A null output queries the size without reading the length slot.
    let mut size = MaybeUninit::<usize>::uninit();
    // SAFETY: ctx is live; null out makes the length slot output-only.
    let result = unsafe {
        DigestAlgorithm::<Serializable>::serialize(
            core::ptr::from_mut(&mut ctx).cast(),
            core::ptr::null_mut(),
            size.as_mut_ptr(),
        )
    };
    assert_eq!(result, 1);
    // SAFETY: the successful query initialized the slot.
    assert_eq!(unsafe { size.assume_init() }, 1);

    // A non-null output reads the slot as capacity and reports written bytes.
    let mut bytes = [0xa5u8; 3];
    let mut len = 1;
    // SAFETY: ctx is live, the length is initialized, and one exclusive
    // writable byte sits at bytes[1].
    let result = unsafe {
        DigestAlgorithm::<Serializable>::serialize(
            core::ptr::from_mut(&mut ctx).cast(),
            bytes.as_mut_ptr().wrapping_add(1),
            &raw mut len,
        )
    };
    assert_eq!(result, 1);
    assert_eq!(len, 1);
    assert_eq!(bytes, [0xa5, 42, 0xa5]);
    // Serialization borrows the context; the computation survives.
    assert_eq!(ctx.0, 42);

    // A capacity larger than the blob succeeds and reports only written bytes.
    let mut bytes = [0xa5u8; 3];
    let mut len = 3;
    // SAFETY: ctx is live, the length is initialized, and three exclusive
    // writable bytes are disjoint from ctx and len.
    let result = unsafe {
        DigestAlgorithm::<Serializable>::serialize(
            core::ptr::from_mut(&mut ctx).cast(),
            bytes.as_mut_ptr(),
            &raw mut len,
        )
    };
    assert_eq!(result, 1);
    assert_eq!(len, 1);
    assert_eq!(bytes, [42, 0xa5, 0xa5]);

    // Zero capacity cannot hold the blob; an oversized capacity is rejected
    // before a slice is ever formed. Both leave slot and buffer untouched.
    for capacity in [0, usize::MAX] {
        let mut len = capacity;
        let mut bytes = [0xa5u8; 3];
        // SAFETY: neither rejected case accesses the buffer, and ctx is live.
        let result = unsafe {
            DigestAlgorithm::<Serializable>::serialize(
                core::ptr::from_mut(&mut ctx).cast(),
                bytes.as_mut_ptr(),
                &raw mut len,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(len, capacity);
        assert_eq!(bytes, [0xa5, 0xa5, 0xa5]);
    }

    // Null context and null length slot fail before anything is read.
    let mut len = 1;
    // SAFETY: null arguments are rejected before any dereference.
    let result = unsafe {
        DigestAlgorithm::<Serializable>::serialize(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &raw mut len,
        )
    };
    assert_eq!(result, 0);
    // SAFETY: a null length slot is rejected before touching the buffer.
    let result = unsafe {
        DigestAlgorithm::<Serializable>::serialize(
            core::ptr::from_mut(&mut ctx).cast(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(result, 0);
}

#[test]
fn deserialize_validates_input_before_restoring() {
    let mut ctx = Serializable(42);
    let input = [7u8];

    // Null input, zero length, and oversized length are all rejected at the
    // adapter before the implementation ever sees them. A wrong-length slice
    // that does reach the implementation is rejected there instead. No
    // rejected restoration may touch the live state.
    for (data, len) in [
        (core::ptr::null(), 1usize),
        (core::ptr::null(), 0),
        (input.as_ptr(), 0),
        (input.as_ptr(), usize::MAX),
    ] {
        // SAFETY: rejected inputs are never read; ctx stays live throughout.
        let result = unsafe {
            DigestAlgorithm::<Serializable>::deserialize(
                core::ptr::from_mut(&mut ctx).cast(),
                data,
                len,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(ctx.0, 42);
    }

    // SAFETY: null context is rejected before reading the input.
    let result = unsafe {
        DigestAlgorithm::<Serializable>::deserialize(core::ptr::null_mut(), input.as_ptr(), 1)
    };
    assert_eq!(result, 0);

    // SAFETY: ctx is live and exclusively borrowed; the one input byte is
    // readable and disjoint from ctx.
    let result = unsafe {
        DigestAlgorithm::<Serializable>::deserialize(
            core::ptr::from_mut(&mut ctx).cast(),
            input.as_ptr(),
            1,
        )
    };
    assert_eq!(result, 1);
    assert_eq!(ctx.0, 7);
}
