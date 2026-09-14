// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

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
