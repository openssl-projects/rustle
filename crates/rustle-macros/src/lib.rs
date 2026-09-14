// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Method-presence metadata for safe provider operation traits.

#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::ext::IdentExt;
use syn::{Attribute, Error, ImplItem, Item, TraitItem, parse_macro_input, parse_quote};

fn configuration(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
}

fn expand(item: Item) -> syn::Result<proc_macro2::TokenStream> {
    match item {
        Item::Trait(mut item) => {
            let mut generated = vec![parse_quote! {
                #[doc(hidden)]
                const __VTABLE: ();
            }];
            for member in &item.items {
                if let TraitItem::Fn(method) = member {
                    let name = format_ident!(
                        "HAS_{}",
                        method.sig.ident.unraw().to_string().to_uppercase()
                    );
                    let cfg = configuration(&method.attrs);
                    generated.push(parse_quote! {
                        #(#cfg)*
                        #[doc(hidden)]
                        const #name: bool = false;
                    });
                }
            }
            item.items.extend(generated);
            Ok(quote!(#item))
        }
        Item::Impl(mut item) if item.trait_.is_some() => {
            let mut generated = vec![parse_quote! {
                const __VTABLE: () = ();
            }];
            for member in &mut item.items {
                match member {
                    ImplItem::Fn(method) => {
                        let name = format_ident!(
                            "HAS_{}",
                            method.sig.ident.unraw().to_string().to_uppercase()
                        );
                        let cfg = configuration(&method.attrs);
                        generated.push(parse_quote! {
                            #(#cfg)*
                            const #name: bool = true;
                        });
                    }
                    ImplItem::Const(value)
                        if value.ident == "__VTABLE"
                            || value.ident.to_string().starts_with("HAS_") =>
                    {
                        return Err(Error::new_spanned(
                            value,
                            "vtable metadata is generated; implement the method instead",
                        ));
                    }
                    ImplItem::Macro(invocation) => {
                        let supported =
                            invocation.mac.path.segments.last().is_some_and(|segment| {
                                segment.ident == "gettable_params"
                                    || segment.ident == "settable_ctx_params"
                                    || segment.ident == "gettable_ctx_params"
                            });
                        if !supported {
                            return Err(Error::new_spanned(
                                invocation,
                                "unsupported implementation-item macro; write the methods directly or generate the whole #[vtable] impl",
                            ));
                        }
                        // These cooperating macros emit presence constants along
                        // with their methods. An outer attribute cannot inspect
                        // methods that a nested macro has not expanded yet.
                        let tokens = &invocation.mac.tokens;
                        invocation.mac.tokens = quote!(@vtable #tokens);
                    }
                    _ => {}
                }
            }
            item.items.extend(generated);
            Ok(quote!(#item))
        }
        item => Err(Error::new_spanned(
            item,
            "#[vtable] requires a trait or trait implementation",
        )),
    }
}

/// Derive method-presence constants for a trait and its implementations.
///
/// Apply this attribute to both the trait and each implementation. Explicit
/// methods get `HAS_METHOD = true`; omitted methods retain `false`. Configuration
/// attributes follow their methods. The trait's required marker catches a
/// forgotten implementation attribute.
///
/// Rustle's parameter macros cooperate with this attribute. Other macros that
/// generate implementation items are rejected rather than silently omitted.
///
/// Handwritten overrides of generated metadata are rejected; implement the
/// corresponding method instead.
#[proc_macro_attribute]
pub fn vtable(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return Error::new(
            proc_macro2::Span::call_site(),
            "#[vtable] takes no arguments",
        )
        .into_compile_error()
        .into();
    }
    match expand(parse_macro_input!(input as Item)) {
        Ok(output) => output.into(),
        Err(error) => error.into_compile_error().into(),
    }
}
