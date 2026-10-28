/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, parse_macro_input};

// inbuxa: the displayed version (see version.rs).
mod version;

/// The workspace version as tags and images name it, as a string literal, so
/// it can go into `concat!`. Read from the crate being compiled, which
/// inherits the one version in the workspace Cargo.toml.
#[proc_macro]
pub fn display_version(_input: TokenStream) -> TokenStream {
    let cargo = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    match version::display(&cargo) {
        Ok(shown) => quote!(#shown).into(),
        Err(err) => {
            let err = format!("workspace version: {err}");
            quote!(compile_error!(#err)).into()
        }
    }
}

#[proc_macro_derive(EnumMethods)]
pub fn enum_id(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let variants = match input.data {
        Data::Enum(ref data) => &data.variants,
        _ => panic!("EnumMethods only works on enums"),
    };

    let variant_count = variants.len();
    let variant_names: Vec<_> = variants.iter().map(|v| &v.ident).collect();
    let variant_ids: Vec<u32> = (0..(variant_count as u32)).collect();
    let snake_case_names: Vec<String> = variant_names
        .iter()
        .map(|name| to_snake_case(&name.to_string()))
        .collect();

    let expanded = quote! {
        impl #name {
            pub const COUNT: usize = #variant_count;

            pub const fn id(&self) -> u32 {
                match self {
                    #(#name::#variant_names => #variant_ids,)*
                }
            }

            pub fn from_id(id: u32) -> Option<Self> {
                match id {
                    #(#variant_ids => Some(#name::#variant_names),)*
                    _ => None,
                }
            }

            pub fn name(&self) -> &'static str {
                match self {
                    #(#name::#variant_names => #snake_case_names,)*
                }
            }

            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    #(#snake_case_names => Some(#name::#variant_names),)*
                    _ => None,
                }
            }
        }
    };

    TokenStream::from(expanded)
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.char_indices() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('-');
            }
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    result
}
