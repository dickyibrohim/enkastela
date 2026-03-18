//! Code generation for `#[derive(VaultEncrypt)]`.
//!
//! Generates the `VaultEncryptable` trait implementation for the annotated struct.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

use crate::parse::{ParsedField, ParsedMode};

/// Generates the `VaultEncryptable` impl block for a struct.
pub fn generate(struct_name: &Ident, table_name: &str, fields: &[ParsedField]) -> TokenStream {
    let field_entries: Vec<TokenStream> = fields
        .iter()
        .map(|f| {
            let name = f.name.to_string();
            let mode = match f.mode {
                ParsedMode::Randomized => {
                    quote! { ::enkastela::types::traits::EncryptionMode::Randomized }
                }
                ParsedMode::Searchable => {
                    quote! { ::enkastela::types::traits::EncryptionMode::Searchable }
                }
                ParsedMode::Deterministic => {
                    quote! { ::enkastela::types::traits::EncryptionMode::Deterministic }
                }
            };
            quote! {
                ::enkastela::types::traits::FieldDef {
                    name: #name,
                    mode: #mode,
                }
            }
        })
        .collect();

    quote! {
        impl ::enkastela::types::traits::VaultEncryptable for #struct_name {
            fn table_name() -> &'static str {
                #table_name
            }

            fn encrypted_fields() -> ::std::vec::Vec<::enkastela::types::traits::FieldDef> {
                ::std::vec![
                    #( #field_entries ),*
                ]
            }
        }
    }
}
