//! Derive macros for enkastela field encryption.
//!
//! Provides `#[derive(VaultEncrypt)]` and field-level attributes
//! (`#[encrypt]`, `#[encrypt(searchable)]`, `#[encrypt(deterministic)]`)
//! for zero-boilerplate encryption of struct fields.
//!
//! # Example
//!
//! ```rust,ignore
//! use enkastela_derive::VaultEncrypt;
//!
//! #[derive(VaultEncrypt)]
//! #[vault(table = "users")]
//! struct User {
//!     id: i64,
//!
//!     #[encrypt]
//!     full_name: String,
//!
//!     #[encrypt(searchable)]
//!     email: String,
//!
//!     #[encrypt(deterministic)]
//!     national_id: String,
//! }
//! ```

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod codegen;
mod parse;
mod validate;

/// Derive macro for enkastela field encryption.
///
/// Generates an implementation of `VaultEncryptable` for the annotated struct.
/// Fields marked with `#[encrypt]` will be transparently encrypted/decrypted.
///
/// # Struct Attribute
///
/// - `#[vault(table = "table_name")]` -- required, specifies the database table.
///
/// # Field Attributes
///
/// - `#[encrypt]` -- randomized AES-256-GCM encryption (default).
/// - `#[encrypt(searchable)]` -- randomized encryption with HMAC-SHA256 blind index.
///   Only valid on `String` fields.
/// - `#[encrypt(deterministic)]` -- deterministic AES-256-SIV encryption.
#[proc_macro_derive(VaultEncrypt, attributes(vault, encrypt))]
pub fn vault_encrypt_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match vault_encrypt_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn vault_encrypt_impl(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let struct_name = &input.ident;
    let struct_span = struct_name.span();

    // Parse the #[vault(table = "...")] attribute.
    let table_name = parse::parse_vault_table(&input.attrs)?;

    // Parse field-level #[encrypt] attributes.
    let fields = match &input.data {
        syn::Data::Struct(data) => parse::parse_fields(&data.fields)?,
        syn::Data::Enum(_) => {
            return Err(syn::Error::new(
                struct_span,
                "VaultEncrypt can only be derived for structs, not enums",
            ));
        }
        syn::Data::Union(_) => {
            return Err(syn::Error::new(
                struct_span,
                "VaultEncrypt can only be derived for structs, not unions",
            ));
        }
    };

    // Validate the parsed data.
    validate::validate(&table_name, &fields, struct_span)?;

    // The table_name is guaranteed to be Some after validation.
    let table = table_name.unwrap();

    // Generate the VaultEncryptable implementation.
    Ok(codegen::generate(struct_name, &table, &fields))
}
