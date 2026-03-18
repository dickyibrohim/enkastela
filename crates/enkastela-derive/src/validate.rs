//! Compile-time validation for `#[derive(VaultEncrypt)]`.
//!
//! Validates that the struct and its fields satisfy all requirements
//! before code generation.

use syn::Result;

use crate::parse::{ParsedField, ParsedMode};

/// Returns `true` if the type path ends with `String`.
fn is_string_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                segment.ident == "String"
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Validates a parsed struct definition.
///
/// Checks:
/// - Table name is present and non-empty
/// - At least one field has `#[encrypt]`
/// - `#[encrypt(searchable)]` is only on `String` fields
pub fn validate(
    table_name: &Option<String>,
    fields: &[ParsedField],
    struct_span: proc_macro2::Span,
) -> Result<()> {
    // Ensure #[vault(table = "...")] is present.
    let table = match table_name {
        Some(name) => name,
        None => {
            return Err(syn::Error::new(
                struct_span,
                "missing `#[vault(table = \"...\")]` attribute on struct",
            ));
        }
    };

    // Ensure table name is non-empty.
    if table.is_empty() {
        return Err(syn::Error::new(
            struct_span,
            "table name in `#[vault(table = \"...\")]` must not be empty",
        ));
    }

    // Ensure at least one field has #[encrypt].
    if fields.is_empty() {
        return Err(syn::Error::new(
            struct_span,
            "at least one field must have `#[encrypt]` attribute",
        ));
    }

    // Validate searchable fields are String type.
    for field in fields {
        if field.mode == ParsedMode::Searchable && !is_string_type(&field.ty) {
            return Err(syn::Error::new(
                field.span,
                "`#[encrypt(searchable)]` can only be applied to `String` fields \
                 because blind index computation requires UTF-8 normalization",
            ));
        }
    }

    Ok(())
}
