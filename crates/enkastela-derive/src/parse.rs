//! Attribute parsing logic for `#[derive(VaultEncrypt)]`.
//!
//! Parses `#[vault(table = "name")]` from struct attributes and
//! `#[encrypt]`, `#[encrypt(searchable)]`, `#[encrypt(deterministic)]`
//! from field attributes.

use proc_macro2::Span;
use syn::{Attribute, Field, Fields, Ident, LitStr, Result};

/// The encryption mode parsed from a field's `#[encrypt(...)]` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedMode {
    Randomized,
    Searchable,
    Deterministic,
}

/// A parsed encrypted field.
#[derive(Debug)]
pub struct ParsedField {
    pub name: Ident,
    pub mode: ParsedMode,
    pub ty: syn::Type,
    pub span: Span,
}

/// Extracts the table name from `#[vault(table = "...")]` on a struct.
///
/// Returns `None` if the attribute is not present.
pub fn parse_vault_table(attrs: &[Attribute]) -> Result<Option<String>> {
    for attr in attrs {
        if !attr.path().is_ident("vault") {
            continue;
        }

        let mut table_name: Option<String> = None;

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("table") {
                let value = meta.value()?;
                let lit: LitStr = value.parse()?;
                table_name = Some(lit.value());
                Ok(())
            } else {
                Err(meta.error("expected `table = \"...\"`"))
            }
        })?;

        if let Some(name) = table_name {
            return Ok(Some(name));
        }

        return Err(syn::Error::new_spanned(
            attr,
            "expected `#[vault(table = \"...\")]`",
        ));
    }

    Ok(None)
}

/// Parses `#[encrypt]` attributes from a single field.
///
/// Returns `None` if the field has no `#[encrypt]` attribute, or `Some(ParsedMode)`
/// if it does.
pub fn parse_encrypt_attr(field: &Field) -> Result<Option<ParsedMode>> {
    let mut found_mode: Option<ParsedMode> = None;
    let mut found_searchable = false;
    let mut found_deterministic = false;

    for attr in &field.attrs {
        if !attr.path().is_ident("encrypt") {
            continue;
        }

        if found_mode.is_some() {
            return Err(syn::Error::new_spanned(
                attr,
                "duplicate `#[encrypt]` attribute on field",
            ));
        }

        // Check if it's a bare `#[encrypt]` or has arguments.
        match &attr.meta {
            syn::Meta::Path(_) => {
                // Bare `#[encrypt]` => randomized.
                found_mode = Some(ParsedMode::Randomized);
            }
            syn::Meta::List(list) => {
                // Parse the tokens inside the parentheses.
                list.parse_nested_meta(|meta| {
                    if meta.path.is_ident("searchable") {
                        if found_deterministic {
                            return Err(
                                meta.error("field cannot be both `searchable` and `deterministic`")
                            );
                        }
                        found_searchable = true;
                        Ok(())
                    } else if meta.path.is_ident("deterministic") {
                        if found_searchable {
                            return Err(
                                meta.error("field cannot be both `searchable` and `deterministic`")
                            );
                        }
                        found_deterministic = true;
                        Ok(())
                    } else {
                        Err(meta.error("expected `searchable` or `deterministic`"))
                    }
                })?;

                if found_searchable {
                    found_mode = Some(ParsedMode::Searchable);
                } else if found_deterministic {
                    found_mode = Some(ParsedMode::Deterministic);
                } else {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "expected `searchable` or `deterministic` inside `#[encrypt(...)]`",
                    ));
                }
            }
            syn::Meta::NameValue(_) => {
                return Err(syn::Error::new_spanned(
                    attr,
                    "expected `#[encrypt]`, `#[encrypt(searchable)]`, or `#[encrypt(deterministic)]`",
                ));
            }
        }
    }

    Ok(found_mode)
}

/// Parses all fields of a struct, extracting those with `#[encrypt]` attributes.
pub fn parse_fields(fields: &Fields) -> Result<Vec<ParsedField>> {
    let named = match fields {
        Fields::Named(named) => named,
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "VaultEncrypt can only be derived for structs with named fields",
            ));
        }
    };

    let mut parsed = Vec::new();

    for field in &named.named {
        if let Some(mode) = parse_encrypt_attr(field)? {
            let ident = field
                .ident
                .clone()
                .expect("named field must have an identifier");

            parsed.push(ParsedField {
                name: ident,
                mode,
                ty: field.ty.clone(),
                span: field
                    .ident
                    .as_ref()
                    .map(|i| i.span())
                    .unwrap_or_else(Span::call_site),
            });
        }
    }

    Ok(parsed)
}
