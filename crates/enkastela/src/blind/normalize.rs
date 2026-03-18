//! Unicode normalization for blind index inputs.
//!
//! Ensures that equivalent Unicode representations (NFC vs NFD) produce
//! the same blind index value.

use unicode_normalization::UnicodeNormalization;

/// Normalizes text for blind index computation.
///
/// Applies: Unicode NFC normalization, trim whitespace, lowercase.
/// This ensures that visually identical strings produce the same blind index.
pub fn normalize_for_blind_index(input: &str) -> String {
    input.nfc().collect::<String>().trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passthrough() {
        assert_eq!(normalize_for_blind_index("hello"), "hello");
        assert_eq!(
            normalize_for_blind_index("alice@example.com"),
            "alice@example.com"
        );
    }

    #[test]
    fn nfc_vs_nfd_equivalence() {
        // NFC: e-acute as a single codepoint U+00E9
        let nfc = "\u{00E9}"; // é
                              // NFD: e + combining acute accent U+0065 U+0301
        let nfd = "\u{0065}\u{0301}"; // é (decomposed)

        assert_eq!(
            normalize_for_blind_index(nfc),
            normalize_for_blind_index(nfd),
        );
    }

    #[test]
    fn trim_whitespace() {
        assert_eq!(normalize_for_blind_index("  hello  "), "hello");
        assert_eq!(normalize_for_blind_index("\thello\n"), "hello");
        assert_eq!(normalize_for_blind_index("  hello world  "), "hello world");
    }

    #[test]
    fn lowercase() {
        assert_eq!(normalize_for_blind_index("HELLO"), "hello");
        assert_eq!(normalize_for_blind_index("Hello World"), "hello world");
        assert_eq!(
            normalize_for_blind_index("Alice@Example.COM"),
            "alice@example.com"
        );
    }

    #[test]
    fn empty_string() {
        assert_eq!(normalize_for_blind_index(""), "");
    }

    #[test]
    fn cjk_characters_preserved() {
        // CJK characters should pass through normalization unchanged
        let input = "\u{4F60}\u{597D}"; // 你好
        assert_eq!(normalize_for_blind_index(input), input);
    }

    #[test]
    fn accented_characters_composed_vs_decomposed() {
        // "café" in NFC
        let composed = "caf\u{00E9}";
        // "café" in NFD
        let decomposed = "caf\u{0065}\u{0301}";

        let norm_composed = normalize_for_blind_index(composed);
        let norm_decomposed = normalize_for_blind_index(decomposed);

        assert_eq!(norm_composed, norm_decomposed);
        assert_eq!(norm_composed, "caf\u{00E9}");
    }

    #[test]
    fn whitespace_only_becomes_empty() {
        assert_eq!(normalize_for_blind_index("   "), "");
        assert_eq!(normalize_for_blind_index("\t\n "), "");
    }

    #[test]
    fn mixed_case_unicode() {
        // German sharp s and uppercase handling
        assert_eq!(normalize_for_blind_index("\u{00DC}BER"), "\u{00FC}ber"); // Ü -> ü
    }
}
