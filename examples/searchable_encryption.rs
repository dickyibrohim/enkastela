//! Searchable encryption with blind indexes.
//!
//! Demonstrates how to encrypt data while maintaining the ability to search
//! by computing deterministic blind indexes (HMAC-SHA256).
//!
//! Run with:
//! ```sh
//! cargo run --example searchable_encryption
//! ```

use enkastela::{SecretKey, Vault};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SecretKey::from_bytes([0x42; 32]);

    let vault = Vault::builder()
        .master_key_static(key)
        .allow_insecure_connection()
        .build()
        .await?;

    println!("=== Enkastela Searchable Encryption Example ===\n");

    // --- Simulate a user database with encrypted emails ---
    let users = vec![
        ("user_1", "alice@example.com"),
        ("user_2", "bob@example.com"),
        ("user_3", "charlie@example.com"),
        ("user_4", "alice@example.com"), // duplicate email
    ];

    println!("--- Storing Users (Encrypted) ---");
    let mut stored: Vec<(String, String, [u8; 32])> = Vec::new();

    for (id, email) in &users {
        let encrypted_email = vault
            .encrypt_field("users", "email", email.as_bytes())
            .await?;
        let blind_index = vault.compute_blind_index("users", "email", email.as_bytes())?;

        println!(
            "  {id}: encrypted={:.40}...  index={}",
            encrypted_email,
            hex::encode(blind_index)
        );
        stored.push((id.to_string(), encrypted_email, blind_index));
    }

    // --- Search by email ---
    println!("\n--- Searching for alice@example.com ---");
    let search_email = b"alice@example.com";
    let search_index = vault.compute_blind_index("users", "email", search_email)?;
    println!("  Search index: {}", hex::encode(search_index));

    let matches: Vec<&(String, String, [u8; 32])> = stored
        .iter()
        .filter(|(_, _, idx)| *idx == search_index)
        .collect();

    println!("  Found {} match(es):", matches.len());
    for (id, encrypted_email, _) in &matches {
        let decrypted = vault
            .decrypt_field("users", "email", encrypted_email)
            .await?;
        println!("    {id}: {}", String::from_utf8_lossy(&decrypted));
    }

    // --- Verify non-match ---
    println!("\n--- Searching for unknown@example.com ---");
    let search_index = vault.compute_blind_index("users", "email", b"unknown@example.com")?;
    let matches: Vec<_> = stored
        .iter()
        .filter(|(_, _, idx)| *idx == search_index)
        .collect();
    println!("  Found {} match(es) (expected 0)", matches.len());

    // --- Demonstrate blind index properties ---
    println!("\n--- Blind Index Properties ---");
    let idx_a = vault.compute_blind_index("users", "email", b"test@test.com")?;
    let idx_b = vault.compute_blind_index("users", "email", b"test@test.com")?;
    let idx_c = vault.compute_blind_index("users", "phone", b"test@test.com")?;
    println!("  Same input, same column:      match={}", idx_a == idx_b);
    println!(
        "  Same input, different column:  match={} (expected false)",
        idx_a == idx_c
    );

    println!("\n=== Searchable encryption demo complete! ===");
    Ok(())
}

mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
