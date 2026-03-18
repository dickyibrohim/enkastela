//! Key derivation and management example.
//!
//! Demonstrates how enkastela derives separate encryption keys per table
//! and how the key hierarchy works.
//!
//! Run with:
//! ```sh
//! cargo run --example key_derivation
//! ```

use enkastela::{SecretKey, Vault};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Enkastela Key Derivation Example ===\n");

    let key = SecretKey::from_bytes([0x42; 32]);

    let vault = Vault::builder()
        .master_key_static(key)
        .allow_insecure_connection()
        .build()
        .await?;

    // --- Per-table key isolation ---
    println!("--- Per-Table Key Isolation ---");
    println!("Each table gets its own derived encryption key (DEK).");
    println!("This means compromising one table's DEK doesn't affect others.\n");

    // Encrypt same value under different tables
    let value = b"sensitive_data";

    let ct_users = vault.encrypt_field("users", "data", value).await?;
    let ct_orders = vault.encrypt_field("orders", "data", value).await?;

    println!("Same plaintext, different tables:");
    println!("  users.data:  {:.50}...", ct_users);
    println!("  orders.data: {:.50}...", ct_orders);
    println!("  Different ciphertext: {}", ct_users != ct_orders);

    // Cross-table decrypt fails (AAD mismatch)
    let cross_result = vault.decrypt_field("orders", "data", &ct_users).await;
    println!(
        "  Cross-table decrypt: {} (security!)",
        if cross_result.is_err() {
            "REJECTED"
        } else {
            "accepted"
        }
    );

    // --- DEK versioning ---
    println!("\n--- DEK Versioning ---");
    println!("Current DEK version: {}", vault.current_version());
    println!("Wire format embeds the version used for encryption.");
    println!("This enables key rotation: old ciphertext decrypts with old DEK,");
    println!("new ciphertext uses new DEK.\n");

    let ct = vault.encrypt_field("users", "name", b"Alice").await?;
    println!("Ciphertext: {:.30}...", ct);
    println!(
        "Starts with ek:1:v{}: {}",
        vault.current_version(),
        ct.starts_with(&format!("ek:1:v{}:", vault.current_version()))
    );

    // --- Deterministic encryption ---
    println!("\n--- Deterministic vs Randomized ---");
    let ct_rand1 = vault.encrypt_field("t", "c", b"same").await?;
    let ct_rand2 = vault.encrypt_field("t", "c", b"same").await?;
    println!(
        "Randomized (default): different each time = {}",
        ct_rand1 != ct_rand2
    );

    let ct_det1 = vault.encrypt_field_deterministic("t", "c", b"same").await?;
    let ct_det2 = vault.encrypt_field_deterministic("t", "c", b"same").await?;
    println!(
        "Deterministic (SIV):  same each time     = {}",
        ct_det1 == ct_det2
    );

    println!("\n=== Key derivation demo complete! ===");
    Ok(())
}
