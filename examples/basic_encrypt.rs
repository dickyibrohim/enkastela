//! Basic encryption/decryption example.
//!
//! Run with:
//! ```sh
//! cargo run --example basic_encrypt
//! ```

use enkastela::{SecretKey, Vault};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a test key (in production, use Vault::builder().master_key_from_env())
    let key = SecretKey::from_bytes([0x42; 32]);

    let vault = Vault::builder()
        .master_key_static(key)
        .allow_insecure_connection()
        .build()
        .await?;

    println!("=== Enkastela Basic Encryption Example ===\n");

    // --- Encrypt fields ---
    let email = "alice@example.com";
    let phone = "+1-555-0123";
    let ssn = "123-45-6789";

    let encrypted_email = vault
        .encrypt_field("users", "email", email.as_bytes())
        .await?;
    let encrypted_phone = vault
        .encrypt_field("users", "phone", phone.as_bytes())
        .await?;
    let encrypted_ssn = vault.encrypt_field("users", "ssn", ssn.as_bytes()).await?;

    println!("Original email:    {email}");
    println!("Encrypted email:   {encrypted_email}\n");
    println!("Original phone:    {phone}");
    println!("Encrypted phone:   {encrypted_phone}\n");
    println!("Original SSN:      {ssn}");
    println!("Encrypted SSN:     {encrypted_ssn}\n");

    // --- Decrypt fields ---
    let decrypted_email = vault
        .decrypt_field("users", "email", &encrypted_email)
        .await?;
    let decrypted_phone = vault
        .decrypt_field("users", "phone", &encrypted_phone)
        .await?;
    let decrypted_ssn = vault.decrypt_field("users", "ssn", &encrypted_ssn).await?;

    println!(
        "Decrypted email:   {}",
        String::from_utf8_lossy(&decrypted_email)
    );
    println!(
        "Decrypted phone:   {}",
        String::from_utf8_lossy(&decrypted_phone)
    );
    println!(
        "Decrypted SSN:     {}",
        String::from_utf8_lossy(&decrypted_ssn)
    );

    // --- Verify is_encrypted ---
    println!("\n--- Encryption Detection ---");
    println!(
        "Is '{}' encrypted? {}",
        &encrypted_email[..30],
        Vault::is_encrypted(&encrypted_email)
    );
    println!("Is 'hello' encrypted? {}", Vault::is_encrypted("hello"));

    // --- Demonstrate AAD binding (wrong table/column fails) ---
    println!("\n--- AAD Binding Security ---");
    let result = vault
        .decrypt_field("orders", "email", &encrypted_email)
        .await;
    println!(
        "Decrypt with wrong table: {}",
        if result.is_err() {
            "REJECTED (correct!)"
        } else {
            "accepted (BAD!)"
        }
    );

    let result = vault
        .decrypt_field("users", "phone", &encrypted_email)
        .await;
    println!(
        "Decrypt with wrong column: {}",
        if result.is_err() {
            "REJECTED (correct!)"
        } else {
            "accepted (BAD!)"
        }
    );

    // --- Randomized encryption ---
    println!("\n--- Randomized Encryption ---");
    let ct1 = vault.encrypt_field("t", "c", b"same").await?;
    let ct2 = vault.encrypt_field("t", "c", b"same").await?;
    println!("Same plaintext, different ciphertext: {}", ct1 != ct2);

    // --- Blind index for searchable encryption ---
    println!("\n--- Blind Index (Searchable Encryption) ---");
    let idx1 = vault.compute_blind_index("users", "email", b"alice@example.com")?;
    let idx2 = vault.compute_blind_index("users", "email", b"alice@example.com")?;
    let idx3 = vault.compute_blind_index("users", "email", b"bob@example.com")?;
    println!("Index for alice (1): {}", hex::encode(idx1));
    println!("Index for alice (2): {}", hex::encode(idx2));
    println!("Same? {}", idx1 == idx2);
    println!("Index for bob:       {}", hex::encode(idx3));
    println!("Different? {}", idx1 != idx3);

    println!("\n=== All operations completed successfully! ===");
    Ok(())
}

mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
