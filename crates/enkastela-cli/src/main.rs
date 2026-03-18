//! Enkastela CLI — operational tooling for field encryption management.

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, Subcommand};
use enkastela::{SecretKey, Vault};

#[derive(Parser)]
#[command(
    name = "enkastela",
    about = "Application-level field encryption for PostgreSQL",
    version,
    long_about = "Enkastela provides application-level field encryption for PostgreSQL.\nAll sensitive data is encrypted at the application layer — the database never sees plaintext."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new master key (base64-encoded, 32 bytes)
    Keygen,

    /// Encrypt a plaintext value (for testing/debugging)
    Encrypt {
        /// Table name
        #[arg(long)]
        table: String,
        /// Column name
        #[arg(long)]
        column: String,
        /// Plaintext value to encrypt
        #[arg(long)]
        value: String,
        /// Master key (base64-encoded). If not provided, reads ENKASTELA_MASTER_KEY env var
        #[arg(long, env = "ENKASTELA_MASTER_KEY")]
        key: String,
    },

    /// Decrypt a ciphertext value (for testing/debugging)
    Decrypt {
        /// Table name
        #[arg(long)]
        table: String,
        /// Column name
        #[arg(long)]
        column: String,
        /// Ciphertext (wire format) to decrypt
        #[arg(long)]
        value: String,
        /// Master key (base64-encoded). If not provided, reads ENKASTELA_MASTER_KEY env var
        #[arg(long, env = "ENKASTELA_MASTER_KEY")]
        key: String,
    },

    /// Check if a value is enkastela-encrypted
    Check {
        /// Value to check
        value: String,
    },
}

fn parse_key(b64: &str) -> Result<SecretKey, String> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| format!("invalid base64 key: {e}"))?;
    SecretKey::from_slice(&bytes).ok_or_else(|| "master key must be exactly 32 bytes".to_string())
}

/// Derives a deterministic salt from the master key bytes.
///
/// The CLI needs a stable salt so that encrypt and decrypt commands
/// (which create separate Vault instances) derive the same DEKs.
/// In production with a database, the salt is stored in the DB.
fn derive_cli_salt(key: &SecretKey) -> [u8; 32] {
    use enkastela::crypto::kdf;
    let salt_key = kdf::derive_key(key, &[0u8; 32], b"enkastela:cli:salt:v1")
        .expect("salt derivation should not fail");
    let mut salt = [0u8; 32];
    salt.copy_from_slice(salt_key.as_bytes());
    salt
}

async fn build_vault(key_b64: &str) -> Vault {
    let secret_key = match parse_key(key_b64) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    let salt = derive_cli_salt(&secret_key);
    Vault::builder()
        .master_key_static(secret_key)
        .dek_salt(salt)
        .allow_insecure_connection()
        .build()
        .await
        .unwrap_or_else(|e| {
            eprintln!("Error building vault: {e}");
            std::process::exit(1);
        })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            let mut key_bytes = [0u8; 32];
            rand::fill(&mut key_bytes);
            let encoded = STANDARD.encode(key_bytes);
            println!("{encoded}");
        }

        Commands::Encrypt {
            table,
            column,
            value,
            key,
        } => {
            let vault = build_vault(&key).await;
            match vault.encrypt_field(&table, &column, value.as_bytes()).await {
                Ok(ct) => println!("{ct}"),
                Err(e) => {
                    eprintln!("Encryption failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Decrypt {
            table,
            column,
            value,
            key,
        } => {
            let vault = build_vault(&key).await;
            match vault.decrypt_field(&table, &column, &value).await {
                Ok(pt) => {
                    let text = String::from_utf8_lossy(&pt);
                    println!("{text}");
                }
                Err(e) => {
                    eprintln!("Decryption failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Check { value } => {
            if Vault::is_encrypted(&value) {
                println!("Encrypted (enkastela wire format detected)");
            } else {
                println!("Not encrypted");
            }
        }
    }
}
