//! Compliance report generation.
//!
//! Generates JSON-serializable reports mapping encryption controls to
//! compliance standards (SOC2, GDPR, HIPAA).

use serde::{Deserialize, Serialize};

/// Supported compliance standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Standard {
    /// SOC 2 Type II
    SOC2,
    /// EU General Data Protection Regulation
    GDPR,
    /// Health Insurance Portability and Accountability Act
    HIPAA,
}

impl std::fmt::Display for Standard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Standard::SOC2 => write!(f, "SOC 2 Type II"),
            Standard::GDPR => write!(f, "GDPR"),
            Standard::HIPAA => write!(f, "HIPAA"),
        }
    }
}

/// Status of a compliance control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlStatus {
    /// Control is fully implemented and active.
    Implemented,
    /// Control is partially implemented.
    Partial(String),
    /// Control is not implemented.
    NotImplemented,
}

/// A single compliance control mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMapping {
    /// Control identifier (e.g., "CC6.1" for SOC2).
    pub control_id: String,
    /// Human-readable control description.
    pub description: String,
    /// How Enkastela satisfies this control.
    pub enkastela_implementation: String,
    /// Current status.
    pub status: ControlStatus,
}

/// A complete compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Standard being reported against.
    pub standard: Standard,
    /// Report generation timestamp.
    pub generated_at: String,
    /// Enkastela version.
    pub enkastela_version: String,
    /// Control mappings.
    pub controls: Vec<ControlMapping>,
    /// Summary statistics.
    pub summary: ReportSummary,
}

/// Summary of control implementation status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_controls: usize,
    pub implemented: usize,
    pub partial: usize,
    pub not_implemented: usize,
}

/// Configuration for report generation.
pub struct ReportConfig {
    /// Whether audit logging is enabled.
    pub audit_enabled: bool,
    /// Whether key rotation is configured.
    pub rotation_configured: bool,
    /// Whether TLS is enforced.
    pub tls_enforced: bool,
    /// Whether crypto-shredding (GDPR erasure) is available.
    pub crypto_shredding: bool,
    /// Whether FIPS mode is active.
    pub fips_mode: bool,
    /// Whether access control is configured.
    pub access_control: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            audit_enabled: true,
            rotation_configured: false,
            tls_enforced: true,
            crypto_shredding: true,
            fips_mode: false,
            access_control: false,
        }
    }
}

/// Generates a compliance report for the specified standard.
pub fn generate_report(standard: Standard, config: &ReportConfig) -> ComplianceReport {
    let controls = match standard {
        Standard::SOC2 => generate_soc2_controls(config),
        Standard::GDPR => generate_gdpr_controls(config),
        Standard::HIPAA => generate_hipaa_controls(config),
    };

    let summary = ReportSummary {
        total_controls: controls.len(),
        implemented: controls
            .iter()
            .filter(|c| matches!(c.status, ControlStatus::Implemented))
            .count(),
        partial: controls
            .iter()
            .filter(|c| matches!(c.status, ControlStatus::Partial(_)))
            .count(),
        not_implemented: controls
            .iter()
            .filter(|c| matches!(c.status, ControlStatus::NotImplemented))
            .count(),
    };

    ComplianceReport {
        standard,
        generated_at: chrono::Utc::now().to_rfc3339(),
        enkastela_version: env!("CARGO_PKG_VERSION").to_string(),
        controls,
        summary,
    }
}

fn generate_soc2_controls(config: &ReportConfig) -> Vec<ControlMapping> {
    vec![
        ControlMapping {
            control_id: "CC6.1".into(),
            description: "Logical and physical access controls".into(),
            enkastela_implementation: "Field-level encryption with AES-256-GCM ensures data is protected at rest. Each field is independently encrypted with unique DEKs.".into(),
            status: ControlStatus::Implemented,
        },
        ControlMapping {
            control_id: "CC6.6".into(),
            description: "Encryption of data in transit and at rest".into(),
            enkastela_implementation: if config.tls_enforced {
                "TLS enforced for database connections. AES-256-GCM for data at rest.".into()
            } else {
                "AES-256-GCM for data at rest. TLS not enforced.".into()
            },
            status: if config.tls_enforced {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("TLS not enforced for database connections".into())
            },
        },
        ControlMapping {
            control_id: "CC6.7".into(),
            description: "Encryption key management".into(),
            enkastela_implementation: "HKDF-SHA256 key derivation with per-table DEKs. AES-256 key wrapping. Optional cloud KMS integration.".into(),
            status: ControlStatus::Implemented,
        },
        ControlMapping {
            control_id: "CC7.2".into(),
            description: "Monitoring of system components".into(),
            enkastela_implementation: if config.audit_enabled {
                "HMAC-chained audit trail for all encrypt/decrypt operations.".into()
            } else {
                "Audit logging available but not enabled.".into()
            },
            status: if config.audit_enabled {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("Audit logging not enabled".into())
            },
        },
        ControlMapping {
            control_id: "CC8.1".into(),
            description: "Change management".into(),
            enkastela_implementation: "Key version tracking with rotation support. Old versions remain accessible for decryption.".into(),
            status: if config.rotation_configured {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("Key rotation not configured".into())
            },
        },
    ]
}

fn generate_gdpr_controls(config: &ReportConfig) -> Vec<ControlMapping> {
    vec![
        ControlMapping {
            control_id: "Art. 5(1)(f)".into(),
            description: "Integrity and confidentiality".into(),
            enkastela_implementation: "AES-256-GCM authenticated encryption with AAD binding prevents unauthorized access and tampering.".into(),
            status: ControlStatus::Implemented,
        },
        ControlMapping {
            control_id: "Art. 17".into(),
            description: "Right to erasure (right to be forgotten)".into(),
            enkastela_implementation: if config.crypto_shredding {
                "Crypto-shredding: destroy tenant key to make all encrypted data irrecoverable. Erasure receipt with cryptographic proof.".into()
            } else {
                "Crypto-shredding available but not configured.".into()
            },
            status: if config.crypto_shredding {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("Crypto-shredding not configured".into())
            },
        },
        ControlMapping {
            control_id: "Art. 20".into(),
            description: "Right to data portability".into(),
            enkastela_implementation: "GDPR export module generates structured JSON with all encrypted fields decrypted for the data subject.".into(),
            status: ControlStatus::Implemented,
        },
        ControlMapping {
            control_id: "Art. 25".into(),
            description: "Data protection by design and by default".into(),
            enkastela_implementation: "Encryption is applied at the field level by default. Blind indexes enable search without exposing plaintext.".into(),
            status: ControlStatus::Implemented,
        },
        ControlMapping {
            control_id: "Art. 32".into(),
            description: "Security of processing".into(),
            enkastela_implementation: "AES-256-GCM (NIST-approved), HKDF-SHA256 key derivation, constant-time comparisons, automatic key zeroization.".into(),
            status: ControlStatus::Implemented,
        },
        ControlMapping {
            control_id: "Art. 33".into(),
            description: "Notification of breach to supervisory authority".into(),
            enkastela_implementation: if config.audit_enabled {
                "Tamper-evident audit trail with HMAC chain integrity verification. Intrusion detection via poison records.".into()
            } else {
                "Audit logging available but not enabled.".into()
            },
            status: if config.audit_enabled {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("Audit logging not enabled".into())
            },
        },
    ]
}

fn generate_hipaa_controls(config: &ReportConfig) -> Vec<ControlMapping> {
    vec![
        ControlMapping {
            control_id: "§164.312(a)(2)(iv)".into(),
            description: "Encryption and decryption".into(),
            enkastela_implementation: if config.fips_mode {
                "AES-256-GCM via FIPS-140-2 validated backend (aws-lc-rs).".into()
            } else {
                "AES-256-GCM via audited RustCrypto. FIPS mode available but not active.".into()
            },
            status: if config.fips_mode {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("FIPS-140 mode not active".into())
            },
        },
        ControlMapping {
            control_id: "§164.312(b)".into(),
            description: "Audit controls".into(),
            enkastela_implementation: if config.audit_enabled {
                "Comprehensive audit trail with HMAC integrity chain for all encryption operations.".into()
            } else {
                "Audit capability available but not enabled.".into()
            },
            status: if config.audit_enabled {
                ControlStatus::Implemented
            } else {
                ControlStatus::NotImplemented
            },
        },
        ControlMapping {
            control_id: "§164.312(c)(1)".into(),
            description: "Integrity".into(),
            enkastela_implementation: "AES-256-GCM provides authenticated encryption — any tampering is detected during decryption.".into(),
            status: ControlStatus::Implemented,
        },
        ControlMapping {
            control_id: "§164.312(d)".into(),
            description: "Person or entity authentication".into(),
            enkastela_implementation: if config.access_control {
                "Field-level access control with role-based permissions.".into()
            } else {
                "Access control available but not configured.".into()
            },
            status: if config.access_control {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("Access control not configured".into())
            },
        },
        ControlMapping {
            control_id: "§164.312(e)(1)".into(),
            description: "Transmission security".into(),
            enkastela_implementation: if config.tls_enforced {
                "TLS required for all database connections.".into()
            } else {
                "TLS available but not enforced.".into()
            },
            status: if config.tls_enforced {
                ControlStatus::Implemented
            } else {
                ControlStatus::Partial("TLS not enforced".into())
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_soc2_report() {
        let config = ReportConfig::default();
        let report = generate_report(Standard::SOC2, &config);

        assert_eq!(report.standard, Standard::SOC2);
        assert!(!report.controls.is_empty());
        assert!(report.summary.total_controls > 0);
        assert!(report.summary.implemented > 0);
    }

    #[test]
    fn generate_gdpr_report() {
        let config = ReportConfig::default();
        let report = generate_report(Standard::GDPR, &config);

        assert_eq!(report.standard, Standard::GDPR);
        assert!(report.controls.len() >= 5);
        // With default config (audit=true, shredding=true), most should be implemented
        assert!(report.summary.implemented >= 4);
    }

    #[test]
    fn generate_hipaa_report() {
        let config = ReportConfig {
            fips_mode: true,
            audit_enabled: true,
            access_control: true,
            ..Default::default()
        };
        let report = generate_report(Standard::HIPAA, &config);

        assert_eq!(report.standard, Standard::HIPAA);
        assert!(report.summary.implemented >= 4);
    }

    #[test]
    fn report_reflects_config() {
        let config = ReportConfig {
            audit_enabled: false,
            tls_enforced: false,
            fips_mode: false,
            ..Default::default()
        };
        let report = generate_report(Standard::SOC2, &config);

        // Should have some partial/not implemented
        assert!(report.summary.partial > 0 || report.summary.not_implemented > 0);
    }

    #[test]
    fn report_serializes_to_json() {
        let config = ReportConfig::default();
        let report = generate_report(Standard::GDPR, &config);

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("GDPR"));
        assert!(json.contains("controls"));

        // Roundtrip
        let _: ComplianceReport = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn standard_display() {
        assert_eq!(format!("{}", Standard::SOC2), "SOC 2 Type II");
        assert_eq!(format!("{}", Standard::GDPR), "GDPR");
        assert_eq!(format!("{}", Standard::HIPAA), "HIPAA");
    }
}
