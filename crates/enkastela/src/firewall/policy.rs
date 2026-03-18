//! Firewall policy definitions.
//!
//! Defines which columns are encrypted and what actions to take on violations.

use std::collections::HashSet;

/// Action to take when a violation is detected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ViolationAction {
    /// Log a warning but allow the query.
    #[default]
    Warn,
    /// Block the query (return error).
    Deny,
    /// Log and alert (via audit trail).
    Alert,
}

/// A detected SQL firewall violation.
#[derive(Debug, Clone)]
pub struct Violation {
    /// Type of violation.
    pub kind: ViolationKind,
    /// Table involved.
    pub table: Option<String>,
    /// Column involved.
    pub column: Option<String>,
    /// Description of the violation.
    pub description: String,
    /// Configured action.
    pub action: ViolationAction,
}

/// Types of SQL encryption violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// Direct SELECT on encrypted column without Vault.
    DirectRead,
    /// INSERT plaintext into encrypted column.
    PlaintextInsert,
    /// WHERE comparison with plaintext literal on encrypted column.
    PlaintextComparison,
    /// JOIN on encrypted column.
    EncryptedJoin,
    /// ORDER BY on encrypted column (meaningless without ORE).
    EncryptedOrderBy,
    /// GROUP BY on encrypted column.
    EncryptedGroupBy,
    /// LIKE/ILIKE on encrypted column.
    EncryptedLike,
    /// Aggregate function on encrypted column.
    EncryptedAggregate,
}

impl std::fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationKind::DirectRead => write!(f, "direct_read"),
            ViolationKind::PlaintextInsert => write!(f, "plaintext_insert"),
            ViolationKind::PlaintextComparison => write!(f, "plaintext_comparison"),
            ViolationKind::EncryptedJoin => write!(f, "encrypted_join"),
            ViolationKind::EncryptedOrderBy => write!(f, "encrypted_order_by"),
            ViolationKind::EncryptedGroupBy => write!(f, "encrypted_group_by"),
            ViolationKind::EncryptedLike => write!(f, "encrypted_like"),
            ViolationKind::EncryptedAggregate => write!(f, "encrypted_aggregate"),
        }
    }
}

/// Firewall policy defining which columns are encrypted.
#[derive(Debug, Clone)]
pub struct FirewallPolicy {
    /// Set of encrypted columns as "table.column" identifiers.
    encrypted_columns: HashSet<String>,
    /// Default action for violations.
    pub default_action: ViolationAction,
}

impl FirewallPolicy {
    /// Creates a new empty firewall policy.
    pub fn new() -> Self {
        Self {
            encrypted_columns: HashSet::new(),
            default_action: ViolationAction::Warn,
        }
    }

    /// Registers a column as encrypted.
    pub fn add_encrypted_column(&mut self, table: &str, column: &str) {
        self.encrypted_columns.insert(format!(
            "{}.{}",
            table.to_lowercase(),
            column.to_lowercase()
        ));
    }

    /// Checks if a column is registered as encrypted.
    pub fn is_encrypted(&self, table: &str, column: &str) -> bool {
        self.encrypted_columns.contains(&format!(
            "{}.{}",
            table.to_lowercase(),
            column.to_lowercase()
        ))
    }

    /// Sets the default violation action.
    pub fn set_default_action(&mut self, action: ViolationAction) {
        self.default_action = action;
    }

    /// Returns all registered encrypted columns.
    pub fn encrypted_columns(&self) -> &HashSet<String> {
        &self.encrypted_columns
    }
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_add_and_check() {
        let mut policy = FirewallPolicy::new();
        policy.add_encrypted_column("users", "email");
        policy.add_encrypted_column("users", "ssn");

        assert!(policy.is_encrypted("users", "email"));
        assert!(policy.is_encrypted("users", "ssn"));
        assert!(!policy.is_encrypted("users", "name"));
        assert!(!policy.is_encrypted("orders", "email"));
    }

    #[test]
    fn policy_case_insensitive() {
        let mut policy = FirewallPolicy::new();
        policy.add_encrypted_column("Users", "Email");

        assert!(policy.is_encrypted("users", "email"));
        assert!(policy.is_encrypted("USERS", "EMAIL"));
    }

    #[test]
    fn violation_kind_display() {
        assert_eq!(format!("{}", ViolationKind::DirectRead), "direct_read");
        assert_eq!(
            format!("{}", ViolationKind::PlaintextInsert),
            "plaintext_insert"
        );
        assert_eq!(
            format!("{}", ViolationKind::EncryptedLike),
            "encrypted_like"
        );
    }
}
