//! Access control policy definitions.

use std::collections::{HashMap, HashSet};

/// A field identifier as (table, column).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldId {
    pub table: String,
    pub column: String,
}

impl FieldId {
    pub fn new(table: &str, column: &str) -> Self {
        Self {
            table: table.to_lowercase(),
            column: column.to_lowercase(),
        }
    }
}

/// Permission level for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Can read plaintext (decrypt).
    Decrypt,
    /// Can write ciphertext (encrypt).
    Encrypt,
    /// Full access (encrypt + decrypt).
    Full,
    /// No access.
    Deny,
}

/// Access control policy mapping roles to field permissions.
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    /// Role → set of (field, permission) grants.
    grants: HashMap<String, HashMap<FieldId, Permission>>,
    /// Roles with wildcard (all fields) access.
    admin_roles: HashSet<String>,
}

impl AccessPolicy {
    /// Creates an empty access policy.
    pub fn new() -> Self {
        Self {
            grants: HashMap::new(),
            admin_roles: HashSet::new(),
        }
    }

    /// Grants a permission to a role for a specific field.
    pub fn grant(&mut self, role: &str, table: &str, column: &str, permission: Permission) {
        let field = FieldId::new(table, column);
        self.grants
            .entry(role.to_lowercase())
            .or_default()
            .insert(field, permission);
    }

    /// Grants admin access to a role (all fields, all permissions).
    pub fn grant_admin(&mut self, role: &str) {
        self.admin_roles.insert(role.to_lowercase());
    }

    /// Checks if a role has the required permission for a field.
    pub fn check(&self, role: &str, table: &str, column: &str, required: Permission) -> bool {
        let role_lower = role.to_lowercase();

        // Admin roles have all permissions
        if self.admin_roles.contains(&role_lower) {
            return true;
        }

        let field = FieldId::new(table, column);
        if let Some(role_grants) = self.grants.get(&role_lower) {
            if let Some(granted) = role_grants.get(&field) {
                return matches!(
                    (granted, required),
                    (Permission::Full, _)
                        | (Permission::Decrypt, Permission::Decrypt)
                        | (Permission::Encrypt, Permission::Encrypt)
                );
            }
        }

        false
    }

    /// Checks if a role can decrypt a field.
    pub fn can_decrypt(&self, role: &str, table: &str, column: &str) -> bool {
        self.check(role, table, column, Permission::Decrypt)
    }

    /// Checks if a role can encrypt a field.
    pub fn can_encrypt(&self, role: &str, table: &str, column: &str) -> bool {
        self.check(role, table, column, Permission::Encrypt)
    }

    /// Returns all fields a role can decrypt.
    pub fn decryptable_fields(&self, role: &str) -> Vec<FieldId> {
        let role_lower = role.to_lowercase();
        if let Some(grants) = self.grants.get(&role_lower) {
            grants
                .iter()
                .filter(|(_, perm)| matches!(perm, Permission::Decrypt | Permission::Full))
                .map(|(field, _)| field.clone())
                .collect()
        } else {
            vec![]
        }
    }
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_and_check_decrypt() {
        let mut policy = AccessPolicy::new();
        policy.grant("support", "users", "name", Permission::Decrypt);

        assert!(policy.can_decrypt("support", "users", "name"));
        assert!(!policy.can_decrypt("support", "users", "ssn"));
        assert!(!policy.can_encrypt("support", "users", "name"));
    }

    #[test]
    fn grant_full_access() {
        let mut policy = AccessPolicy::new();
        policy.grant("admin", "users", "ssn", Permission::Full);

        assert!(policy.can_decrypt("admin", "users", "ssn"));
        assert!(policy.can_encrypt("admin", "users", "ssn"));
    }

    #[test]
    fn admin_role_has_all_access() {
        let mut policy = AccessPolicy::new();
        policy.grant_admin("superadmin");

        assert!(policy.can_decrypt("superadmin", "any_table", "any_column"));
        assert!(policy.can_encrypt("superadmin", "any_table", "any_column"));
    }

    #[test]
    fn unknown_role_denied() {
        let policy = AccessPolicy::new();
        assert!(!policy.can_decrypt("unknown", "users", "email"));
    }

    #[test]
    fn case_insensitive() {
        let mut policy = AccessPolicy::new();
        policy.grant("Support", "Users", "Email", Permission::Decrypt);

        assert!(policy.can_decrypt("support", "users", "email"));
        assert!(policy.can_decrypt("SUPPORT", "USERS", "EMAIL"));
    }

    #[test]
    fn encrypt_only_cannot_decrypt() {
        let mut policy = AccessPolicy::new();
        policy.grant("writer", "users", "email", Permission::Encrypt);

        assert!(policy.can_encrypt("writer", "users", "email"));
        assert!(!policy.can_decrypt("writer", "users", "email"));
    }

    #[test]
    fn decryptable_fields_list() {
        let mut policy = AccessPolicy::new();
        policy.grant("support", "users", "name", Permission::Decrypt);
        policy.grant("support", "users", "email", Permission::Full);
        policy.grant("support", "users", "ssn", Permission::Encrypt);

        let fields = policy.decryptable_fields("support");
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn multiple_roles_independent() {
        let mut policy = AccessPolicy::new();
        policy.grant("role_a", "users", "email", Permission::Decrypt);
        policy.grant("role_b", "users", "ssn", Permission::Decrypt);

        assert!(policy.can_decrypt("role_a", "users", "email"));
        assert!(!policy.can_decrypt("role_a", "users", "ssn"));
        assert!(!policy.can_decrypt("role_b", "users", "email"));
        assert!(policy.can_decrypt("role_b", "users", "ssn"));
    }
}
