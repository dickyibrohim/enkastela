//! SQL query analyzer for detecting encryption violations.
//!
//! Parses SQL using `sqlparser` and walks the AST to find operations that
//! bypass field encryption.

use sqlparser::ast::*;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use super::policy::{FirewallPolicy, Violation, ViolationKind};

/// Analyzes a SQL query against a firewall policy.
///
/// Returns a list of detected violations. An empty list means the query
/// is considered safe.
pub fn analyze_query(sql: &str, policy: &FirewallPolicy) -> Vec<Violation> {
    let dialect = PostgreSqlDialect {};
    let ast = match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => stmts,
        Err(_) => return vec![],
    };

    let mut violations = Vec::new();

    for stmt in &ast {
        match stmt {
            Statement::Query(query) => {
                analyze_select_query(query, policy, &mut violations);
            }
            Statement::Insert(insert) => {
                analyze_insert(insert, policy, &mut violations);
            }
            Statement::Update(update) => {
                analyze_update(update, policy, &mut violations);
            }
            _ => {}
        }
    }

    violations
}

/// Analyzes a SELECT query for violations.
fn analyze_select_query(query: &Query, policy: &FirewallPolicy, violations: &mut Vec<Violation>) {
    if let SetExpr::Select(select) = query.body.as_ref() {
        let tables = extract_table_names(select);

        // Check WHERE clause
        if let Some(ref selection) = select.selection {
            check_where_expr(selection, &tables, policy, violations);
        }

        // Check ORDER BY
        if let Some(ref order_by) = query.order_by {
            match &order_by.kind {
                OrderByKind::All(_) => {}
                OrderByKind::Expressions(exprs) => {
                    for expr in exprs {
                        if let Some((table, column)) = extract_column_ref(&expr.expr, &tables) {
                            if policy.is_encrypted(&table, &column) {
                                violations.push(Violation {
                                    kind: ViolationKind::EncryptedOrderBy,
                                    table: Some(table),
                                    column: Some(column),
                                    description:
                                        "ORDER BY on encrypted column is meaningless without ORE"
                                            .into(),
                                    action: policy.default_action.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check GROUP BY
        if let GroupByExpr::Expressions(exprs, _) = &select.group_by {
            for expr in exprs {
                if let Some((table, column)) = extract_column_ref(expr, &tables) {
                    if policy.is_encrypted(&table, &column) {
                        violations.push(Violation {
                            kind: ViolationKind::EncryptedGroupBy,
                            table: Some(table),
                            column: Some(column),
                            description: "GROUP BY on encrypted column will not group correctly"
                                .into(),
                            action: policy.default_action.clone(),
                        });
                    }
                }
            }
        }

        // Check JOINs
        for table_with_join in &select.from {
            for join in &table_with_join.joins {
                if let Some(JoinConstraint::On(expr)) = extract_join_constraint(&join.join_operator)
                {
                    check_join_expr(expr, &tables, policy, violations);
                }
            }
        }
    }
}

/// Extracts JoinConstraint from a JoinOperator.
fn extract_join_constraint(op: &JoinOperator) -> Option<&JoinConstraint> {
    match op {
        JoinOperator::Join(c)
        | JoinOperator::Inner(c)
        | JoinOperator::Left(c)
        | JoinOperator::LeftOuter(c)
        | JoinOperator::Right(c)
        | JoinOperator::RightOuter(c)
        | JoinOperator::FullOuter(c) => Some(c),
        _ => None,
    }
}

/// Checks WHERE expressions for violations.
fn check_where_expr(
    expr: &Expr,
    tables: &[(String, Option<String>)],
    policy: &FirewallPolicy,
    violations: &mut Vec<Violation>,
) {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            match op {
                BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq => {
                    // Check left = column, right = literal
                    if let Some((table, column)) = extract_column_ref(left, tables) {
                        if policy.is_encrypted(&table, &column) && is_literal(right) {
                            violations.push(Violation {
                                kind: ViolationKind::PlaintextComparison,
                                table: Some(table),
                                column: Some(column),
                                description: format!(
                                    "Comparing encrypted column with plaintext literal using {op}"
                                ),
                                action: policy.default_action.clone(),
                            });
                        }
                    }
                    // Check right = column, left = literal
                    if let Some((table, column)) = extract_column_ref(right, tables) {
                        if policy.is_encrypted(&table, &column) && is_literal(left) {
                            violations.push(Violation {
                                kind: ViolationKind::PlaintextComparison,
                                table: Some(table),
                                column: Some(column),
                                description: format!(
                                    "Comparing plaintext literal with encrypted column using {op}"
                                ),
                                action: policy.default_action.clone(),
                            });
                        }
                    }
                }
                BinaryOperator::And | BinaryOperator::Or => {
                    check_where_expr(left, tables, policy, violations);
                    check_where_expr(right, tables, policy, violations);
                }
                _ => {}
            }
        }
        Expr::Like { expr: col_expr, .. } | Expr::ILike { expr: col_expr, .. } => {
            if let Some((table, column)) = extract_column_ref(col_expr, tables) {
                if policy.is_encrypted(&table, &column) {
                    violations.push(Violation {
                        kind: ViolationKind::EncryptedLike,
                        table: Some(table),
                        column: Some(column),
                        description: "LIKE/ILIKE on encrypted column will never match correctly"
                            .into(),
                        action: policy.default_action.clone(),
                    });
                }
            }
        }
        _ => {}
    }
}

/// Checks JOIN conditions for encrypted column usage.
fn check_join_expr(
    expr: &Expr,
    tables: &[(String, Option<String>)],
    policy: &FirewallPolicy,
    violations: &mut Vec<Violation>,
) {
    if let Expr::BinaryOp {
        left,
        right,
        op: BinaryOperator::Eq,
    } = expr
    {
        if let (Some((t1, c1)), Some((t2, c2))) = (
            extract_column_ref(left, tables),
            extract_column_ref(right, tables),
        ) {
            if policy.is_encrypted(&t1, &c1) || policy.is_encrypted(&t2, &c2) {
                violations.push(Violation {
                    kind: ViolationKind::EncryptedJoin,
                    table: Some(format!("{t1}, {t2}")),
                    column: Some(format!("{c1}, {c2}")),
                    description:
                        "JOIN on encrypted column — ciphertexts are randomized and will never match"
                            .into(),
                    action: policy.default_action.clone(),
                });
            }
        }
    }
}

/// Analyzes INSERT for plaintext values into encrypted columns.
fn analyze_insert(insert: &Insert, policy: &FirewallPolicy, violations: &mut Vec<Violation>) {
    let table_name = match &insert.table {
        TableObject::TableName(name) => name.to_string().to_lowercase(),
        _ => return,
    };

    let columns: Vec<String> = insert
        .columns
        .iter()
        .map(|c| c.value.to_lowercase())
        .collect();

    if let Some(ref source) = insert.source {
        if let SetExpr::Values(values) = source.body.as_ref() {
            for row in &values.rows {
                for (i, val_expr) in row.iter().enumerate() {
                    if let Some(col_name) = columns.get(i) {
                        if policy.is_encrypted(&table_name, col_name)
                            && is_plaintext_literal(val_expr)
                        {
                            violations.push(Violation {
                                kind: ViolationKind::PlaintextInsert,
                                table: Some(table_name.clone()),
                                column: Some(col_name.clone()),
                                description: format!(
                                    "INSERT plaintext literal into encrypted column {table_name}.{col_name}"
                                ),
                                action: policy.default_action.clone(),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Analyzes UPDATE for violations.
fn analyze_update(update: &Update, policy: &FirewallPolicy, violations: &mut Vec<Violation>) {
    let table_name = extract_table_name_from_factor(&update.table.relation)
        .unwrap_or_default()
        .to_lowercase();

    for assignment in &update.assignments {
        let col_name = match &assignment.target {
            AssignmentTarget::ColumnName(name) => name.to_string().to_lowercase(),
            AssignmentTarget::Tuple(_) => continue,
        };
        if policy.is_encrypted(&table_name, &col_name) && is_plaintext_literal(&assignment.value) {
            violations.push(Violation {
                kind: ViolationKind::PlaintextInsert,
                table: Some(table_name.clone()),
                column: Some(col_name),
                description: "UPDATE encrypted column with plaintext literal".into(),
                action: policy.default_action.clone(),
            });
        }
    }

    if let Some(ref where_expr) = update.selection {
        let tables = vec![(table_name, None)];
        check_where_expr(where_expr, &tables, policy, violations);
    }
}

/// Extracts table names from FROM clause.
fn extract_table_names(select: &Select) -> Vec<(String, Option<String>)> {
    let mut tables = Vec::new();
    for from in &select.from {
        if let Some(name) = extract_table_name_from_factor(&from.relation) {
            let alias = extract_alias_from_factor(&from.relation);
            tables.push((name, alias));
        }
        for join in &from.joins {
            if let Some(name) = extract_table_name_from_factor(&join.relation) {
                let alias = extract_alias_from_factor(&join.relation);
                tables.push((name, alias));
            }
        }
    }
    tables
}

fn extract_table_name_from_factor(factor: &TableFactor) -> Option<String> {
    match factor {
        TableFactor::Table { name, .. } => Some(name.to_string().to_lowercase()),
        _ => None,
    }
}

fn extract_alias_from_factor(factor: &TableFactor) -> Option<String> {
    match factor {
        TableFactor::Table { alias, .. } => alias.as_ref().map(|a| a.name.value.to_lowercase()),
        _ => None,
    }
}

fn extract_column_ref(
    expr: &Expr,
    tables: &[(String, Option<String>)],
) -> Option<(String, String)> {
    match expr {
        Expr::Identifier(ident) => {
            let col = ident.value.to_lowercase();
            if tables.len() == 1 {
                Some((tables[0].0.clone(), col))
            } else {
                None
            }
        }
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            let qualifier = parts[0].value.to_lowercase();
            let col = parts[1].value.to_lowercase();
            for (table, alias) in tables {
                if *table == qualifier || alias.as_deref() == Some(&qualifier) {
                    return Some((table.clone(), col));
                }
            }
            Some((qualifier, col))
        }
        _ => None,
    }
}

fn is_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Value(ValueWithSpan { value, .. }) => !matches!(value, Value::Placeholder(_)),
        _ => false,
    }
}

fn is_plaintext_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Value(ValueWithSpan { value, .. }) => !matches!(value, Value::Placeholder(_)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::policy::FirewallPolicy;
    use super::*;

    fn test_policy() -> FirewallPolicy {
        let mut policy = FirewallPolicy::new();
        policy.add_encrypted_column("users", "email");
        policy.add_encrypted_column("users", "ssn");
        policy.add_encrypted_column("users", "phone");
        policy.add_encrypted_column("orders", "address");
        policy
    }

    #[test]
    fn detect_plaintext_comparison() {
        let policy = test_policy();
        let sql = "SELECT * FROM users WHERE email = 'alice@example.com'";
        let violations = analyze_query(sql, &policy);
        assert!(!violations.is_empty());
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::PlaintextComparison));
    }

    #[test]
    fn allow_parameterized_query() {
        let policy = test_policy();
        let sql = "SELECT * FROM users WHERE email = $1";
        let violations = analyze_query(sql, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn detect_plaintext_insert() {
        let policy = test_policy();
        let sql = "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')";
        let violations = analyze_query(sql, &policy);
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::PlaintextInsert));
    }

    #[test]
    fn allow_parameterized_insert() {
        let policy = test_policy();
        let sql = "INSERT INTO users (name, email) VALUES ($1, $2)";
        let violations = analyze_query(sql, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn detect_like_on_encrypted() {
        let policy = test_policy();
        let sql = "SELECT * FROM users WHERE email LIKE '%example%'";
        let violations = analyze_query(sql, &policy);
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::EncryptedLike));
    }

    #[test]
    fn detect_order_by_encrypted() {
        let policy = test_policy();
        let sql = "SELECT * FROM users ORDER BY email";
        let violations = analyze_query(sql, &policy);
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::EncryptedOrderBy));
    }

    #[test]
    fn detect_group_by_encrypted() {
        let policy = test_policy();
        let sql = "SELECT email, COUNT(*) FROM users GROUP BY email";
        let violations = analyze_query(sql, &policy);
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::EncryptedGroupBy));
    }

    #[test]
    fn detect_join_on_encrypted() {
        let policy = test_policy();
        let sql = "SELECT * FROM users u JOIN orders o ON u.email = o.address";
        let violations = analyze_query(sql, &policy);
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::EncryptedJoin));
    }

    #[test]
    fn allow_non_encrypted_column() {
        let policy = test_policy();
        let sql = "SELECT * FROM users WHERE name = 'Alice' ORDER BY name";
        let violations = analyze_query(sql, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn detect_update_with_plaintext() {
        let policy = test_policy();
        let sql = "UPDATE users SET email = 'new@example.com' WHERE id = 1";
        let violations = analyze_query(sql, &policy);
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::PlaintextInsert));
    }

    #[test]
    fn detect_multiple_violations() {
        let policy = test_policy();
        let sql = "SELECT * FROM users WHERE email = 'test@x.com' AND ssn = '123' ORDER BY phone";
        let violations = analyze_query(sql, &policy);
        assert!(violations.len() >= 3);
    }

    #[test]
    fn detect_comparison_both_sides() {
        let policy = test_policy();
        let sql = "SELECT * FROM users WHERE 'alice@example.com' = email";
        let violations = analyze_query(sql, &policy);
        assert!(violations
            .iter()
            .any(|v| v.kind == ViolationKind::PlaintextComparison));
    }

    #[test]
    fn unparseable_sql_returns_empty() {
        let policy = test_policy();
        let sql = "THIS IS NOT SQL AT ALL !!!";
        let violations = analyze_query(sql, &policy);
        assert!(violations.is_empty());
    }
}
