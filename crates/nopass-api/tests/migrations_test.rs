use sqlx::PgPool;

/// Constraints are added NOT VALID so the migration doesn't hold a long lock;
/// the guarantee is that a later migration validates them, so they cover the
/// rows that existed before.
#[sqlx::test(migrations = "src/db/migrations")]
async fn deferred_constraints_are_validated(pool: PgPool) {
    let unvalidated: Vec<String> =
        sqlx::query_scalar("SELECT conname::text FROM pg_constraint WHERE NOT convalidated")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(unvalidated.is_empty(), "constraints left NOT VALID: {unvalidated:?}");
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn concurrently_built_indexes_are_valid(pool: PgPool) {
    let indexes = [
        "sessions_device_id",
        "users_email_hash_unkeyed",
        "pending_srp_user",
        "vault_items_pkey",
    ];
    for name in indexes {
        let valid: Option<bool> = sqlx::query_scalar(
            "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = $1",
        )
        .bind(name)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(valid, Some(true), "index {name} missing or invalid");
    }
}
