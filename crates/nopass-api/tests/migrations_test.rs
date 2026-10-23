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

const DROP_SESSIONS_INDEX: &str = include_str!("../src/db/migrations/019_drop_sessions_device_index.sql");
const CREATE_SESSIONS_INDEX: &str = include_str!("../src/db/migrations/020_sessions_device_index.sql");

/// An interrupted CONCURRENTLY build leaves an INVALID index with the final
/// name. The drop-then-create pair must rebuild it; the create alone must not
/// pretend it is fine (it fails on the existing name rather than skipping).
#[sqlx::test(migrations = "src/db/migrations")]
async fn rerunning_an_interrupted_index_build_recovers(pool: PgPool) {
    sqlx::query("UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'sessions_device_id'::regclass")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(nopass_api::db::schema::invalid_indexes(&pool).await.unwrap(), ["sessions_device_id"]);

    assert!(sqlx::raw_sql(CREATE_SESSIONS_INDEX).execute(&pool).await.is_err());

    sqlx::raw_sql(DROP_SESSIONS_INDEX).execute(&pool).await.unwrap();
    sqlx::raw_sql(CREATE_SESSIONS_INDEX).execute(&pool).await.unwrap();
    assert!(nopass_api::db::schema::invalid_indexes(&pool).await.unwrap().is_empty());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn startup_refuses_an_invalid_index_and_names_it(pool: PgPool) {
    nopass_api::db::schema::ensure_indexes_valid(&pool).await.unwrap();

    // A real failed CONCURRENTLY build: unique index over duplicate data
    sqlx::raw_sql("CREATE TABLE dup (a INT); INSERT INTO dup VALUES (1), (1);")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::raw_sql("CREATE UNIQUE INDEX CONCURRENTLY dup_a ON dup(a)").execute(&pool).await.is_err());

    let err = nopass_api::db::schema::ensure_indexes_valid(&pool).await.unwrap_err();
    assert!(err.to_string().contains("dup_a"), "{err}");
}
