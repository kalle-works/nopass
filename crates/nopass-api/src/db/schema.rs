use anyhow::{bail, Result};
use sqlx::PgPool;

/// Names of indexes in the current schema that Postgres marked INVALID,
/// typically the leftover of an interrupted `CREATE INDEX CONCURRENTLY`.
pub async fn invalid_indexes(pool: &PgPool) -> Result<Vec<String>> {
    let names = sqlx::query_scalar::<_, String>(
        r#"
        SELECT c.relname::text
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        WHERE NOT i.indisvalid AND c.relnamespace = current_schema()::regnamespace
        ORDER BY c.relname
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(names)
}

/// Refuse to serve on a schema with an invalid index: queries would silently
/// skip it, and a unique index that never finished enforces nothing.
pub async fn ensure_indexes_valid(pool: &PgPool) -> Result<()> {
    let invalid = invalid_indexes(pool).await?;
    if !invalid.is_empty() {
        bail!(
            "invalid indexes left by an interrupted build: {}. Drop each with DROP INDEX CONCURRENTLY <name>, then restart so its migration rebuilds it",
            invalid.join(", ")
        );
    }
    Ok(())
}
