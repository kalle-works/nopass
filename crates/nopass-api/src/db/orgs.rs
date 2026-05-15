use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::org::{OrgMember, OrgMemberResponse, OrgSummaryResponse, Organization};

pub async fn create_org(
    pool: &PgPool,
    name: &str,
    created_by: Uuid,
    encrypted_org_key: &str,
) -> Result<Organization> {
    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (name, created_by) VALUES ($1, $2) RETURNING *",
    )
    .bind(name)
    .bind(created_by)
    .fetch_one(pool)
    .await?;

    // Add creator as active owner
    sqlx::query(
        r#"INSERT INTO organization_members
           (org_id, user_id, role, status, encrypted_org_key, joined_at)
           VALUES ($1, $2, 'owner', 'active', $3, NOW())"#,
    )
    .bind(org.id)
    .bind(created_by)
    .bind(encrypted_org_key)
    .execute(pool)
    .await?;

    Ok(org)
}

pub async fn list_orgs_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<OrgSummaryResponse>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, i64, chrono::DateTime<chrono::Utc>)>(
        r#"SELECT o.id, o.name, m.role,
                  (SELECT COUNT(*) FROM organization_members WHERE org_id = o.id AND status = 'active') as member_count,
                  o.created_at
           FROM organizations o
           JOIN organization_members m ON m.org_id = o.id AND m.user_id = $1
           WHERE m.status = 'active'
           ORDER BY o.created_at"#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, name, role, member_count, created_at)| OrgSummaryResponse {
            id,
            name,
            role,
            member_count,
            created_at,
        })
        .collect())
}

pub async fn get_org_member(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Option<OrgMember>> {
    let m = sqlx::query_as::<_, OrgMember>(
        "SELECT * FROM organization_members WHERE org_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(m)
}

pub async fn get_org(pool: &PgPool, org_id: Uuid) -> Result<Option<Organization>> {
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_optional(pool)
        .await?;
    Ok(org)
}

pub async fn list_members(pool: &PgPool, org_id: Uuid) -> Result<Vec<OrgMemberResponse>> {
    let rows = sqlx::query_as::<_, OrgMember>(
        "SELECT * FROM organization_members WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|m| OrgMemberResponse {
            user_id: m.user_id,
            role: m.role,
            status: m.status,
            joined_at: m.joined_at,
        })
        .collect())
}

pub async fn invite_member(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
    encrypted_org_key: &str,
    invited_by: Uuid,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO organization_members
           (org_id, user_id, role, status, encrypted_org_key, invited_by)
           VALUES ($1, $2, $3, 'pending', $4, $5)
           ON CONFLICT (org_id, user_id) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(user_id)
    .bind(role)
    .bind(encrypted_org_key)
    .bind(invited_by)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn accept_invite(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<bool> {
    let rows = sqlx::query(
        r#"UPDATE organization_members
           SET status = 'active', joined_at = NOW()
           WHERE org_id = $1 AND user_id = $2 AND status = 'pending'"#,
    )
    .bind(org_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(rows.rows_affected() > 0)
}

pub async fn remove_member(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<bool> {
    let rows =
        sqlx::query("DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2 AND role != 'owner'")
            .bind(org_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    Ok(rows.rows_affected() > 0)
}
