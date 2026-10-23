use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::org::{
    KeyBundleResponse, OrgMember, OrgMemberResponse, OrgSummaryResponse, Organization, PendingInviteResponse,
};

pub async fn create_org(
    pool: &PgPool,
    id: Option<Uuid>,
    name: &str,
    created_by: Uuid,
    encrypted_org_key: &str,
    wrap_signature: Option<&str>,
) -> Result<Organization> {
    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, name, created_by) VALUES (COALESCE($1, gen_random_uuid()), $2, $3) RETURNING *",
    )
    .bind(id)
    .bind(name)
    .bind(created_by)
    .fetch_one(pool)
    .await?;

    // Add creator as active owner
    sqlx::query(
        r#"INSERT INTO organization_members
           (org_id, user_id, role, status, encrypted_org_key, wrap_signature, joined_at)
           VALUES ($1, $2, 'owner', 'active', $3, $4, NOW())"#,
    )
    .bind(org.id)
    .bind(created_by)
    .bind(encrypted_org_key)
    .bind(wrap_signature)
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
    let rows = sqlx::query_as::<_, OrgMemberResponse>(
        r#"SELECT m.user_id, m.role, m.status, m.joined_at,
                  u.public_key, u.identity_public_key, u.public_key_signature
           FROM organization_members m
           JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1
           ORDER BY m.created_at"#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn invite_member(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
    encrypted_org_key: &str,
    wrap_signature: &str,
    invited_by: Uuid,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO organization_members
           (org_id, user_id, role, status, encrypted_org_key, wrap_signature, invited_by)
           VALUES ($1, $2, $3, 'pending', $4, $5, $6)
           ON CONFLICT (org_id, user_id) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(user_id)
    .bind(role)
    .bind(encrypted_org_key)
    .bind(wrap_signature)
    .bind(invited_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Pending invites for a user, with each inviter's published key bundle.
pub async fn list_pending_invites(pool: &PgPool, user_id: Uuid) -> Result<Vec<PendingInviteResponse>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        org_id: Uuid,
        org_name: String,
        role: String,
        encrypted_org_key: String,
        wrap_signature: Option<String>,
        inviter_id: Uuid,
        inviter_public_key: String,
        inviter_identity_public_key: Option<String>,
        inviter_public_key_signature: Option<String>,
    }
    let rows = sqlx::query_as::<_, Row>(
        r#"SELECT m.org_id, o.name AS org_name, m.role, m.encrypted_org_key, m.wrap_signature,
                  u.id AS inviter_id, u.public_key AS inviter_public_key,
                  u.identity_public_key AS inviter_identity_public_key,
                  u.public_key_signature AS inviter_public_key_signature
           FROM organization_members m
           JOIN organizations o ON o.id = m.org_id
           JOIN users u ON u.id = m.invited_by
           WHERE m.user_id = $1 AND m.status = 'pending'
             AND m.encrypted_org_key IS NOT NULL AND u.public_key IS NOT NULL
           ORDER BY m.created_at"#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| PendingInviteResponse {
            org_id: r.org_id,
            org_name: r.org_name,
            role: r.role,
            encrypted_org_key: r.encrypted_org_key,
            wrap_signature: r.wrap_signature,
            inviter: KeyBundleResponse {
                user_id: r.inviter_id,
                public_key: r.inviter_public_key,
                identity_public_key: r.inviter_identity_public_key,
                public_key_signature: r.inviter_public_key_signature,
            },
        })
        .collect())
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
