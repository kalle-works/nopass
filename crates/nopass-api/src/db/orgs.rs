use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::org::{
    KeyBundleResponse, OrgMember, OrgMemberResponse, OrgSummaryResponse, Organization, PendingInviteResponse,
    RewrapEntry, WrapLinkResponse,
};

pub async fn create_org(
    pool: &PgPool,
    id: Option<Uuid>,
    name: &str,
    created_by: Uuid,
    encrypted_org_key: &str,
    wrap_signature: Option<&str>,
    key_epoch: Option<i32>,
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
           (org_id, user_id, role, status, encrypted_org_key, wrap_signature, key_epoch, joined_at)
           VALUES ($1, $2, 'owner', 'active', $3, $4, $5, NOW())"#,
    )
    .bind(org.id)
    .bind(created_by)
    .bind(encrypted_org_key)
    .bind(wrap_signature)
    .bind(key_epoch)
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

/// An org key wrapped for one member, with the signature over it.
pub struct SignedWrap<'a> {
    pub encrypted_org_key: &'a str,
    pub wrap_signature: &'a str,
    pub key_epoch: i32,
}

pub async fn invite_member(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
    wrap: SignedWrap<'_>,
    invited_by: Uuid,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO organization_members
           (org_id, user_id, role, status, encrypted_org_key, wrap_signature, key_epoch, invited_by)
           VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7)
           ON CONFLICT (org_id, user_id) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(user_id)
    .bind(role)
    .bind(wrap.encrypted_org_key)
    .bind(wrap.wrap_signature)
    .bind(wrap.key_epoch)
    .bind(invited_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// The chain of wraps vouching for `user_id`'s org key: their own wrap, then
/// the wrap of whoever signed it, and so on until a self-signed wrap (the
/// owner) or a signer who is no longer a member. Clients decide what it proves.
pub async fn wrap_chain(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Result<Vec<WrapLinkResponse>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        recipient_user_id: Uuid,
        role: String,
        encrypted_org_key: String,
        wrap_signature: Option<String>,
        key_epoch: Option<i32>,
        signer_user_id: Uuid,
        public_key: String,
        identity_public_key: Option<String>,
        public_key_signature: Option<String>,
    }
    let rows = sqlx::query_as::<_, Row>(
        r#"WITH RECURSIVE chain AS (
               SELECT m.user_id, m.role, m.encrypted_org_key, m.wrap_signature, m.key_epoch,
                      COALESCE(m.invited_by, m.user_id) AS signer_id, 0 AS depth
               FROM organization_members m
               WHERE m.org_id = $1 AND m.user_id = $2
             UNION ALL
               SELECT m.user_id, m.role, m.encrypted_org_key, m.wrap_signature, m.key_epoch,
                      COALESCE(m.invited_by, m.user_id), c.depth + 1
               FROM organization_members m
               JOIN chain c ON m.org_id = $1 AND m.user_id = c.signer_id
               WHERE c.signer_id <> c.user_id AND c.depth < 16
           )
           SELECT c.user_id AS recipient_user_id, c.role, c.encrypted_org_key, c.wrap_signature, c.key_epoch,
                  c.signer_id AS signer_user_id, u.public_key, u.identity_public_key, u.public_key_signature
           FROM chain c
           JOIN users u ON u.id = c.signer_id
           WHERE c.encrypted_org_key IS NOT NULL AND u.public_key IS NOT NULL
           ORDER BY c.depth"#,
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| WrapLinkResponse {
            recipient_user_id: r.recipient_user_id,
            role: r.role,
            encrypted_org_key: r.encrypted_org_key,
            wrap_signature: r.wrap_signature,
            key_epoch: r.key_epoch,
            signer_user_id: r.signer_user_id,
            signer: KeyBundleResponse {
                user_id: r.signer_user_id,
                public_key: r.public_key,
                identity_public_key: r.identity_public_key,
                public_key_signature: r.public_key_signature,
            },
        })
        .collect())
}

/// Pending invites for a user, each with the wrap chain the invitee verifies
/// before accepting.
pub async fn list_pending_invites(pool: &PgPool, user_id: Uuid) -> Result<Vec<PendingInviteResponse>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String)>(
        r#"SELECT m.org_id, o.name, m.role
           FROM organization_members m
           JOIN organizations o ON o.id = m.org_id
           WHERE m.user_id = $1 AND m.status = 'pending'
           ORDER BY m.created_at"#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut invites = Vec::with_capacity(rows.len());
    for (org_id, org_name, role) in rows {
        invites.push(PendingInviteResponse {
            org_id,
            org_name,
            role,
            wrap_chain: wrap_chain(pool, org_id, user_id).await?,
        });
    }
    Ok(invites)
}

/// Replace members' wraps with ones the owner signed. The owner's own row
/// stays self-signed; everyone else's signer becomes the owner. Members not
/// in the org are rejected so the whole batch applies or none of it does.
pub async fn rewrap_members(pool: &PgPool, org_id: Uuid, owner_id: Uuid, wraps: &[RewrapEntry]) -> Result<bool> {
    let mut tx = pool.begin().await?;
    for w in wraps {
        let updated = sqlx::query(
            r#"UPDATE organization_members
               SET encrypted_org_key = $3, wrap_signature = $4, key_epoch = $5,
                   invited_by = CASE WHEN user_id = $6 THEN NULL ELSE $6 END
               WHERE org_id = $1 AND user_id = $2"#,
        )
        .bind(org_id)
        .bind(w.user_id)
        .bind(&w.encrypted_org_key)
        .bind(&w.wrap_signature)
        .bind(w.key_epoch)
        .bind(owner_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if updated != 1 {
            return Ok(false);
        }
    }
    tx.commit().await?;
    Ok(true)
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
