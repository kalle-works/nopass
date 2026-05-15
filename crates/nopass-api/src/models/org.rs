use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct OrgMember {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub status: String,
    pub encrypted_org_key: Option<String>,
    pub invited_by: Option<Uuid>,
    pub joined_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ── Request / response bodies ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgBody {
    pub name: String,
    pub public_key: String,
    pub protected_private_key: String,
    pub protected_private_key_iv: String,
    pub encrypted_org_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteMemberBody {
    /// SHA-256("nopass-v1-email:" + lowercase(email)) — server never receives plaintext
    pub email_hash: String,
    pub role: String,
    pub encrypted_org_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInviteBody {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgSummaryResponse {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgMemberResponse {
    pub user_id: Uuid,
    pub role: String,
    pub status: String,
    pub joined_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgDetailsResponse {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
    pub members: Vec<OrgMemberResponse>,
    pub encrypted_org_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    pub user_id: Uuid,
    pub public_key: String,
}
