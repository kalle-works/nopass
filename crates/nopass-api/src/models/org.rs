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
    pub wrap_signature: Option<String>,
    pub joined_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ── Request / response bodies ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgBody {
    /// Client-chosen id, so the creator can sign their own org-key wrap
    #[serde(default)]
    pub id: Option<Uuid>,
    pub name: String,
    pub public_key: String,
    pub protected_private_key: String,
    pub protected_private_key_iv: String,
    pub encrypted_org_key: String,
    /// Creator's identity-key signature over their own org-key wrap
    #[serde(default)]
    pub wrap_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteMemberBody {
    /// SHA-256("nopass-v1-email:" + lowercase(email)) — server never receives plaintext
    pub email_hash: String,
    pub role: String,
    pub encrypted_org_key: String,
    /// Inviter's identity-key signature over the wrap, verified by the invitee
    pub wrap_signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInviteBody {}

/// A user's published keys, as returned to other users.
#[derive(Debug, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct KeyBundleResponse {
    pub user_id: Uuid,
    pub public_key: String,
    pub identity_public_key: Option<String>,
    pub public_key_signature: Option<String>,
}

/// A pending invite as the invitee sees it, with what they need to check it
/// came from the inviter before accepting.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingInviteResponse {
    pub org_id: Uuid,
    pub org_name: String,
    pub role: String,
    pub encrypted_org_key: String,
    pub wrap_signature: Option<String>,
    pub inviter: KeyBundleResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgSummaryResponse {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct OrgMemberResponse {
    pub user_id: Uuid,
    pub role: String,
    pub status: String,
    pub joined_at: Option<DateTime<Utc>>,
    /// Key bundle, so members can verify each other's keys client-side
    pub public_key: Option<String>,
    pub identity_public_key: Option<String>,
    pub public_key_signature: Option<String>,
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
    /// Signature over the caller's wrap and who made it, so the org key can be
    /// checked on every load, not only when the invite was accepted
    pub wrap_signature: Option<String>,
    pub wrap_signer_id: Uuid,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    pub user_id: Uuid,
    pub public_key: String,
    /// base64 Ed25519 key; None until the user's client has migrated
    pub identity_public_key: Option<String>,
    /// base64 Ed25519 signature over the key bundle
    pub public_key_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetIdentityBody {
    pub identity_public_key: String,
    pub public_key_signature: String,
    /// Fresh password proof; required for the first publish, which binds the
    /// account to an identity key for good.
    pub proof: Option<nopass_models::PasswordProof>,
}
