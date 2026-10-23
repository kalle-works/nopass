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
    pub key_epoch: Option<i32>,
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
    /// Org key epoch the creator's wrap was signed for
    #[serde(default)]
    pub key_epoch: Option<i32>,
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
    /// Org key epoch the wrap was signed for
    pub key_epoch: i32,
}

/// Owner-only replacement of members' org-key wraps (re-signing a legacy org).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewrapBody {
    pub wraps: Vec<RewrapEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewrapEntry {
    pub user_id: Uuid,
    pub encrypted_org_key: String,
    pub wrap_signature: String,
    pub key_epoch: i32,
}

/// Owner-only org key rotation: optionally remove one member, then replace
/// every org item and every remaining member's wrap at `new_epoch`, all in one
/// transaction.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateKeyBody {
    pub new_epoch: i32,
    #[serde(default)]
    pub remove_user_id: Option<Uuid>,
    pub wraps: Vec<RewrapEntry>,
    pub items: Vec<ReencryptedOrgItem>,
    /// Undecryptable items the owner chose to delete in the same transaction
    #[serde(default)]
    pub delete_item_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReencryptedOrgItem {
    pub id: Uuid,
    pub blob: String,
    pub blob_iv: String,
    pub blob_mac: String,
}

/// An org item as served to members (base64 fields, like personal items).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgItemResponse {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub item_type: String,
    pub blob: String,
    pub blob_iv: String,
    pub blob_mac: String,
    pub version: i64,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One signed wrap in the chain that vouches for a member's org key: the
/// member's wrap, and the key bundle of whoever signed it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrapLinkResponse {
    pub recipient_user_id: Uuid,
    pub role: String,
    pub encrypted_org_key: String,
    pub wrap_signature: Option<String>,
    pub key_epoch: Option<i32>,
    pub signer_user_id: Uuid,
    pub signer: KeyBundleResponse,
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

/// A pending invite as the invitee sees it. `wrap_chain[0]` is the invitee's
/// own wrap; the rest vouch for whoever signed it, up to the owner.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingInviteResponse {
    pub org_id: Uuid,
    pub org_name: String,
    pub role: String,
    pub wrap_chain: Vec<WrapLinkResponse>,
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
    /// Signed chain for the caller's wrap, so the org key is verified on every
    /// load, not only when the invite was accepted
    pub wrap_chain: Vec<WrapLinkResponse>,
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
