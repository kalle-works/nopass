use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use uuid::Uuid;

use crate::{
    db::{auth as db_auth, keys as db_keys, orgs as db_orgs, subscriptions as db_subs},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::org::{
        CreateOrgBody, InviteMemberBody, OrgDetailsResponse,
        OrgItemResponse, OrgSummaryResponse, PendingInviteResponse, PublicKeyResponse, RewrapBody,
        RotateKeyBody,
    },
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_orgs).post(create_org))
        .route("/invites", get(list_invites))
        .route("/{org_id}", get(get_org))
        .route("/{org_id}/members", post(invite_member))
        .route("/{org_id}/members/{user_id}", delete(remove_member))
        .route("/{org_id}/accept", post(accept_invite))
        .route("/{org_id}/wraps", put(rewrap_members))
        .route("/{org_id}/items", get(list_org_items))
        .route("/{org_id}/rotate", post(rotate_key))
        // Look up a user's public key by email hash (needed before sending an invite)
        .route("/public-key/{email_hash}", get(get_public_key))
}

async fn list_orgs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<Vec<OrgSummaryResponse>>> {
    let orgs = db_orgs::list_orgs_for_user(&state.db, auth.user_id).await?;
    Ok(Json(orgs))
}

async fn create_org(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateOrgBody>,
) -> ApiResult<(StatusCode, Json<OrgSummaryResponse>)> {
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("org name must not be empty".into()));
    }

    // Store the key pair on the user if not already set
    sqlx::query(
        r#"UPDATE users SET
            public_key = COALESCE(public_key, $1),
            protected_private_key = COALESCE(protected_private_key, $2),
            protected_private_key_iv = COALESCE(protected_private_key_iv, $3)
           WHERE id = $4"#,
    )
    .bind(&body.public_key)
    .bind(&body.protected_private_key)
    .bind(&body.protected_private_key_iv)
    .bind(auth.user_id)
    .execute(&state.db)
    .await?;

    let org = db_orgs::create_org(
        &state.db,
        body.id,
        body.name.trim(),
        auth.user_id,
        &body.encrypted_org_key,
        body.wrap_signature.as_deref(),
        body.key_epoch,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(OrgSummaryResponse {
            id: org.id,
            name: org.name,
            role: "owner".into(),
            member_count: 1,
            created_at: org.created_at,
        }),
    ))
}

async fn get_org(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<OrgDetailsResponse>> {
    let member = db_orgs::get_org_member(&state.db, org_id, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("org not found".into()))?;

    if member.status != "active" {
        return Err(ApiError::Forbidden("invite not yet accepted".into()));
    }

    let org = db_orgs::get_org(&state.db, org_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("org not found".into()))?;

    let members = db_orgs::list_members(&state.db, org_id).await?;
    let member_count = members.iter().filter(|m| m.status == "active").count() as i64;

    let encrypted_org_key = member
        .encrypted_org_key
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("missing encrypted org key")))?;

    Ok(Json(OrgDetailsResponse {
        id: org.id,
        name: org.name,
        role: member.role,
        member_count,
        created_at: org.created_at,
        members,
        encrypted_org_key,
        wrap_chain: db_orgs::wrap_chain(&state.db, org_id, auth.user_id).await?,
    }))
}

async fn invite_member(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(org_id): Path<Uuid>,
    Json(body): Json<InviteMemberBody>,
) -> ApiResult<StatusCode> {
    // Must be owner or admin
    let caller = db_orgs::get_org_member(&state.db, org_id, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::Forbidden("not a member of this org".into()))?;

    if caller.status != "active" || (caller.role != "owner" && caller.role != "admin") {
        return Err(ApiError::Forbidden("must be an admin to invite members".into()));
    }

    if body.role == "owner" {
        return Err(ApiError::BadRequest("cannot invite as owner".into()));
    }

    // Enforce org member limit based on the inviting user's subscription plan.
    let plan = db_subs::effective_plan(&state.db, auth.user_id).await?;
    if let Some(limit) = plan.org_member_limit() {
        let members = db_orgs::list_members(&state.db, org_id).await?;
        let active = members.iter().filter(|m| m.status == "active").count();
        if active >= limit {
            return Err(ApiError::Forbidden(format!(
                "org member limit of {limit} reached on your current plan — upgrade to Pro to add more"
            )));
        }
    }

    // Compute email hash client-side and pass it; server looks up user by it.
    // The invite body contains the email hash (not plaintext email) for privacy.
    let (invitee_id, _) = db_auth::get_public_key_by_account_key(&state.db, &state.account_key(&body.email_hash))
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found or has no public key".into()))?;

    if B64.decode(&body.wrap_signature).map(|s| s.len()) != Ok(64) {
        return Err(ApiError::BadRequest("wrapSignature must be 64 bytes of base64".into()));
    }
    // A wrap for an older epoch carries a key that a rotation already retired
    if Some(body.key_epoch) != db_orgs::current_key_epoch(&state.db, org_id).await? {
        return Err(ApiError::Conflict("keyEpoch is not the org's current key epoch".into()));
    }

    db_orgs::invite_member(
        &state.db,
        org_id,
        invitee_id,
        &body.role,
        db_orgs::SignedWrap {
            encrypted_org_key: &body.encrypted_org_key,
            wrap_signature: &body.wrap_signature,
            key_epoch: body.key_epoch,
        },
        auth.user_id,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Owner-only: replace members' org-key wraps with owner-signed ones, e.g. to
/// bring an org created before signed wraps under verification.
async fn rewrap_members(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(org_id): Path<Uuid>,
    Json(body): Json<RewrapBody>,
) -> ApiResult<StatusCode> {
    require_owner(&state, org_id, auth.user_id).await?;
    let epoch = db_orgs::current_key_epoch(&state.db, org_id).await?.unwrap_or(1);
    for w in &body.wraps {
        if B64.decode(&w.wrap_signature).map(|s| s.len()) != Ok(64) || w.key_epoch != epoch {
            return Err(ApiError::BadRequest("each wrap needs a 64-byte signature at the current key epoch".into()));
        }
    }
    if !db_orgs::rewrap_members(&state.db, org_id, auth.user_id, &body.wraps).await? {
        return Err(ApiError::BadRequest("every wrap must be for a member of this org".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_invites(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<Vec<PendingInviteResponse>>> {
    Ok(Json(db_orgs::list_pending_invites(&state.db, auth.user_id).await?))
}

async fn accept_invite(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(org_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let accepted = db_orgs::accept_invite(&state.db, org_id, auth.user_id).await?;
    if !accepted {
        return Err(ApiError::NotFound("no pending invite found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Removing a member is only possible as part of a key rotation (POST
/// /{org_id}/rotate with removeUserId): otherwise the removed member would
/// keep the org key and could read everything written afterwards.
async fn remove_member(
    State(_state): State<AppState>,
    Extension(_auth): Extension<AuthUser>,
    Path((_org_id, _user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    Err(ApiError::Conflict(
        "members are removed by rotating the org key: POST /organizations/{id}/rotate with removeUserId".into(),
    ))
}

async fn require_owner(state: &AppState, org_id: Uuid, user_id: Uuid) -> ApiResult<()> {
    let caller = db_orgs::get_org_member(&state.db, org_id, user_id)
        .await?
        .ok_or_else(|| ApiError::Forbidden("not a member of this org".into()))?;
    if caller.status != "active" || caller.role != "owner" {
        return Err(ApiError::Forbidden("only the owner can do this".into()));
    }
    Ok(())
}

/// All org items, tombstones included, for active members.
async fn list_org_items(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Vec<OrgItemResponse>>> {
    let member = db_orgs::get_org_member(&state.db, org_id, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("org not found".into()))?;
    if member.status != "active" {
        return Err(ApiError::Forbidden("invite not yet accepted".into()));
    }
    let items = db_orgs::list_org_items(&state.db, org_id)
        .await?
        .into_iter()
        .map(|i| OrgItemResponse {
            id: i.id,
            vault_id: i.vault_id,
            user_id: i.user_id,
            org_id: i.org_id,
            item_type: i.item_type,
            blob: B64.encode(&i.blob),
            blob_iv: B64.encode(&i.blob_iv),
            blob_mac: B64.encode(&i.blob_mac),
            version: i.version,
            deleted_at: i.deleted_at,
            created_at: i.created_at,
            updated_at: i.updated_at,
        })
        .collect();
    Ok(Json(items))
}

/// Owner-only key rotation, optionally removing a member. Everything (member
/// removal, every org item, every remaining wrap, the epoch) changes in one
/// transaction or not at all.
async fn rotate_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(org_id): Path<Uuid>,
    Json(body): Json<RotateKeyBody>,
) -> ApiResult<StatusCode> {
    require_owner(&state, org_id, auth.user_id).await?;
    if body.remove_user_id == Some(auth.user_id) {
        return Err(ApiError::BadRequest("the owner cannot remove themselves".into()));
    }
    for w in &body.wraps {
        if B64.decode(&w.wrap_signature).map(|s| s.len()) != Ok(64) {
            return Err(ApiError::BadRequest("each wrap needs a 64-byte signature".into()));
        }
    }
    let items = body
        .items
        .iter()
        .map(|i| {
            let decode = |v: &str, what: &str| B64.decode(v).map_err(|_| ApiError::BadRequest(format!("invalid {what}")));
            let (blob, blob_iv, blob_mac) = (decode(&i.blob, "blob")?, decode(&i.blob_iv, "blob_iv")?, decode(&i.blob_mac, "blob_mac")?);
            if blob_iv.len() != 12 || blob.is_empty() || !(blob_mac.is_empty() || blob_mac.len() == 32) {
                return Err(ApiError::BadRequest("malformed re-encrypted item".into()));
            }
            Ok((i.id, blob, blob_iv, blob_mac))
        })
        .collect::<ApiResult<Vec<_>>>()?;

    let rotation = db_orgs::Rotation {
        new_epoch: body.new_epoch,
        remove_user_id: body.remove_user_id,
        wraps: &body.wraps,
        items,
    };
    match db_orgs::rotate_key(&state.db, org_id, auth.user_id, rotation).await? {
        db_orgs::RotationOutcome::Rotated => Ok(StatusCode::NO_CONTENT),
        db_orgs::RotationOutcome::StaleEpoch => {
            Err(ApiError::Conflict("newEpoch must be the current key epoch + 1".into()))
        }
        db_orgs::RotationOutcome::BadRemoval => {
            Err(ApiError::BadRequest("member to remove not found, or is the owner".into()))
        }
        db_orgs::RotationOutcome::IncompleteWraps => Err(ApiError::BadRequest(
            "wraps must cover every remaining member exactly once, at newEpoch".into(),
        )),
        db_orgs::RotationOutcome::IncompleteItems => {
            Err(ApiError::BadRequest("items must cover every org item exactly once".into()))
        }
    }
}

async fn get_public_key(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthUser>,
    Path(email_hash): Path<String>,
) -> ApiResult<Json<PublicKeyResponse>> {
    let bundle = db_keys::get_bundle_by_account_key(&state.db, &state.account_key(&email_hash))
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found or has no public key".into()))?;

    Ok(Json(PublicKeyResponse {
        user_id: bundle.user_id,
        public_key: bundle.public_key,
        identity_public_key: bundle.identity_public_key,
        public_key_signature: bundle.public_key_signature,
    }))
}
