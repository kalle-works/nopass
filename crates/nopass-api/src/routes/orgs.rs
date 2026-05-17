use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use uuid::Uuid;

use crate::{
    db::{auth as db_auth, orgs as db_orgs, subscriptions as db_subs},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::org::{
        CreateOrgBody, InviteMemberBody, OrgDetailsResponse,
        OrgSummaryResponse, PublicKeyResponse,
    },
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_orgs).post(create_org))
        .route("/{org_id}", get(get_org))
        .route("/{org_id}/members", post(invite_member))
        .route("/{org_id}/members/{user_id}", delete(remove_member))
        .route("/{org_id}/accept", post(accept_invite))
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
        body.name.trim(),
        auth.user_id,
        &body.encrypted_org_key,
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
    let (invitee_id, _) = db_auth::get_public_key_by_email_hash(&state.db, &body.email_hash)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found or has no public key".into()))?;

    db_orgs::invite_member(
        &state.db,
        org_id,
        invitee_id,
        &body.role,
        &body.encrypted_org_key,
        auth.user_id,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
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

async fn remove_member(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let caller = db_orgs::get_org_member(&state.db, org_id, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::Forbidden("not a member of this org".into()))?;

    if caller.status != "active" || (caller.role != "owner" && caller.role != "admin") {
        return Err(ApiError::Forbidden(
            "must be an admin to remove members".into(),
        ));
    }

    // Members may also remove themselves
    if user_id != auth.user_id && caller.role != "owner" && caller.role != "admin" {
        return Err(ApiError::Forbidden("insufficient permissions".into()));
    }

    let removed = db_orgs::remove_member(&state.db, org_id, user_id).await?;
    if !removed {
        return Err(ApiError::NotFound(
            "member not found or cannot remove owner".into(),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn get_public_key(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthUser>,
    Path(email_hash): Path<String>,
) -> ApiResult<Json<PublicKeyResponse>> {
    let (user_id, public_key) =
        db_auth::get_public_key_by_email_hash(&state.db, &email_hash)
            .await?
            .ok_or_else(|| ApiError::NotFound("user not found or has no public key".into()))?;

    Ok(Json(PublicKeyResponse { user_id, public_key }))
}
