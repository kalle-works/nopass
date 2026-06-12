use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post, put},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use nopass_models::{
    ConflictResponse, CreateVaultItemRequest, CreateVaultRequest, EncryptedVaultItem,
    MoveItemRequest, UpdateVaultItemRequest, VaultInfo, VaultItemType,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    db::vaults as db_vaults,
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_vaults).post(create_vault))
        .route("/{vault_id}", put(rename_vault).delete(delete_vault))
        .route("/{vault_id}/items", get(list_items).post(create_item))
        .route(
            "/{vault_id}/items/{item_id}",
            put(update_item).delete(delete_item),
        )
        .route("/{vault_id}/items/{item_id}/move", post(move_item))
}

fn vault_to_info(v: crate::models::vault::Vault) -> VaultInfo {
    VaultInfo {
        id: v.id,
        name_blob: B64.encode(&v.name_blob),
        name_iv: B64.encode(&v.name_iv),
        created_at: v.created_at,
    }
}

async fn list_vaults(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<Vec<VaultInfo>>> {
    let vaults = db_vaults::list_vaults_for_user(&state.db, auth.user_id).await?;
    Ok(Json(vaults.into_iter().map(vault_to_info).collect()))
}

async fn create_vault(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(req): Json<CreateVaultRequest>,
) -> ApiResult<(StatusCode, Json<VaultInfo>)> {
    let name_blob = B64.decode(&req.name_blob)
        .map_err(|_| ApiError::BadRequest("invalid name_blob base64".into()))?;
    let name_iv = B64.decode(&req.name_iv)
        .map_err(|_| ApiError::BadRequest("invalid name_iv base64".into()))?;

    let count = db_vaults::count_vaults_for_user(&state.db, auth.user_id).await?;
    if count >= 32 {
        return Err(ApiError::BadRequest("vault limit reached".into()));
    }

    let vault = db_vaults::create_named_vault(&state.db, auth.user_id, &name_blob, &name_iv).await?;
    Ok((StatusCode::CREATED, Json(vault_to_info(vault))))
}

async fn rename_vault(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<CreateVaultRequest>,
) -> ApiResult<StatusCode> {
    let name_blob = B64.decode(&req.name_blob)
        .map_err(|_| ApiError::BadRequest("invalid name_blob base64".into()))?;
    let name_iv = B64.decode(&req.name_iv)
        .map_err(|_| ApiError::BadRequest("invalid name_iv base64".into()))?;

    let renamed = db_vaults::rename_vault(&state.db, vault_id, auth.user_id, &name_blob, &name_iv).await?;
    if !renamed {
        return Err(ApiError::NotFound("vault not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_vault(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(vault_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    db_vaults::get_vault(&state.db, vault_id, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("vault not found".into()))?;

    // The last vault must survive, and non-empty vaults must be emptied first —
    // silently deleting items would be data loss behind one keystroke
    let vault_count = db_vaults::count_vaults_for_user(&state.db, auth.user_id).await?;
    if vault_count <= 1 {
        return Err(ApiError::Conflict("cannot delete your only vault".into()));
    }
    let item_count = db_vaults::count_items_in_vault(&state.db, vault_id, auth.user_id).await?;
    if item_count > 0 {
        return Err(ApiError::Conflict("move or delete the vault's items first".into()));
    }

    db_vaults::delete_vault(&state.db, vault_id, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn move_item(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path((_vault_id, item_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<MoveItemRequest>,
) -> ApiResult<StatusCode> {
    let moved = db_vaults::move_item(&state.db, item_id, auth.user_id, req.to_vault_id).await?;
    if !moved {
        return Err(ApiError::NotFound("item or destination vault not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SinceQuery {
    since: Option<DateTime<Utc>>,
}

async fn list_items(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(vault_id): Path<Uuid>,
    Query(query): Query<SinceQuery>,
) -> ApiResult<Json<Vec<EncryptedVaultItem>>> {
    // Verify vault belongs to user
    db_vaults::get_vault(&state.db, vault_id, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("vault not found".into()))?;

    let items = db_vaults::list_items(&state.db, vault_id, auth.user_id, query.since).await?;

    let response = items
        .into_iter()
        .map(|item| {
            Ok(EncryptedVaultItem {
                id: item.id,
                vault_id: item.vault_id,
                user_id: item.user_id,
                item_type: parse_item_type(&item.item_type)?,
                blob: B64.encode(&item.blob),
                blob_iv: B64.encode(&item.blob_iv),
                blob_mac: B64.encode(&item.blob_mac),
                version: item.version,
                deleted_at: item.deleted_at,
                created_at: item.created_at,
                updated_at: item.updated_at,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;

    Ok(Json(response))
}

async fn create_item(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<CreateVaultItemRequest>,
) -> ApiResult<(StatusCode, Json<EncryptedVaultItem>)> {
    db_vaults::get_vault(&state.db, vault_id, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("vault not found".into()))?;

    let blob = B64.decode(&req.blob)
        .map_err(|_| ApiError::BadRequest("invalid blob".into()))?;
    let blob_iv = B64.decode(&req.blob_iv)
        .map_err(|_| ApiError::BadRequest("invalid blob_iv".into()))?;
    let blob_mac = B64.decode(&req.blob_mac)
        .map_err(|_| ApiError::BadRequest("invalid blob_mac".into()))?;

    // AES-256-GCM requires exactly 12-byte IV; HMAC-SHA256 output is 32 bytes.
    if blob_iv.len() != 12 {
        return Err(ApiError::BadRequest("blob_iv must be 12 bytes".into()));
    }
    if blob_mac.len() != 32 {
        return Err(ApiError::BadRequest("blob_mac must be 32 bytes".into()));
    }
    if blob.is_empty() {
        return Err(ApiError::BadRequest("blob must not be empty".into()));
    }

    let item_type_str = item_type_to_str(&req.item_type);
    let item =
        db_vaults::create_item(&state.db, vault_id, auth.user_id, item_type_str, &blob, &blob_iv, &blob_mac)
            .await?;

    Ok((
        StatusCode::CREATED,
        Json(EncryptedVaultItem {
            id: item.id,
            vault_id: item.vault_id,
            user_id: item.user_id,
            item_type: req.item_type,
            blob: req.blob,
            blob_iv: req.blob_iv,
            blob_mac: req.blob_mac,
            version: item.version,
            deleted_at: None,
            created_at: item.created_at,
            updated_at: item.updated_at,
        }),
    ))
}

async fn update_item(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path((vault_id, item_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateVaultItemRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = vault_id; // vault ownership already checked via user_id on item

    let blob = B64.decode(&req.blob)
        .map_err(|_| ApiError::BadRequest("invalid blob".into()))?;
    let blob_iv = B64.decode(&req.blob_iv)
        .map_err(|_| ApiError::BadRequest("invalid blob_iv".into()))?;
    let blob_mac = B64.decode(&req.blob_mac)
        .map_err(|_| ApiError::BadRequest("invalid blob_mac".into()))?;

    if blob_iv.len() != 12 {
        return Err(ApiError::BadRequest("blob_iv must be 12 bytes".into()));
    }
    if blob_mac.len() != 32 {
        return Err(ApiError::BadRequest("blob_mac must be 32 bytes".into()));
    }
    if blob.is_empty() {
        return Err(ApiError::BadRequest("blob must not be empty".into()));
    }

    let updated =
        db_vaults::update_item(&state.db, item_id, auth.user_id, &blob, &blob_iv, &blob_mac, req.version)
            .await?;

    match updated {
        Some(item) => Ok(Json(
            serde_json::json!({ "version": item.version, "updatedAt": item.updated_at }),
        )),
        None => {
            // Optimistic locking conflict — return 409 with current version
            let current_version =
                db_vaults::get_current_version(&state.db, item_id, auth.user_id).await?;
            match current_version {
                Some(v) => Err(ApiError::Conflict(
                    serde_json::to_string(&ConflictResponse {
                        conflict: true,
                        server_version: v,
                    })
                    .unwrap_or_default(),
                )),
                None => Err(ApiError::NotFound("item not found".into())),
            }
        }
    }
}

async fn delete_item(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path((_vault_id, item_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let deleted = db_vaults::soft_delete_item(&state.db, item_id, auth.user_id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("item not found".into()))
    }
}

pub(crate) fn parse_item_type(s: &str) -> ApiResult<VaultItemType> {
    match s {
        "login" => Ok(VaultItemType::Login),
        "note" => Ok(VaultItemType::Note),
        "card" => Ok(VaultItemType::Card),
        "identity" => Ok(VaultItemType::Identity),
        "ssh_key" => Ok(VaultItemType::SshKey),
        other => Err(ApiError::BadRequest(format!("unknown item type: {other}"))),
    }
}

fn item_type_to_str(t: &VaultItemType) -> &'static str {
    match t {
        VaultItemType::Login => "login",
        VaultItemType::Note => "note",
        VaultItemType::Card => "card",
        VaultItemType::Identity => "identity",
        VaultItemType::SshKey => "ssh_key",
    }
}
