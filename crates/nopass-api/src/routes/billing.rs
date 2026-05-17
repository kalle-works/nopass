use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Extension, Json, Router,
};

use crate::{
    db::subscriptions as db_subs,
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::billing::{
        BillingStatusResponse, CheckoutSessionResponse, CreateCheckoutRequest,
        CreatePortalRequest, PortalSessionResponse, SubscriptionPlan, SubscriptionStatus,
    },
    state::AppState,
    stripe::StripeSubscription,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(billing_status))
        .route("/checkout", post(create_checkout))
        .route("/portal", post(create_portal))
}

pub fn webhook_router() -> Router<AppState> {
    Router::new().route("/billing/webhooks", post(handle_webhook))
}

// ─── GET /billing/status ─────────────────────────────────────────────────────

async fn billing_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<BillingStatusResponse>> {
    let sub = db_subs::get_subscription(&state.db, auth.user_id).await?;
    let resp = match sub {
        Some(s) => BillingStatusResponse {
            plan: s.plan,
            status: s.status,
            current_period_end: s.current_period_end,
            stripe_customer_id: s.stripe_customer_id,
        },
        None => BillingStatusResponse {
            plan: SubscriptionPlan::Free,
            status: SubscriptionStatus::Active,
            current_period_end: None,
            stripe_customer_id: None,
        },
    };
    Ok(Json(resp))
}

// ─── POST /billing/checkout ──────────────────────────────────────────────────

async fn create_checkout(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateCheckoutRequest>,
) -> ApiResult<Json<CheckoutSessionResponse>> {
    let stripe = state
        .stripe
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("billing not configured".into()))?;

    let customer_id = ensure_stripe_customer(&state, auth.user_id, stripe).await?;

    let url = stripe
        .create_checkout_session(
            &customer_id,
            &body.price_id,
            &body.success_url,
            &body.cancel_url,
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(CheckoutSessionResponse { url }))
}

// ─── POST /billing/portal ────────────────────────────────────────────────────

async fn create_portal(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreatePortalRequest>,
) -> ApiResult<Json<PortalSessionResponse>> {
    let stripe = state
        .stripe
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("billing not configured".into()))?;

    let sub = db_subs::get_subscription(&state.db, auth.user_id).await?;
    let customer_id = sub
        .and_then(|s| s.stripe_customer_id)
        .ok_or_else(|| ApiError::NotFound("no active subscription found".into()))?;

    let url = stripe
        .create_portal_session(&customer_id, &body.return_url)
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(PortalSessionResponse { url }))
}

// ─── POST /billing/webhooks (public — no auth middleware) ────────────────────

async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let stripe = state
        .stripe
        .as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "billing not configured"))?;

    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing Stripe-Signature header"))?;

    let event = stripe
        .construct_event(&body, sig)
        .map_err(|e| {
            tracing::warn!("Stripe webhook rejected: {e}");
            (StatusCode::BAD_REQUEST, "invalid webhook signature")
        })?;

    match event.event_type.as_str() {
        "customer.subscription.created" | "customer.subscription.updated" => {
            if let Some(sub) = event.as_subscription() {
                handle_subscription_update(&state, &sub).await.map_err(|e| {
                    tracing::error!("subscription update failed: {e}");
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                })?;
            }
        }
        "customer.subscription.deleted" => {
            if let Some(sub) = event.as_subscription() {
                handle_subscription_deleted(&state, &sub).await.map_err(|e| {
                    tracing::error!("subscription deletion failed: {e}");
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                })?;
            }
        }
        other => {
            tracing::debug!("unhandled Stripe event: {other}");
        }
    }

    Ok(StatusCode::OK)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn ensure_stripe_customer(
    state: &AppState,
    user_id: uuid::Uuid,
    stripe: &crate::stripe::StripeClient,
) -> ApiResult<String> {
    let existing = db_subs::get_subscription(&state.db, user_id).await?;
    if let Some(cid) = existing.and_then(|s| s.stripe_customer_id) {
        return Ok(cid);
    }

    let cid = stripe
        .create_customer(user_id)
        .await
        .map_err(ApiError::Internal)?;

    // Persist the new customer ID on the free-plan subscription row
    db_subs::upsert_subscription(
        &state.db,
        user_id,
        SubscriptionPlan::Free,
        SubscriptionStatus::Active,
        Some(&cid),
        None,
        None,
    )
    .await?;

    Ok(cid)
}

fn stripe_status_to_model(status: &str) -> SubscriptionStatus {
    match status {
        "active" => SubscriptionStatus::Active,
        "past_due" => SubscriptionStatus::PastDue,
        "canceled" | "cancelled" => SubscriptionStatus::Canceled,
        "trialing" => SubscriptionStatus::Trialing,
        _ => SubscriptionStatus::Active,
    }
}

fn price_id_to_plan(state: &AppState, price_id: &str) -> SubscriptionPlan {
    let cfg = &state.config;
    if cfg.stripe_pro_monthly_price_id.as_deref() == Some(price_id)
        || cfg.stripe_pro_annual_price_id.as_deref() == Some(price_id)
    {
        return SubscriptionPlan::Pro;
    }
    if cfg.stripe_teams_price_id.as_deref() == Some(price_id) {
        return SubscriptionPlan::Teams;
    }
    SubscriptionPlan::Free
}

async fn handle_subscription_update(
    state: &AppState,
    stripe_sub: &StripeSubscription,
) -> anyhow::Result<()> {
    let sub = db_subs::get_subscription_by_stripe_customer(&state.db, &stripe_sub.customer)
        .await?;

    let user_sub = match sub {
        Some(s) => s,
        None => {
            tracing::warn!(
                customer = stripe_sub.customer,
                "received subscription event for unknown customer"
            );
            return Ok(());
        }
    };

    let plan = stripe_sub
        .price_id()
        .map(|pid| price_id_to_plan(state, pid))
        .unwrap_or(SubscriptionPlan::Free);

    let status = stripe_status_to_model(&stripe_sub.status);
    let period_end = stripe_sub.period_end_dt();

    db_subs::upsert_subscription(
        &state.db,
        user_sub.user_id,
        plan,
        status,
        Some(&stripe_sub.customer),
        Some(&stripe_sub.id),
        period_end,
    )
    .await?;

    Ok(())
}

async fn handle_subscription_deleted(
    state: &AppState,
    stripe_sub: &StripeSubscription,
) -> anyhow::Result<()> {
    let sub = db_subs::get_subscription_by_stripe_customer(&state.db, &stripe_sub.customer)
        .await?;

    let user_sub = match sub {
        Some(s) => s,
        None => return Ok(()),
    };

    db_subs::upsert_subscription(
        &state.db,
        user_sub.user_id,
        SubscriptionPlan::Free,
        SubscriptionStatus::Canceled,
        Some(&stripe_sub.customer),
        Some(&stripe_sub.id),
        stripe_sub.period_end_dt(),
    )
    .await?;

    Ok(())
}
