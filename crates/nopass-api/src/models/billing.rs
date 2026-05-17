use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "subscription_plan", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionPlan {
    Free,
    Pro,
    Teams,
    Enterprise,
}

impl SubscriptionPlan {
    /// Max active org members allowed on this plan (across all orgs the user owns).
    pub fn org_member_limit(&self) -> Option<usize> {
        match self {
            Self::Free => Some(3),
            Self::Pro | Self::Teams | Self::Enterprise => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "subscription_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Canceled,
    Trialing,
}

impl SubscriptionStatus {
    pub fn is_access_granted(&self) -> bool {
        matches!(self, Self::Active | Self::Trialing)
    }
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: Uuid,
    pub user_id: Uuid,
    pub plan: SubscriptionPlan,
    pub status: SubscriptionStatus,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Request / Response ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCheckoutRequest {
    /// Stripe price ID (e.g. STRIPE_PRO_MONTHLY_PRICE_ID).
    pub price_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckoutSessionResponse {
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePortalRequest {
    pub return_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalSessionResponse {
    pub url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingStatusResponse {
    pub plan: SubscriptionPlan,
    pub status: SubscriptionStatus,
    pub current_period_end: Option<DateTime<Utc>>,
    pub stripe_customer_id: Option<String>,
}
