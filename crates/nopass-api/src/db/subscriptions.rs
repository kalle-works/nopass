use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::billing::{Subscription, SubscriptionPlan, SubscriptionStatus};

pub async fn get_subscription(pool: &PgPool, user_id: Uuid) -> Result<Option<Subscription>> {
    let sub = sqlx::query_as::<_, Subscription>(
        "SELECT * FROM subscriptions WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(sub)
}

pub async fn get_subscription_by_stripe_customer(
    pool: &PgPool,
    stripe_customer_id: &str,
) -> Result<Option<Subscription>> {
    let sub = sqlx::query_as::<_, Subscription>(
        "SELECT * FROM subscriptions WHERE stripe_customer_id = $1",
    )
    .bind(stripe_customer_id)
    .fetch_optional(pool)
    .await?;
    Ok(sub)
}

pub async fn upsert_subscription(
    pool: &PgPool,
    user_id: Uuid,
    plan: SubscriptionPlan,
    status: SubscriptionStatus,
    stripe_customer_id: Option<&str>,
    stripe_subscription_id: Option<&str>,
    current_period_end: Option<DateTime<Utc>>,
) -> Result<Subscription> {
    let sub = sqlx::query_as::<_, Subscription>(
        r#"INSERT INTO subscriptions
               (user_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (user_id) DO UPDATE SET
               plan                    = EXCLUDED.plan,
               status                  = EXCLUDED.status,
               stripe_customer_id      = COALESCE(EXCLUDED.stripe_customer_id, subscriptions.stripe_customer_id),
               stripe_subscription_id  = COALESCE(EXCLUDED.stripe_subscription_id, subscriptions.stripe_subscription_id),
               current_period_end      = COALESCE(EXCLUDED.current_period_end, subscriptions.current_period_end),
               updated_at              = NOW()
           RETURNING *"#,
    )
    .bind(user_id)
    .bind(plan)
    .bind(status)
    .bind(stripe_customer_id)
    .bind(stripe_subscription_id)
    .bind(current_period_end)
    .fetch_one(pool)
    .await?;
    Ok(sub)
}

/// Returns the effective plan for a user, defaulting to Free if no subscription row exists.
pub async fn effective_plan(pool: &PgPool, user_id: Uuid) -> Result<SubscriptionPlan> {
    let sub = get_subscription(pool, user_id).await?;
    Ok(match sub {
        Some(s) if s.status.is_access_granted() => s.plan,
        _ => SubscriptionPlan::Free,
    })
}
