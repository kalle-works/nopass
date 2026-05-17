/// Minimal Stripe API client — uses direct HTTP (reqwest) to avoid coupling to
/// a versioned Stripe Rust SDK. Only the endpoints needed for subscription
/// billing are implemented.
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Deserialize;
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";

// ─── Client ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct StripeClient {
    http: Client,
    secret_key: String,
    webhook_secret: String,
}

impl StripeClient {
    pub fn new(secret_key: String, webhook_secret: String) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed to create HTTP client")?;
        Ok(Self { http, secret_key, webhook_secret })
    }

    async fn post_form(&self, path: &str, params: Vec<(&str, &str)>) -> Result<serde_json::Value> {
        let url = format!("{STRIPE_API_BASE}{path}");
        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .form(&params)
            .send()
            .await
            .context("Stripe request failed")?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.context("failed to parse Stripe response")?;

        if !status.is_success() {
            let msg = body["error"]["message"]
                .as_str()
                .unwrap_or("unknown Stripe error");
            return Err(anyhow!("Stripe error {status}: {msg}"));
        }
        Ok(body)
    }

    // ─── Customers ───────────────────────────────────────────────────────────

    pub async fn create_customer(&self, user_id: Uuid) -> Result<String> {
        let uid = user_id.to_string();
        let body = self
            .post_form(
                "/customers",
                vec![("metadata[user_id]", uid.as_str())],
            )
            .await?;
        body["id"]
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| anyhow!("missing customer id in Stripe response"))
    }

    // ─── Checkout sessions ───────────────────────────────────────────────────

    pub async fn create_checkout_session(
        &self,
        customer_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<String> {
        let body = self
            .post_form(
                "/checkout/sessions",
                vec![
                    ("customer", customer_id),
                    ("mode", "subscription"),
                    ("line_items[0][price]", price_id),
                    ("line_items[0][quantity]", "1"),
                    ("success_url", success_url),
                    ("cancel_url", cancel_url),
                ],
            )
            .await?;
        body["url"]
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| anyhow!("missing url in Stripe checkout session response"))
    }

    // ─── Customer portal ─────────────────────────────────────────────────────

    pub async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<String> {
        let body = self
            .post_form(
                "/billing_portal/sessions",
                vec![("customer", customer_id), ("return_url", return_url)],
            )
            .await?;
        body["url"]
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| anyhow!("missing url in Stripe portal session response"))
    }

    // ─── Webhook verification ────────────────────────────────────────────────

    /// Verify the `Stripe-Signature` header and deserialize the event.
    ///
    /// Stripe signs webhooks with HMAC-SHA256.  The signed payload is
    /// `{timestamp}.{raw_body}`, and the header contains `t={ts},v1={hex_sig}`.
    /// We accept events within a ±300 second tolerance window.
    pub fn construct_event(&self, payload: &[u8], signature_header: &str) -> Result<StripeEvent> {
        let mut timestamp: Option<i64> = None;
        let mut signatures: Vec<&str> = Vec::new();

        for part in signature_header.split(',') {
            if let Some(t) = part.strip_prefix("t=") {
                timestamp = Some(t.parse().context("invalid timestamp in Stripe-Signature")?);
            } else if let Some(v) = part.strip_prefix("v1=") {
                signatures.push(v);
            }
        }

        let timestamp = timestamp.ok_or_else(|| anyhow!("missing t= in Stripe-Signature"))?;

        // Tolerance: reject events older than 5 minutes
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if (now - timestamp).abs() > 300 {
            return Err(anyhow!("Stripe webhook timestamp outside tolerance window"));
        }

        // Signed payload = "{timestamp}.{raw_body}"
        let ts_str = timestamp.to_string();
        let mut signed = ts_str.as_bytes().to_vec();
        signed.push(b'.');
        signed.extend_from_slice(payload);

        let mut mac =
            HmacSha256::new_from_slice(self.webhook_secret.as_bytes()).context("HMAC init")?;
        mac.update(&signed);
        let expected = hex::encode(mac.finalize().into_bytes());

        if !signatures.iter().any(|s| constant_time_eq(s, &expected)) {
            return Err(anyhow!("Stripe webhook signature verification failed"));
        }

        serde_json::from_slice(payload).context("failed to parse Stripe event JSON")
    }
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ─── Webhook event types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

impl StripeEvent {
    /// Deserialize `data.object` as a subscription event.
    pub fn as_subscription(&self) -> Option<StripeSubscription> {
        serde_json::from_value(self.data.object.clone()).ok()
    }
}

#[derive(Debug, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub customer: String,
    pub status: String,
    pub items: StripeSubscriptionItems,
    pub current_period_end: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct StripeSubscriptionItems {
    pub data: Vec<StripeSubscriptionItem>,
}

#[derive(Debug, Deserialize)]
pub struct StripeSubscriptionItem {
    pub price: StripePrice,
}

#[derive(Debug, Deserialize)]
pub struct StripePrice {
    pub id: String,
}

impl StripeSubscription {
    pub fn price_id(&self) -> Option<&str> {
        self.items.data.first().map(|i| i.price.id.as_str())
    }

    pub fn period_end_dt(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.current_period_end
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
    }
}
