// Each test binary compiles the shared helpers on its own and uses a subset
#[allow(dead_code)]
mod helpers;

use helpers::build_test_server;
use nopass_api::metrics;
use sqlx::PgPool;

fn sample(body: &str, series: &str) -> f64 {
    body.lines()
        .find_map(|l| l.strip_prefix(series).and_then(|rest| rest.trim().parse().ok()))
        .unwrap_or(0.0)
}

// Dashboards and alerts key on these names and labels; the route label must
// be the template, or every vault id becomes its own series.
#[sqlx::test(migrations = "src/db/migrations")]
async fn requests_are_counted_per_route_template_and_status(pool: PgPool) {
    let server = build_test_server(pool);
    let series = r#"nopass_http_requests_total{method="GET",route="/v1/vaults/{vault_id}/items",status="401"}"#;
    let before = sample(&metrics::render(), series);

    for _ in 0..2 {
        server
            .get("/v1/vaults/00000000-0000-0000-0000-000000000001/items")
            .await;
    }
    server
        .get("/v1/vaults/00000000-0000-0000-0000-000000000002/items")
        .await;

    let body = metrics::render();
    assert_eq!(sample(&body, series) - before, 3.0, "{body}");
    assert!(body.contains("nopass_http_request_duration_seconds_count"));
}

#[test]
fn login_failure_helper_increments_the_exported_counter() {
    let before = sample(&metrics::render(), "nopass_login_failures_total");
    metrics::record_login_failure();
    let after = sample(&metrics::render(), "nopass_login_failures_total");
    assert_eq!(after - before, 1.0);
}
