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

/// Alerting on `nopass_login_failures_total` only works if every credential
/// rejection counts: a wrong password the OPAQUE client catches locally only
/// reaches the server as the SRP fallback's failed verify, and a forged proof
/// is rejected at OPAQUE finish.
#[sqlx::test(migrations = "src/db/migrations")]
async fn rejected_credentials_count_as_login_failures(pool: PgPool) {
    let server = build_test_server(pool);
    helpers::register_user(&server, "metrics@example.com", "right password").await;
    let count = || sample(&metrics::render(), "nopass_login_failures_total");

    let before = count();
    // Wrong password: the client rejects the OPAQUE response, falls back to SRP, fails there.
    assert!(helpers::opaque_login_start(&server, "metrics@example.com", "wrong").await.finish_request.is_none());
    helpers::srp_login(&server, "metrics@example.com", "wrong")
        .await
        .assert_status(axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(count() - before, 1.0);

    // A proof from another handshake is rejected at OPAQUE finish.
    let wrong = helpers::opaque_login_start(&server, "metrics@example.com", "wrong").await;
    let other = helpers::opaque_login_start(&server, "metrics@example.com", "right password").await;
    helpers::opaque_login_finish(&server, wrong.login_id, &other.finish_request.unwrap())
        .await
        .assert_status(axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(count() - before, 2.0);
}
