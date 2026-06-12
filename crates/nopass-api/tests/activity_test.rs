mod helpers;

use axum::http::StatusCode;
use helpers::{build_test_server, login, register_user};
use nopass_models::ActivityEventInfo;
use sqlx::PgPool;

const EMAIL: &str = "activity@example.com";
const PASSWORD: &str = "correct horse battery staple";

#[sqlx::test(migrations = "src/db/migrations")]
async fn activity_records_logins_and_requires_auth(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    // Unauthenticated access is rejected
    server.get("/v1/activity").await.assert_status(StatusCode::UNAUTHORIZED);

    let events: Vec<ActivityEventInfo> = server
        .get("/v1/activity")
        .authorization_bearer(&session.session_token)
        .await
        .json();

    assert!(events.iter().any(|e| e.event_type == "login_succeeded"));
    assert!(events.iter().all(|e| e.ip.is_some()));

    // A second login adds another event
    let _again = login(&server, EMAIL, PASSWORD).await;
    let events2: Vec<ActivityEventInfo> = server
        .get("/v1/activity")
        .authorization_bearer(&session.session_token)
        .await
        .json();
    let count = |evs: &[ActivityEventInfo]| evs.iter().filter(|e| e.event_type == "login_succeeded").count();
    assert_eq!(count(&events2), count(&events) + 1);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn activity_is_scoped_to_the_user(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    register_user(&server, "other@example.com", PASSWORD).await;
    let _a = login(&server, EMAIL, PASSWORD).await;
    let b = login(&server, "other@example.com", PASSWORD).await;

    let events: Vec<ActivityEventInfo> = server
        .get("/v1/activity")
        .authorization_bearer(&b.session_token)
        .await
        .json();

    // Only B's own single login — not A's
    assert_eq!(events.iter().filter(|e| e.event_type == "login_succeeded").count(), 1);
}
