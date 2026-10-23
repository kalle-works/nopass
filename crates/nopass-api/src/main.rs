use dotenvy::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // One-off secret generation for deployments; prints and exits without
    // touching the database.
    if std::env::args().nth(1).as_deref() == Some("generate-opaque-setup") {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        println!("{}", URL_SAFE_NO_PAD.encode(nopass_crypto::opaque::generate_server_setup()));
        return Ok(());
    }

    dotenv().ok();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "nopass_api=debug,tower_http=info".into());

    let use_json = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if use_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    nopass_api::run().await
}
