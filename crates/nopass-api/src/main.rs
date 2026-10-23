use dotenvy::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Exec-probe entry point: no logging, no database, just the verdict
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(nopass_api::healthcheck::run());
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
