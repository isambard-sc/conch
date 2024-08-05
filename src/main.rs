// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::Result;
use axum::{routing::get, Json, Router};
use clap::Parser;
use tracing::info;

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Conch SSH CA
struct Args {
    /// the port to open the service on
    #[arg(long, default_value_t = 3000)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting Conch SSH CA");

    let args = Args::parse();

    let app = Router::new()
        .route("/", get(|| async { Json(serde_json::Value::Null) }))
        .route("/sign", get(sign));
    let listener =
        tokio::net::TcpListener::bind(&std::net::SocketAddr::new("0.0.0.0".parse()?, args.port))
            .await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[tracing::instrument]
async fn sign() {
    info!("Signing an SSH key");
}
