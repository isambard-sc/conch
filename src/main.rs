// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, RequestPartsExt as _, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use clap::Parser;
use jsonwebtoken as jwt;
use openidconnect::{
    core::CoreProviderMetadata, reqwest::async_http_client, IssuerUrl, JsonWebKey as _,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_retry::{strategy::FixedInterval, Retry};
use tracing::info;

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Conch SSH CA
struct Args {
    /// the config file
    #[arg(long)]
    config: std::path::PathBuf,
    /// the port to open the service on
    #[arg(long, default_value_t = 3000)]
    port: u16,
}

#[derive(Deserialize)]
struct Config {
    issuer: url::Url,
}

#[derive(Debug)]
struct AppState {
    provider_metadata: CoreProviderMetadata, // TODO Cache this and refresh periodically
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    iss: String,
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .context("Could not extract Bearer header")?;
        let kid = jwt::decode_header(bearer.token())?
            .kid
            .context("Could not decode KID.")?;
        let alg = jwt::decode_header(bearer.token())?.alg;
        let jwk = state
            .provider_metadata
            .jwks()
            .keys()
            .iter()
            .find(|k| k.key_id().is_some_and(|k| k.as_str() == kid))
            .context("Could not find JWK matching KID.")?;
        let jwk = serde_json::from_value(serde_json::to_value(jwk)?)?; // Convert from `openidconnect` to `jsonwebtoken`.
        let mut validation = jwt::Validation::new(alg);
        validation.set_audience(&["account"]);
        let token_data = jwt::decode::<Claims>(
            bearer.token(),
            &jwt::DecodingKey::from_jwk(&jwk)?,
            &validation,
        )
        .context("Could not decode JWT")?;

        Ok(token_data.claims)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting Conch SSH CA");

    let args = Args::parse();

    let config: Config = toml::from_str(
        &std::fs::read_to_string(&args.config)
            .context(format!("Could not read config file {:?}", &args.config))?,
    )
    .context("Cannot parse config file")?;

    let issuer_url = IssuerUrl::from_url(config.issuer);

    let provider_metadata = Retry::spawn(FixedInterval::from_millis(1_000).take(60), || async {
        info!("Trying to access the OIDC endpoints.");
        CoreProviderMetadata::discover_async(issuer_url.clone(), async_http_client)
            .await
            .context("")
    })
    .await?;

    let state = Arc::new(AppState { provider_metadata });

    let app = Router::new()
        .route("/", get(|| async { Json(serde_json::Value::Null) }))
        .route("/sign", get(sign))
        .with_state(state);
    let listener =
        tokio::net::TcpListener::bind(&std::net::SocketAddr::new("0.0.0.0".parse()?, args.port))
            .await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn sign(claims: Claims) {
    info!("Signing an SSH key");
}

// Errors

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message":format!("Something went wrong: {:?}", self.0)})),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
