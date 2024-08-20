// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Context, Result};
use axum::{
    async_trait,
    extract::{FromRequestParts, Query, State},
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
use tracing::{error, info};

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn version() -> &'static str {
    built_info::GIT_VERSION.unwrap_or(built_info::PKG_VERSION)
}

#[derive(Parser)]
#[command(version = version(), about, long_about = None)]
/// Conch SSH CA
struct Args {
    /// the config file
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// the port to open the service on
    #[arg(long, default_value_t = 3000)]
    port: u16,
}

#[derive(Debug, Deserialize)]
struct Config {
    issuer: url::Url,
    signing_key_path: std::path::PathBuf,
    #[serde(default)]
    platforms: Platforms,
    #[serde(default)]
    log_format: LogFormat,
}

#[derive(Debug, Deserialize, Default)]
enum LogFormat {
    #[default]
    Full,
    Json,
}

type Platforms = HashMap<String, Platform>;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Platform {
    #[serde(skip_serializing)]
    alias: String,
    #[serde(with = "http_serde::authority")]
    hostname: axum::http::uri::Authority,
    #[serde(with = "http_serde::authority")]
    proxy_jump: axum::http::uri::Authority,
}

#[derive(Debug)]
struct AppState {
    provider_metadata: CoreProviderMetadata, // TODO Cache this and refresh periodically
    config: Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config: Config = {
        let mut builder = config::Config::builder();
        if let Some(config_file_path) = &args.config {
            builder = builder.add_source(config::File::from(config_file_path.as_path()));
        };
        builder
            .add_source(config::Environment::with_prefix("CONCH"))
            .build()
            .context("Could not build config description.")?
            .try_deserialize()
            .context("Could not build config.")?
    };
    let sub = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
    match config.log_format {
        LogFormat::Full => sub.init(),
        LogFormat::Json => sub.json().init(),
    };
    info!("Starting Conch SSH CA {}", version());

    let issuer_url = IssuerUrl::from_url(config.issuer.clone());

    info!("Trying to access the OIDC endpoints.");
    let provider_metadata =
        CoreProviderMetadata::discover_async(issuer_url.clone(), async_http_client)
            .await
            .context("Could not get OIDC metadata.")?;

    let state = Arc::new(AppState {
        provider_metadata,
        config,
    });

    let app = Router::new()
        .route("/", get(|| async { Json(serde_json::Value::Null) }))
        .route("/sign", get(sign))
        .route("/issuer", get(issuer))
        .with_state(state);
    let listener =
        tokio::net::TcpListener::bind(&std::net::SocketAddr::new("::".parse()?, args.port)).await?;
    info!("Starting server.");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Exiting.");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        #[allow(clippy::expect_used)]
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        #[allow(clippy::expect_used)]
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    iss: String,
    short_name: String,
    projects: HashMap<String, Vec<String>>,
    email: String,
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
            .context("Could not extract Bearer header")
            .status(axum::http::StatusCode::UNAUTHORIZED)?;
        let header =
            jwt::decode_header(bearer.token()).context("Could not decode bearer header")?;
        let kid = header.kid.context("Could not decode KID.")?;
        let alg = header.alg;
        let jwk = state
            .provider_metadata
            .jwks()
            .keys()
            .iter()
            .find(|k| k.key_id().is_some_and(|k| k.as_str() == kid))
            .context("Could not find JWK matching KID.")
            .status(axum::http::StatusCode::FORBIDDEN)?;
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

#[derive(Debug, Deserialize)]
struct SignRequest {
    public_key: ssh_key::PublicKey,
}

#[derive(Debug, Serialize)]
struct SignResponse {
    platforms: Platforms,
    certificate: ssh_key::Certificate,
    projects: Projects,
    short_name: String,
    user: String,
    version: u32,
}

type Projects = HashMap<String, Vec<String>>;

#[tracing::instrument(skip(state))]
async fn sign(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    payload: Query<SignRequest>,
) -> Result<Json<SignResponse>, AppError> {
    info!("Signing an SSH key");
    match payload.public_key.key_data() {
        ssh_key::public::KeyData::Rsa(k) => {
            // https://github.com/RustCrypto/SSH/issues/261
            if k.n
                .as_positive_bytes()
                .context("Could not interpret key RSA modulus as positive integer.")?
                .len()
                * 8
                < 3072
            {
                return Err(anyhow!("RSA keys must be at least 3072 bits long.").into());
            }
        }
        ssh_key::public::KeyData::Dsa(_) => {
            return Err(anyhow!("DSA keys are not supported.").into());
        }
        _ => (),
    };
    let signing_key = ssh_key::PrivateKey::read_openssh_file(&state.config.signing_key_path)
        .context("Could not load signing key.")?;

    // Filter the list of platforms in each project so that only those
    // that are referenced in the relevant platforms list are kept.
    // It also alters the platform name into its alias.
    let projects: Projects = claims
        .projects
        .iter()
        .map(|(project, platforms)| {
            (
                project.clone(),
                platforms
                    .iter()
                    .filter_map(|platform_name| {
                        state
                            .config
                            .platforms
                            .get(platform_name)
                            .map(|platform| platform.alias.clone())
                    })
                    .collect::<Vec<String>>(),
            )
        })
        .collect();

    // Mutate the platform config to have the alias as its name
    let platforms = state
        .config
        .platforms
        .values()
        .map(|c| (c.alias.clone(), c.clone()))
        .collect();
    let short_name = claims.short_name;

    let principals: Vec<String> = projects
        .values()
        .flat_map(|ps| ps.iter().map(|p| format!("{short_name}.{}", p)))
        .collect();
    if principals.is_empty() {
        error!(
            "No valid principals from: user_projects={:?}, config_platforms={:?}",
            &claims.projects, &state.config.platforms
        );
        return Err(anyhow::anyhow!("No valid pricipals found after filtering.").into());
    }
    let valid_after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let valid_before = valid_after + (60 * 60 * 12);
    let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand_core::OsRng,
        &payload.public_key,
        valid_after,
        valid_before,
    )
    .context("Could not create SSH certificate builder.")?;
    cert_builder
        .cert_type(ssh_key::certificate::CertType::User)
        .context("Could not set certificte type.")?;
    for principal in principals {
        cert_builder
            .valid_principal(principal)
            .context("Could not set valid principal.")?;
    }
    cert_builder
        .key_id(
            serde_json::to_string(&serde_json::json!({"projects": projects}))
                .context("Could not encode JSON.")?,
        )
        .context("Could not set key ID.")?;
    cert_builder
        .extension("permit-agent-forwarding", "")
        .context("Could not set extension.")?;
    cert_builder
        .extension("permit-port-forwarding", "")
        .context("Could not set extension.")?;
    cert_builder
        .extension("permit-pty", "")
        .context("Could not set extension.")?;
    let certificate = cert_builder
        .sign(&signing_key)
        .context("Could not sign key.")?;

    let response = SignResponse {
        certificate,
        projects,
        short_name,
        platforms,
        user: claims.email,
        version: 2,
    };
    info!(response = ?response);
    Ok(Json(response))
}

#[tracing::instrument(skip(state))]
async fn issuer(State(state): State<Arc<AppState>>) -> Result<String, AppError> {
    Ok(state.provider_metadata.issuer().to_string())
}

// Errors

struct AppError(anyhow::Error, Option<axum::http::StatusCode>);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            self.1.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(json!({"message":format!("Something went wrong: {:?}", self.0)})),
        )
            .into_response()
    }
}

trait Status<T> {
    /// Add a HTTP status code to an error.
    fn status(self, status: axum::http::StatusCode) -> Result<T, AppError>;
}

impl<T> Status<T> for anyhow::Result<T> {
    fn status(self, status: axum::http::StatusCode) -> Result<T, AppError> {
        self.map_err(|e| AppError(e, Some(status)))
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into(), None)
    }
}
