// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{FromRequestParts, Query, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, RequestPartsExt as _, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization, UserAgent},
    TypedHeader,
};
use clap::Parser;
use jsonwebtoken as jwt;
use openidconnect::{core::CoreProviderMetadata, reqwest::Client, IssuerUrl, JsonWebKey as _};
use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info};

use crate::config::LogFormat;

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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Deserialize, Serialize)]
struct ResourceName(String);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ResourceAlias(String);

mod config {
    use std::collections::HashMap;

    use serde::{Deserialize, Serialize};

    use crate::{Mapper, ResourceAlias, ResourceName};

    #[derive(Debug, Deserialize)]
    pub(crate) struct Config {
        pub(crate) issuer: url::Url,
        pub(crate) signing_key_dir: std::path::PathBuf,
        pub(crate) client_id: openidconnect::ClientId,
        #[serde(default)]
        pub(crate) resources: Resources,
        #[serde(default)]
        pub(crate) log_format: LogFormat,
        pub(crate) mapper: Mapper,
        pub(crate) extensions: Vec<Extension>,
        #[serde(default)]
        /// Internal BriCS: Split by '.' and remove last component
        pub(crate) internal_strip_portal_from_project: bool,
    }

    #[derive(Debug, Deserialize, Default)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum LogFormat {
        #[default]
        Full,
        Json,
    }

    #[derive(Clone, PartialEq, Eq, Hash, Debug, Deserialize)]
    pub(crate) struct Extension(String);

    impl From<Extension> for String {
        fn from(val: Extension) -> Self {
            val.0
        }
    }

    pub(crate) type Resources = HashMap<ResourceName, Resource>;

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub(crate) struct Resource {
        /// The short name that will be used in e.g. a SSH host alias
        pub(crate) alias: ResourceAlias,
        /// The actual hostname of the resource's SSH server.
        #[serde(with = "http_serde::authority")]
        pub(crate) hostname: axum::http::uri::Authority,
        /// The hostname of the SSH jump host.
        pub(crate) proxy_jump: Option<String>,
    }
}

#[derive(Debug)]
struct AppState {
    provider_metadata: CoreProviderMetadata, // TODO Cache this and refresh periodically
    config: config::Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config: config::Config = {
        let mut builder = ::config::Config::builder();
        if let Some(config_file_path) = &args.config {
            builder = builder.add_source(::config::File::from(config_file_path.as_path()));
        };
        builder
            .add_source(::config::Environment::with_prefix("CONCH"))
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
        CoreProviderMetadata::discover_async(issuer_url.clone(), &Client::new())
            .await
            .context("Could not get OIDC metadata.")?;

    let state = Arc::new(AppState {
        provider_metadata,
        config,
    });

    let app = Router::new()
        .route("/", get(|| async { Json(serde_json::Value::Null) }))
        .route("/health", get(health))
        .route("/sign", get(sign))
        .route("/issuer", get(issuer))
        .route("/oidc", get(oidc))
        .route("/public_key", get(public_key))
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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Deserialize, Serialize)]
struct ProjectId(String);

#[derive(Clone, PartialEq, Eq, Hash, Debug, Deserialize, Serialize)]
struct ProjectName(String);

/// A UNIX username as understood by SSH
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Deserialize, Serialize)]
struct Username(String);

/// A prinipal as put in the SSH certificate
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Deserialize, Serialize)]
struct Principal(String);

type Resources = HashMap<ResourceName, Resource>;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Resource {
    /// The short name that will be used in e.g. a SSH host alias
    alias: ResourceAlias,
    /// The actual hostname of the resource's SSH server.
    #[serde(with = "http_serde::authority")]
    hostname: axum::http::uri::Authority,
    /// The hostname of the SSH jump host.
    proxy_jump: Option<String>,
}

impl From<crate::config::Resource> for Resource {
    fn from(resource: crate::config::Resource) -> Self {
        Self {
            alias: resource.alias,
            hostname: resource.hostname,
            proxy_jump: resource.proxy_jump,
        }
    }
}

impl From<Username> for Principal {
    fn from(username: Username) -> Self {
        Self(username.0)
    }
}

#[derive(Clone, Debug, Serialize)]
struct ResourceAssociation {
    username: Username,
    certificate: ssh_key::Certificate,
}

#[derive(Clone, Debug, Deserialize)]
struct ResourceAssociationClaim {
    username: Username,
}

#[derive(Clone, Debug, Serialize)]
struct Project {
    name: ProjectName,
    resources: HashMap<ResourceName, ResourceAssociation>,
}

type ProjectsClaim = HashMap<ProjectId, ProjectClaim>;

#[derive(Clone, Debug, Deserialize)]
struct ProjectClaim {
    name: ProjectName,
    #[serde(deserialize_with = "deserialize_resource_list")]
    resources: HashMap<ResourceName, ResourceAssociationClaim>,
}

/// Allow converting from list of entries to the new format.
/// At some point this will be deprecated.
fn deserialize_resource_list<'de, D>(
    deserializer: D,
) -> Result<HashMap<ResourceName, ResourceAssociationClaim>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct OldResourceAssociationClaim {
        name: ResourceName,
        username: Username,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum EitherType {
        Vec(Vec<OldResourceAssociationClaim>),
        HashMap(HashMap<ResourceName, ResourceAssociationClaim>),
    }

    Ok(match EitherType::deserialize(deserializer)? {
        EitherType::Vec(resource_association_claims) => resource_association_claims
            .iter()
            .map(|claim| {
                (
                    claim.name.clone(),
                    ResourceAssociationClaim {
                        username: claim.username.clone(),
                    },
                )
            })
            .collect(),
        EitherType::HashMap(hash_map) => hash_map,
    })
}

type Projects = HashMap<ProjectId, Project>;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Deserialize)]
struct Claims(serde_json::Value);

impl Claims {
    fn parse<T: DeserializeOwned>(&self, claim_name: &ClaimName) -> Result<T> {
        serde_json::from_value(
            self.0
                .get(&claim_name.0)
                .context(format!("Claim `{}` not present", &claim_name.0))?
                .clone(),
        )
        .context(format!("Could not retrieve claim `{}`.", &claim_name.0))
    }

    fn email(&self) -> Result<String> {
        self.parse(&ClaimName::new("email"))
    }

    fn projects(&self) -> Result<ProjectsClaim> {
        self.parse(&ClaimName::new("projects"))
    }
}

impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = AppError;

    #[tracing::instrument(err(Debug), skip_all)]
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
    resources: Resources,
    associations: Associations,
    user: String,
    version: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Associations {
    Projects(Projects),
    Resources(HashMap<ResourceName, ResourceAssociation>),
}

impl Associations {
    fn principals(&self) -> Result<HashSet<Principal>> {
        let principals: HashSet<Principal> = match self {
            Associations::Projects(projects) => projects
                .iter()
                .flat_map(|(_, project)| {
                    project
                        .resources
                        .values()
                        .map(|resource| resource.username.clone().into())
                })
                .collect(),
            Associations::Resources(resources) => resources
                .iter()
                .map(|(_, resource)| resource.username.clone().into())
                .collect(),
        };
        Ok(principals)
    }

    fn check_principals(&self) -> Result<()> {
        if self.principals()?.is_empty() {
            error!("No valid principals from: associations={:?}", &self);
            anyhow::bail!("No valid principals found after filtering.");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProjectInfraVersion {
    V1,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Deserialize)]
struct ClaimName(String);

impl ClaimName {
    fn new<S: Into<String>>(claim_name: S) -> Self {
        ClaimName(claim_name.into())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mapper {
    ProjectInfra(ProjectInfraVersion),
    Single(ClaimName),
    PerResource(ClaimName),
}

impl Mapper {
    fn map(
        &self,
        claims: &Claims,
        resources: &crate::config::Resources,
        signer: &Signer,
    ) -> Result<Associations> {
        match self {
            Mapper::ProjectInfra(version) => match version {
                ProjectInfraVersion::V1 => {
                    let all_projects = claims.projects()?;

                    // Filter the list of resources in each project so that only those
                    // that are referenced in the relevant resources list are kept.
                    // Finally remove any projects which now have an empty list of resources.
                    let projects = all_projects
                        .iter()
                        .flat_map(|(project_id, project)| -> Result<_> {
                            Ok((
                                project_id.clone(),
                                Project {
                                    name: project.name.clone(),
                                    resources: project
                                        .resources
                                        .iter()
                                        .filter(|(resource_id, _resource)| {
                                            resources.contains_key(resource_id)
                                        })
                                        .map(|(k, v)| {
                                            Ok((
                                                k.clone(),
                                                ResourceAssociation {
                                                    username: v.username.clone(),
                                                    certificate: signer
                                                        .sign(k, &v.username.clone().into())?,
                                                },
                                            ))
                                        })
                                        .collect::<Result<_>>()?,
                                },
                            ))
                        })
                        .filter(|(_, resources)| !resources.resources.is_empty())
                        .collect();
                    Ok(Associations::Projects(projects))
                }
            },
            Mapper::Single(claim_name) => Ok(Associations::Resources(
                resources
                    .iter()
                    .map(|(p_id, _p)| {
                        Ok((
                            p_id.clone(),
                            ResourceAssociation {
                                username: claims.parse(claim_name)?,
                                certificate: signer.sign(p_id, &claims.parse(claim_name)?)?,
                            },
                        ))
                    })
                    .collect::<Result<_>>()?,
            )),
            Mapper::PerResource(claim_name) => Ok(Associations::Resources(
                claims
                    .parse::<HashMap<ResourceName, ResourceAssociationClaim>>(claim_name)?
                    .iter()
                    .filter(|(resource_id, _resource)| resources.contains_key(resource_id))
                    .map(|(k, v)| {
                        Ok((
                            k.clone(),
                            ResourceAssociation {
                                username: v.username.clone(),
                                certificate: signer.sign(k, &v.username.clone().into())?,
                            },
                        ))
                    })
                    .collect::<Result<_>>()?,
            )),
        }
    }
}

/// Provide the certificate signing
/// Currently assumes one signing key for all resources
struct Signer {
    signing_keys: HashMap<ResourceName, ssh_key::PrivateKey>,
    public_key: ssh_key::PublicKey,
    key_id: String,
    extensions: Vec<crate::config::Extension>,
}

impl<'a> Signer {
    fn new(
        signing_keys: HashMap<ResourceName, ssh_key::PrivateKey>,
        public_key: ssh_key::PublicKey,
        key_id: String,
        extensions: Vec<crate::config::Extension>,
    ) -> Self {
        Self {
            signing_keys,
            public_key,
            key_id,
            extensions,
        }
    }

    fn sign(
        &self,
        resource_name: &ResourceName,
        principal: &Principal,
    ) -> Result<ssh_key::Certificate> {
        let principals = [principal];
        let valid_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let valid_before = valid_after + (60 * 60 * 12);
        let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand_core::OsRng,
            &self.public_key,
            valid_after,
            valid_before,
        )
        .context("Could not create SSH certificate builder.")?;
        cert_builder
            .cert_type(ssh_key::certificate::CertType::User)
            .context("Could not set certificte type.")?;
        for principal in principals {
            cert_builder
                .valid_principal(&principal.0)
                .context("Could not set valid principal.")?;
        }
        cert_builder
            .key_id(&self.key_id)
            .context("Could not set key ID.")?;
        cert_builder
            .serial(rand_core::OsRng.next_u64())
            .context("Could not set serial number.")?;
        for extension in &self.extensions {
            cert_builder
                .extension(extension.clone(), "")
                .context("Could not set extension.")?;
        }

        let certificate = cert_builder
            .sign(
                self.signing_keys
                    .get(resource_name)
                    .context("Could not find matching signing key.")?,
            )
            .context("Could not sign key.")?;
        info!("Signed a certificate with serial {}", &certificate.serial());
        Ok(certificate)
    }
}

#[tracing::instrument(
    err(Debug),
    skip_all,
    fields(
        user_agent = &user_agent.map(|h| h.0.to_string()),
        email = claims.email().ok(),
        fingerprint = %payload.0.public_key.fingerprint(Default::default())
    )
)]
async fn sign(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    payload: Query<SignRequest>,
    user_agent: Option<TypedHeader<UserAgent>>,
) -> Result<Json<SignResponse>, AppError> {
    debug!("Signing an SSH key");
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

    let resources = state.config.resources.clone();

    let signing_keys = state
        .config
        .resources
        .iter()
        .map(|(r_id, _)| {
            Ok((
                r_id.clone(),
                ssh_key::PrivateKey::read_openssh_file(
                    &state.config.signing_key_dir.join(r_id.0.clone()),
                )
                .context(format!("Could not load signing key for `{}`.", r_id.0))?,
            ))
        })
        .collect::<Result<_>>()?;

    let signer = Signer::new(
        signing_keys,
        payload.public_key.clone(),
        claims.email()?,
        state.config.extensions.clone(),
    );

    let associations = state.config.mapper.map(&claims, &resources, &signer)?;

    // The BriCS service adds a `.brics` suffix to the end of all project names at
    // the moment which looks messy. This option remove the suffix.
    let associations = if state.config.internal_strip_portal_from_project {
        if let Associations::Projects(projects) = associations {
            Associations::Projects(
                projects
                    .iter()
                    .map(|(project_id, project)| {
                        let project_components = project_id.0.split(".").collect::<Vec<&str>>();
                        let project_id = ProjectId(
                            project_components[0..project_components.len() - 1].join("."),
                        );
                        (project_id, project.clone())
                    })
                    .collect(),
            )
        } else {
            return Err(anyhow::anyhow!("Config variable `internal_strip_portal_from_project` incompatible with non-`project_infra` mapper types.").into());
        }
    } else {
        associations
    };

    associations.check_principals()?;

    let response = SignResponse {
        associations,
        resources: resources
            .into_iter()
            .map(|(r_id, r)| (r_id, r.into()))
            .collect(),
        user: claims.email()?,
        version: 3,
    };
    Ok(Json(response))
}

#[tracing::instrument(skip_all)]
async fn issuer(State(state): State<Arc<AppState>>) -> Result<String, AppError> {
    Ok(state.provider_metadata.issuer().to_string())
}

#[derive(Debug, Serialize)]
struct OidcResponse {
    issuer: openidconnect::IssuerUrl,
    client_id: openidconnect::ClientId,
    version: u32,
}

#[tracing::instrument(skip_all)]
async fn oidc(State(state): State<Arc<AppState>>) -> Result<Json<OidcResponse>, AppError> {
    Ok(Json(OidcResponse {
        issuer: state.provider_metadata.issuer().clone(),
        client_id: state.config.client_id.clone(),
        version: 1,
    }))
}

#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    keys: HashMap<ResourceName, ssh_key::PublicKey>,
    version: u32,
}

#[tracing::instrument(skip_all)]
async fn public_key(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PublicKeyResponse>, AppError> {
    let keys = state
        .config
        .resources
        .iter()
        .map(|(r_id, _)| {
            Ok((
                r_id.clone(),
                ssh_key::PrivateKey::read_openssh_file(
                    &state.config.signing_key_dir.join(r_id.0.to_owned()),
                )
                .context("Could not load signing key.")?
                .public_key()
                .to_owned(),
            ))
        })
        .collect::<Result<_>>()?;
    Ok(Json(PublicKeyResponse { keys, version: 2 }))
}

#[tracing::instrument(skip_all)]
async fn health() -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(json!({})))
}

// Errors

#[derive(Debug)]
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

#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[rstest::fixture]
    fn simple_claims() -> Claims {
        let jwt_payload = json!({
            "email": "user1@example.com",
        });
        serde_json::from_value(jwt_payload).expect("Could not parse claims.")
    }

    fn make_signer(resources: &crate::config::Resources, email: String) -> Signer {
        let public_key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .expect("")
        .public_key()
        .clone();
        let signing_keys = resources
            .keys()
            .map(|r_id| {
                (
                    r_id.to_owned(),
                    ssh_key::PrivateKey::random(
                        &mut ssh_key::rand_core::OsRng,
                        ssh_key::Algorithm::Ed25519,
                    )
                    .expect(""),
                )
            })
            .collect();
        Signer::new(signing_keys, public_key, email, vec![])
    }

    #[rstest::fixture]
    fn claims_with_resource_associations() -> Claims {
        let jwt_payload = json!({
            "email": "user1@example.com",
            "resources": {
                "cluster1": {
                    "username": "user1.c1",
                },
                "cluster2": {
                    "username": "user1.c2",
                },
                "cluster3": {
                    "username": "user_one.c3",
                },
            },
        });
        serde_json::from_value(jwt_payload).expect("Could not parse claims.")
    }

    #[rstest::fixture]
    fn claims_with_project_associations() -> Claims {
        let jwt_payload = json!({
            "email": "user1@example.com",
            "projects": {
                "proj1": {
                    "name": "Project 1",
                    "resources": {
                        "cluster1": {
                            "username": "user1.p1",
                        },
                        "cluster2": {
                            "username": "user1.p1",
                        },
                        "cluster3": {
                            "username": "user_one.p1",
                        },
                    },
                },
                "proj2": {
                    "name": "Project 2",
                    "resources": [ // Use the old-form resources list
                        {
                            "name": "cluster1",
                            "username": "user1.p2",
                        },
                        {
                            "name": "cluster2",
                            "username": "user_one.p2",
                        },
                        {
                            "name": "unknown_cluster",
                            "username": "user1.unknown",
                        },
                    ],
                },
            },
        });
        serde_json::from_value(jwt_payload).expect("Could not parse claims.")
    }

    #[rstest::fixture]
    fn resources() -> crate::config::Resources {
        [
            (
                ResourceName("cluster1".to_string()),
                crate::config::Resource {
                    alias: ResourceAlias("1.site".to_string()),
                    hostname: axum::http::uri::Authority::from_static("c1.example.com"),
                    proxy_jump: None,
                },
            ),
            (
                ResourceName("cluster2".to_string()),
                crate::config::Resource {
                    alias: ResourceAlias("2.site".to_string()),
                    hostname: axum::http::uri::Authority::from_static("c2.example.com"),
                    proxy_jump: None,
                },
            ),
            (
                ResourceName("private_cluster".to_string()),
                crate::config::Resource {
                    alias: ResourceAlias("priv.site".to_string()),
                    hostname: axum::http::uri::Authority::from_static("priv.example.com"),
                    proxy_jump: None,
                },
            ),
        ]
        .into()
    }

    #[rstest::fixture]
    fn unmatching_resources() -> crate::config::Resources {
        [
            (
                ResourceName("othercluster1".to_string()),
                crate::config::Resource {
                    alias: ResourceAlias("1.othersite".to_string()),
                    hostname: axum::http::uri::Authority::from_static("c1.example.org"),
                    proxy_jump: None,
                },
            ),
            (
                ResourceName("othercluster2".to_string()),
                crate::config::Resource {
                    alias: ResourceAlias("2.othersite".to_string()),
                    hostname: axum::http::uri::Authority::from_static("c2.example.org"),
                    proxy_jump: None,
                },
            ),
        ]
        .into()
    }

    #[rstest::rstest]
    fn single(resources: crate::config::Resources, simple_claims: Claims) -> Result<()> {
        let signer = make_signer(&resources, simple_claims.email()?);
        let principals = Mapper::Single(ClaimName("email".to_string()))
            .map(&simple_claims, &resources, &signer)?
            .principals()?;
        assert_eq!(
            &principals,
            &[Principal("user1@example.com".to_string())].into()
        );

        Ok(())
    }

    #[rstest::rstest]
    fn resource_usernames(
        resources: crate::config::Resources,
        claims_with_resource_associations: Claims,
    ) -> Result<()> {
        let signer = make_signer(&resources, claims_with_resource_associations.email()?);
        let principals = Mapper::PerResource(ClaimName("resources".to_string()))
            .map(&claims_with_resource_associations, &resources, &signer)?
            .principals()?;
        assert_eq!(
            &principals,
            &[
                Principal("user1.c2".to_string()),
                Principal("user1.c1".to_string()),
            ]
            .into()
        );

        Ok(())
    }

    #[rstest::rstest]
    fn resource_usernames_unmatching(
        unmatching_resources: crate::config::Resources,
        claims_with_resource_associations: Claims,
    ) -> Result<()> {
        let signer = make_signer(
            &unmatching_resources,
            claims_with_resource_associations.email()?,
        );
        let principals = Mapper::PerResource(ClaimName("resources".to_string()))
            .map(
                &claims_with_resource_associations,
                &unmatching_resources,
                &signer,
            )?
            .check_principals();
        if let Ok(p) = &principals {
            anyhow::bail!("Error should be returned. Got {p:?}");
        };

        Ok(())
    }

    #[rstest::rstest]
    fn project_usernames(
        resources: crate::config::Resources,
        claims_with_project_associations: Claims,
    ) -> Result<()> {
        let signer = make_signer(&resources, claims_with_project_associations.email()?);
        let principals = Mapper::ProjectInfra(ProjectInfraVersion::V1)
            .map(&claims_with_project_associations, &resources, &signer)?
            .principals()?;
        assert_eq!(
            &principals,
            &[
                Principal("user_one.p2".to_string()),
                Principal("user1.p2".to_string()),
                Principal("user1.p1".to_string()),
            ]
            .into()
        );

        Ok(())
    }
}
