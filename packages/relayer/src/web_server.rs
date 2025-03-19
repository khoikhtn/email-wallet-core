use crate::*;

use crate::utils::{get_account_key_from_mail, get_wallet_from_account_key, WalletInfo};
use axum::extract::State;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use axum::response::IntoResponse;
use oauth2::http::StatusCode;
use thiserror::Error;
use tokio::sync::mpsc::UnboundedSender;
use tower_http::cors::{AllowHeaders, AllowMethods, Any, CorsLayer};

#[derive(Deserialize)]
struct EmailAddrCommitRequest {
    email_address: String,
    random: String,
}

#[derive(Deserialize)]
struct UnclaimRequest {
    email_address: String,
    random: String,
    expiry_time: i64,
    is_fund: bool,
    tx_hash: String,
}

#[derive(Deserialize)]
struct AccountRegistrationRequest {
    email_address: String,
    account_key: String,
}

#[derive(Serialize)]
struct AccountRegistrationResponse {
    account_key: String,
    wallet_addr: String,
    tx_hash: String,
}

#[derive(Serialize)]
struct StatResponse {
    onboarding_tokens_distributed: u32,
    onboarding_tokens_left: u32,
}

#[named]
async fn unclaim(
    payload: UnclaimRequest,
    db: Arc<Database>,
    chain_client: Arc<ChainClient>,
    tx_claimer: UnboundedSender<Claim>,
) -> Result<String> {
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&payload.email_address);
    info!(
        LOG,
        "padded email address fields: {:?}",
        padded_email_addr.to_email_addr_fields(); "func" => function_name!()
    );
    let commit = padded_email_addr.to_commitment(&hex2field(&payload.random)?)?;
    info!(LOG, "commit {:?}", commit; "func" => function_name!());
    let id = chain_client
        .get_unclaim_id_from_tx_hash(&payload.tx_hash, payload.is_fund)
        .await?;
    info!(LOG, "id {:?}", id; "func" => function_name!());
    let psi_client = PSIClient::new(
        Arc::clone(&chain_client),
        payload.email_address.clone(),
        id,
        payload.is_fund,
    )
    .await?;
    psi_client
        .check_and_reveal(db.clone(), chain_client.clone(), &payload.email_address)
        .await?;
    let claim = Claim {
        id,
        email_address: payload.email_address.clone(),
        random: payload.random.clone(),
        commit: field2hex(&commit),
        expiry_time: payload.expiry_time,
        is_fund: payload.is_fund,
        is_announced: false,
    };
    tx_claimer.send(claim)?;
    trace!(LOG, "claim sent to tx_claimer"; "func" => function_name!());

    Ok(format!(
        "Unclaimed {} for {} is accepted",
        if payload.is_fund { "fund" } else { "state" },
        payload.email_address
    ))
}

#[named]
pub(crate) async fn run_server(
    addr: &str,
    db: Arc<Database>,
    chain_client: Arc<ChainClient>,
    tx_claimer: UnboundedSender<Claim>,
) -> Result<()> {
    let chain_client_check_clone = Arc::clone(&chain_client);
    let chain_client_reveal_clone = Arc::clone(&chain_client);
    let tx_claimer_reveal_clone = tx_claimer.clone();

    let app_state = AppState { db };

    let app = Router::new()
        .route(
            "/get-wallet-address",
            axum::routing::post(get_wallet_from_email),
        )
        .with_state(app_state)
        .layer(
            CorsLayer::new()
                .allow_methods(AllowMethods::any())
                .allow_headers(AllowHeaders::any())
                .allow_origin(Any),
        );

    trace!(LOG, "Listening API at {}", addr; "func" => function_name!());
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    pub db: Arc<Database>,
}

async fn get_wallet_from_email(
    State(app_state): State<AppState>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let email = request["email"].as_str().unwrap().to_string();
    let account_key = get_account_key_from_mail(&email, &app_state.db).await?;
    if account_key.is_none() {
        return Err(AppError::Unknown(anyhow!("Email not found")));
    }
    let WalletInfo {
        salt: sender_salt,
        address: sender_xion_addr,
    } = get_wallet_from_account_key(&account_key.unwrap()).await?;
    Ok(Json(json!({
        "address": sender_xion_addr
    })))
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("unknown error")]
    Unknown(#[from] anyhow::Error),
}

// Tell axum how `AppError` should be converted into a response.
//
// This is also a convenient place to log errors.
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // How we want errors responses to be serialized

        let (status, message) = match self {
            AppError::Unknown(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        };
        (status, message).into_response()
    }
}