use axum::extract::State;
use factorioops_auth::passwords::{Hasher, Password};
use factorioops_models::user::DbUser;
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(login))
        .routes(routes!(register))
}

#[derive(Deserialize, ToSchema)]
pub struct AuthLoginRequest {
    /// The username of the user attempting to log in.
    pub username: String,

    /// The password of the user attempting to log in.
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct AuthLoginResponse {
    /// The JWT access token for the authenticated user.
    #[schema(example = "eyJhbg...")]
    pub access_token: String,

    /// The number of seconds until the access token expires.
    #[schema(example = 3600)]
    pub expires_in: u64,
}

/// Login
///
/// Login endpoint for user authentication. Returns a JWT token on successful
/// authentication.
#[utoipa::path(
    post,
    path = "/login",
    responses(
        (status = OK, body = AuthLoginResponse),
    ),
    tag = crate::AUTH_TAG,
)]
#[tracing::instrument(skip(state, req))]
pub async fn login(
    State(state): State<crate::AppState>,
    req: axum::Json<AuthLoginRequest>,
) -> Result<axum::Json<AuthLoginResponse>, axum::http::StatusCode> {
    let user = state
        .db
        .get_user_by_username(req.username.clone())
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    if user.is_none() {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let user = user.unwrap();

    let hasher = Hasher::default();
    let is_ok = hasher
        .verify_password(
            &Password::new(&req.password).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?,
            &user.password_hash,
        )
        .map_err(|e| {
            error!("Failed to verify password: {:?}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Here you would normally validate the username and password against your database
    if is_ok {
        let response = AuthLoginResponse {
            access_token: "fake-jwt-token".to_string(),
            expires_in: 3600,
        };
        Ok(axum::Json(response))
    } else {
        Err(axum::http::StatusCode::UNAUTHORIZED)
    }
}

#[derive(Deserialize, ToSchema)]
pub struct AuthRegisterRequest {
    /// The username of the user attempting to register.
    #[schema(example = "jdoe.loves.factorio")]
    pub username: String,

    /// The email to use for the user attempting to register.
    #[schema(example = "john.doe1999@gmail.com")]
    pub email: String,

    /// The password of the user attempting to register.
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct AuthRegisterResponse {
    /// The JWT access token for the authenticated user.
    #[schema(example = "eyJhbg...")]
    pub access_token: String,

    /// The number of seconds until the access token expires.
    #[schema(example = 3600)]
    pub expires_in: u64,
}

/// Register
///
/// Register endpoint for user authentication. Returns a JWT token on successful
/// authentication.
#[utoipa::path(
    post,
    path = "/register",
    responses(
        (status = OK, body = AuthRegisterResponse),
    ),
    tag = crate::AUTH_TAG,
)]
#[axum::debug_handler]
#[tracing::instrument(skip(state, req))]
pub async fn register(
    State(state): State<crate::AppState>,
    req: axum::Json<AuthRegisterRequest>,
) -> Result<axum::Json<AuthRegisterResponse>, axum::http::StatusCode> {
    let password = Password::new(&req.password).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let user = DbUser::create(req.username.clone(), password, req.email.clone()).map_err(|e| {
        error!("Failed to create user: {:?}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    state.db.create_user(user).await.map_err(|e| {
        error!("Failed to insert user: {:?}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let response = AuthRegisterResponse {
        access_token: "fake-jwt-token".to_string(),
        expires_in: 3600,
    };

    Ok(axum::Json(response))
}
