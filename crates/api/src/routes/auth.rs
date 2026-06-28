use axum::extract::State;
use factorioops_models::user::UserStore;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(login))
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
pub async fn login(
    State(state): State<crate::AppState>,
    req: axum::Json<AuthLoginRequest>,
) -> Result<axum::Json<AuthLoginResponse>, axum::http::StatusCode> {
    let user = state
        .db
        .get_user_by_username(req.username.clone())
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    println!("User: {:?}", user);

    // Here you would normally validate the username and password against your database
    if req.password == "password" {
        let response = AuthLoginResponse {
            access_token: "fake-jwt-token".to_string(),
            expires_in: 3600,
        };
        Ok(axum::Json(response))
    } else {
        Err(axum::http::StatusCode::UNAUTHORIZED)
    }
}
