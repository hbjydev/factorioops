use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

pub fn router() -> OpenApiRouter {
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
    req: axum::Json<AuthLoginRequest>,
) -> Result<axum::Json<AuthLoginResponse>, axum::http::StatusCode> {
    // Here you would normally validate the username and password against your database
    if req.username == "admin" && req.password == "password" {
        let response = AuthLoginResponse {
            access_token: "fake-jwt-token".to_string(),
            expires_in: 3600,
        };
        Ok(axum::Json(response))
    } else {
        Err(axum::http::StatusCode::UNAUTHORIZED)
    }
}
