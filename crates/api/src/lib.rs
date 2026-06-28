use std::sync::Arc;

use axum_otel::{AxumOtelOnFailure, AxumOtelOnResponse, AxumOtelSpanCreator};
use tower::ServiceBuilder;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tower_otel::metrics;
use tracing::Level;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_scalar::{Scalar, Servable};

pub use axum::serve;

mod routes;

pub(crate) const AUTH_TAG: &str = "auth";
pub(crate) const BLUEPRINT_TAG: &str = "blueprint";
pub(crate) const BOOK_TAG: &str = "book";

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Factorioops API",
        description = "The API for Factorioops, the Factorio blueprint sharing platform.",
        version = env!("CARGO_PKG_VERSION"),
        license(
            name = "Apache-2.0",
            url = "https://opensource.org/licenses/Apache-2.0"
        )
    ),
    tags(
        (name = AUTH_TAG, description = "Authentication API endpoints"),
        (name = BLUEPRINT_TAG, description = "Blueprint API endpoints"),
        (name = BOOK_TAG, description = "Blueprint Book API endpoints"),
    )
)]
struct ApiDoc;

pub fn router()
-> Result<(axum::Router<AppState>, utoipa::openapi::OpenApi), Box<dyn std::error::Error>> {
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/v1/auth", routes::auth::router())
        .split_for_parts();

    let meter = opentelemetry::global::meter(env!("CARGO_PKG_NAME"));

    let router = router.merge(Scalar::with_url("/docs", api.clone())).layer(
        ServiceBuilder::new()
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            .layer(metrics::HttpLayer::server(&meter))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(AxumOtelSpanCreator::new().level(Level::INFO))
                    .on_response(AxumOtelOnResponse::new().level(Level::INFO))
                    .on_failure(AxumOtelOnFailure::new().level(Level::ERROR)),
            )
            .layer(PropagateRequestIdLayer::x_request_id()),
    );

    Ok((router, api))
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn factorioops_models::Storage>,
}

impl AppState {
    pub fn new(db: Arc<dyn factorioops_models::Storage>) -> Self {
        Self { db }
    }
}
