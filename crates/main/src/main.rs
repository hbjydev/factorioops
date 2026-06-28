use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use factorioops_core::result::Result;
use factorioops_core::result::error::FactorioopsError;
use opentelemetry::global;
use opentelemetry::logs::LoggerProvider;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

#[derive(clap::Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,

    #[clap(
        long,
        env = "FACTORIOOPS_DATABASE_URL",
        default_value = "mongodb://127.0.0.1:27017/factorioops"
    )]
    database_url: String,
}

#[derive(clap::Subcommand, PartialEq)]
enum Command {
    Api {
        #[clap(
            long,
            env = "FACTORIOOPS_API_BIND_ADDR",
            default_value = "0.0.0.0:4123"
        )]
        bind_addr: SocketAddr,
    },
    DumpApi,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.command == Command::DumpApi {
        let (_router, api) = factorioops_api::router().expect("Failed to initialize API router");
        let json = api
            .to_json()
            .expect("Failed to serialize OpenAPI spec to JSON");
        println!("{}", json);
        return;
    }

    let (tp, mp, lp) = init_otel().expect("Failed to initialize OpenTelemetry and/or Tracing");

    match args.command {
        Command::Api { bind_addr } => {
            tracing::info!("Starting API server on {}", bind_addr);
            let (router, _api) =
                factorioops_api::router().expect("Failed to initialize API router");

            let listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .expect("Failed to bind to address");

            let state = factorioops_api::AppState::new(Arc::new(
                factorioops_db::MongoStore::open(args.database_url)
                    .await
                    .expect("Failed to connect to database"),
            ));

            factorioops_api::serve(listener, router.with_state(state))
                .await
                .expect("Failed to start API server");
        }

        // unreachable because we already handled DumpApi above
        Command::DumpApi => unreachable!(),
    }

    let mut shutdown_errors = Vec::new();

    if let Err(e) = tp.shutdown() {
        shutdown_errors.push(format!("tracer provider: {e}"));
    }

    if let Err(e) = lp.shutdown() {
        shutdown_errors.push(format!("logger provider: {e}"));
    }

    if let Err(e) = mp.shutdown() {
        shutdown_errors.push(format!("meter provider: {e}"));
    }

    // Return an error if any shutdown failed
    if !shutdown_errors.is_empty() {
        return tracing::error!(
            "Failed to shutdown providers:{}",
            shutdown_errors.join("\n")
        );
    }
}

fn init_otel() -> Result<(SdkTracerProvider, SdkMeterProvider, SdkLoggerProvider)> {
    let rs = Resource::builder().with_service_name("factorioops").build();

    let te = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .map_err(|e| FactorioopsError::Other(e.into()))?;

    let me = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .build()
        .map_err(|e| FactorioopsError::Other(e.into()))?;

    let le = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .build()
        .map_err(|e| FactorioopsError::Other(e.into()))?;

    let tp = SdkTracerProvider::builder()
        .with_batch_exporter(te)
        .with_resource(rs.clone())
        .build();

    let tracer = tp.tracer("factorioops");

    let mp = SdkMeterProvider::builder()
        .with_periodic_exporter(me)
        .with_resource(rs.clone())
        .build();

    let _meter = mp.meter("factorioops");

    let lp = SdkLoggerProvider::builder()
        .with_batch_exporter(le)
        .with_resource(rs.clone())
        .build();

    let _logger = lp.logger("factorioops");

    global::set_text_map_propagator(TraceContextPropagator::new());
    global::set_tracer_provider(tp.clone());
    global::set_meter_provider(mp.clone());

    let tl = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_error_events_to_status(true);

    let ll = OpenTelemetryTracingBridge::builder(&lp).build();

    let filter = Targets::new()
        .with_target("factorioops", tracing::Level::INFO)
        .with_target("factorioops_api", tracing::Level::INFO)
        .with_target("factorioops_core", tracing::Level::INFO)
        .with_target("factorioops_db", tracing::Level::INFO)
        .with_target("factorioops_models", tracing::Level::INFO);

    let fmt = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .with_filter(filter);

    Registry::default().with(tl).with(ll).with(fmt).init();

    Ok((tp, mp, lp))
}
