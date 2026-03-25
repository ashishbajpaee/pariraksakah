// CyberShield-X Self-Healing Code DNA — Main Entry Point
mod adapters;
mod db;
mod engine;
mod kafka;
mod models;

use adapters::InfraAdapter;
use axum::{routing::get, extract::State, Json, Router};
use db::DbClient;
use engine::SelfHealingEngine;
use kafka::KafkaEventStream;
use models::ThreatEvent;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "self-healing",
        "version": "1.0.0"
    }))
}

async fn compliance_report(State(db): State<Arc<DbClient>>) -> Json<Value> {
    match db.get_compliance_report().await {
        Ok(report) => Json(json!({
            "status": "success",
            "report_period": "30 days",
            "total_incidents": report.len(),
            "data": report
        })),
        Err(e) => {
            error!("Failed to generate compliance report: {}", e);
            Json(json!({
                "status": "error",
                "message": "Internal server error generating report"
            }))
        }
    }
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!("Starting Autonomous Self-Healing Infrastructure startup sequence...");

    // Init TimescaleDB Client
    let db_client = DbClient::new().await;

    // Init Infra Adapter
    let infra_adapter = InfraAdapter::new();

    // Channel for Event bus -> Healing Engine
    let (tx, rx) = mpsc::channel::<ThreatEvent>(100);

    // Start Kafka consumer in background
    let kafka_stream = KafkaEventStream::new();
    tokio::spawn(async move {
        kafka_stream.start_streaming(tx).await;
    });

    // Start Core Engine
    let engine = SelfHealingEngine::new(rx, db_client, infra_adapter);
    tokio::spawn(async move {
        engine.run_loop().await;
    });

    let db_state = Arc::new(db_client.clone());

    // Start health check metrics HTTP API
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/compliance/report", get(compliance_report))
        .with_state(db_state);

    let port: u16 = std::env::var("SELF_HEALING_PORT")
        .unwrap_or_else(|_| "8008".to_string())
        .parse()
        .unwrap_or(8008);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Self-Healing HTTP API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
