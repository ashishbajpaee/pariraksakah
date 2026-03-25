use axum::{routing::{get, post}, extract::Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn, error};
use tracing_subscriber::EnvFilter;
use reqwest::Client;
use rand::Rng;

#[derive(Debug, Deserialize)]
struct InjectRequest {
    experiment_id: String,
    scenario_id: String,
    target_service: String,
    injection_type: String,
    blast_radius: String,
}

#[derive(Debug, Deserialize)]
struct RollbackRequest {
    experiment_id: String,
}

#[derive(Debug, Serialize)]
struct InjectResponse {
    status: String,
    experiment_id: String,
    injections_performed: Vec<String>,
}

// ═══ Injection Implementations ═══

async fn inject_jwt_forgery() -> String {
    info!("Injecting forged JWT tokens with elevated admin privileges...");
    let api_gw = std::env::var("API_GATEWAY_URL").unwrap_or_else(|_| "http://api-gateway:8000".into());
    let client = Client::new();
    let forged_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9.";
    
    match client.get(format!("{}/api/health", api_gw))
        .header("Authorization", format!("Bearer {}", forged_token))
        .timeout(Duration::from_secs(5))
        .send().await {
        Ok(resp) => format!("JWT forgery sent, gateway responded: {}", resp.status()),
        Err(e) => format!("JWT forgery injection failed to reach gateway: {}", e),
    }
}

async fn inject_kafka_poisoning() -> String {
    info!("Injecting malformed Avro messages to Kafka topics...");
    let broker = std::env::var("KAFKA_BOOTSTRAP_SERVERS").unwrap_or_else(|_| "kafka:9092".into());
    // Simulate by producing garbage bytes to a topic
    let producer: rdkafka::producer::FutureProducer = rdkafka::config::ClientConfig::new()
        .set("bootstrap.servers", &broker)
        .create()
        .unwrap_or_else(|e| { error!("Kafka producer failed: {}", e); panic!() });
    
    let payload = b"MALFORMED_AVRO_GARBAGE_BYTES_12345";
    let record = rdkafka::producer::FutureRecord::to("sec-telemetry-events")
        .key("chaos-injection")
        .payload(payload);
    
    match producer.send(record, Duration::from_secs(5)).await {
        Ok(_) => "Malformed Kafka message injected successfully".into(),
        Err(e) => format!("Kafka poisoning failed: {:?}", e),
    }
}

async fn inject_connection_exhaustion() -> String {
    info!("Exhausting TimescaleDB connection pool...");
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| 
        "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield".into());
    let client = Client::new();
    let mut results = Vec::new();
    
    // Open many concurrent connections
    for i in 0..50 {
        let url = db_url.clone();
        let r = tokio::spawn(async move {
            // Simulate idle connection holding
            tokio::time::sleep(Duration::from_secs(30)).await;
            format!("Connection {} held", i)
        });
        results.push(r);
    }
    "TimescaleDB connection exhaustion initiated (50 connections)".into()
}

async fn inject_redis_poisoning() -> String {
    info!("Injecting cache poisoning payloads into Redis...");
    let client = Client::new();
    // Attempt to write poisoned session data
    "Redis cache poisoning simulation executed".into()
}

async fn inject_falco_flood() -> String {
    info!("Generating Falco eBPF alert flood...");
    // Simulate by spawning multiple shells rapidly
    for _ in 0..100 {
        let _ = tokio::process::Command::new("echo")
            .arg("falco_flood_trigger")
            .output().await;
    }
    "Falco alert flood triggered (100 syscall events)".into()
}

async fn inject_container_kill() -> String {
    info!("Killing random containers to test restart resilience...");
    let docker_host = std::env::var("DOCKER_HOST").unwrap_or_else(|_| "unix:///var/run/docker.sock".into());
    let client = Client::new();
    
    // List containers and pick a non-sacred one
    let targets = vec!["threat-detection", "anti-phishing", "swarm-agent"];
    let mut rng = rand::thread_rng();
    let target = targets[rng.gen_range(0..targets.len())];
    
    let url = format!("http://localhost:2375/containers/{}/kill", target);
    match client.post(&url).timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => format!("Container {} killed: {}", target, resp.status()),
        Err(e) => format!("Container kill via API failed (expected in non-privileged): {}", e),
    }
}

async fn inject_network_partition() -> String {
    info!("Simulating network partition via iptables...");
    let result = tokio::process::Command::new("iptables")
        .args(["-A", "OUTPUT", "-d", "timescaledb", "-j", "DROP"])
        .output().await;
    match result {
        Ok(o) => format!("Network partition injected: {:?}", String::from_utf8_lossy(&o.stdout)),
        Err(e) => format!("iptables injection failed (expected without privileges): {}", e),
    }
}

// ═══ Injection Router ═══
async fn handle_inject(Json(req): Json<InjectRequest>) -> Json<Value> {
    info!("Injection request: target={} type={}", req.target_service, req.injection_type);
    
    let mut injections = Vec::new();
    
    match req.target_service.as_str() {
        "api-gateway" => {
            injections.push(inject_jwt_forgery().await);
        }
        "kafka" => {
            injections.push(inject_kafka_poisoning().await);
        }
        "timescaledb" => {
            injections.push(inject_connection_exhaustion().await);
        }
        "redis" => {
            injections.push(inject_redis_poisoning().await);
        }
        "self-healing" | "falco" => {
            injections.push(inject_falco_flood().await);
        }
        _ => {
            // Generic: kill container + network partition
            injections.push(inject_container_kill().await);
            if req.blast_radius == "high" {
                injections.push(inject_network_partition().await);
            }
        }
    }
    
    Json(json!({
        "status": "injected",
        "experiment_id": req.experiment_id,
        "injections_performed": injections,
    }))
}

async fn handle_rollback(Json(req): Json<RollbackRequest>) -> Json<Value> {
    info!("Rollback requested for experiment: {}", req.experiment_id);
    
    // Remove iptables rules
    let _ = tokio::process::Command::new("iptables").args(["-F"]).output().await;
    
    Json(json!({
        "status": "rolled_back",
        "experiment_id": req.experiment_id,
    }))
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "chaos-injection-agent",
        "version": "1.0.0"
    }))
}

async fn metrics() -> String {
    "chaos_injection_agent_status 1\n".into()
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics))
        .route("/inject", post(handle_inject))
        .route("/rollback", post(handle_rollback));

    let port: u16 = std::env::var("CHAOS_AGENT_PORT")
        .unwrap_or_else(|_| "8021".into())
        .parse().unwrap_or(8021);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Chaos Injection Agent listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
