use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Mutex;
use std::collections::HashMap;
use chrono::Utc;
use uuid::Uuid;
use blake3;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use lazy_static::lazy_static;

lazy_static! {
    static ref PEERS: Mutex<HashMap<String, PeerInfo>> = Mutex::new(HashMap::new());
    static ref LOCAL_PEER_ID: String = {
        let host = hostname::get().unwrap_or_default().to_string_lossy().to_string();
        let hash = blake3::hash(format!("dsrn-{}-{}", host, std::process::id()).as_bytes());
        format!("peer-{}", &hash.to_hex()[..16])
    };
}

#[derive(Serialize, Deserialize, Clone)]
struct PeerInfo {
    peer_id: String,
    organization_name: String,
    endpoint_url: String,
    trust_score: f64,
    reputation_score: f64,
    status: String,
    last_seen: String,
    dna_fingerprint: String,
}

#[derive(Deserialize)]
struct ConnectReq { endpoint: String, org_name: String }

async fn kafka_publish(topic: &str, payload: &str) {
    let broker = env::var("KAFKA_BOOTSTRAP_SERVERS").unwrap_or("kafka:9092".into());
    if let Ok(producer) = ClientConfig::new()
        .set("bootstrap.servers", &broker)
        .set("message.timeout.ms", "5000")
        .create::<FutureProducer>() {
        let _ = producer.send(
            FutureRecord::to(topic).payload(payload).key("dsrn-peer"),
            std::time::Duration::from_secs(1),
        ).await;
    }
}

async fn get_peer_id() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"peer_id": *LOCAL_PEER_ID, "status": "ACTIVE"}))
}

async fn list_peers() -> impl Responder {
    let peers = PEERS.lock().unwrap();
    let list: Vec<&PeerInfo> = peers.values().collect();
    HttpResponse::Ok().json(serde_json::json!({"peers": list, "count": list.len()}))
}

async fn connect_peer(req: web::Json<ConnectReq>) -> impl Responder {
    let pid = format!("peer-{}", &blake3::hash(req.endpoint.as_bytes()).to_hex()[..16]);
    let info = PeerInfo {
        peer_id: pid.clone(), organization_name: req.org_name.clone(),
        endpoint_url: req.endpoint.clone(), trust_score: 100.0, reputation_score: 100.0,
        status: "ACTIVE".into(), last_seen: Utc::now().to_rfc3339(),
        dna_fingerprint: blake3::hash(pid.as_bytes()).to_hex().to_string(),
    };
    PEERS.lock().unwrap().insert(pid.clone(), info.clone());
    let event = serde_json::to_string(&info).unwrap();
    kafka_publish("dsrn.peer.discovered", &event).await;
    HttpResponse::Ok().json(serde_json::json!({"connected": pid}))
}

async fn disconnect_peer(path: web::Path<String>) -> impl Responder {
    let pid = path.into_inner();
    let mut peers = PEERS.lock().unwrap();
    if let Some(p) = peers.get_mut(&pid) {
        p.status = "DISCONNECTED".into();
        let event = serde_json::json!({"peer_id": pid, "disconnected_at": Utc::now().to_rfc3339()});
        kafka_publish("dsrn.peer.disconnected", &event.to_string()).await;
        return HttpResponse::Ok().json(serde_json::json!({"disconnected": pid}));
    }
    HttpResponse::NotFound().json(serde_json::json!({"error":"Peer not found"}))
}

async fn network_topology() -> impl Responder {
    let peers = PEERS.lock().unwrap();
    let nodes: Vec<serde_json::Value> = peers.values().map(|p| {
        serde_json::json!({"id": p.peer_id, "org": p.organization_name, "trust": p.trust_score, "status": p.status})
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({"local_peer": *LOCAL_PEER_ID, "nodes": nodes, "edge_count": nodes.len()}))
}

async fn health() -> impl Responder {
    let count = PEERS.lock().unwrap().values().filter(|p| p.status == "ACTIVE").count();
    HttpResponse::Ok().json(serde_json::json!({"status":"UP","service":"dsrn-peer-node","active_peers":count,"peer_id":*LOCAL_PEER_ID}))
}

async fn metrics() -> HttpResponse {
    let count = PEERS.lock().unwrap().len();
    HttpResponse::Ok().body(format!("dsrn_peer_connected_total {}\ndsrn_peer_node_up 1\n", count))
}

fn init_simulated_peers() {
    let mut peers = PEERS.lock().unwrap();
    for (i, org) in [("sim-peer-1","SimOrg-Alpha"),("sim-peer-2","SimOrg-Beta"),("sim-peer-3","SimOrg-Gamma"),("sim-peer-4","SimOrg-Delta")].iter().enumerate() {
        peers.insert(org.0.to_string(), PeerInfo {
            peer_id: org.0.to_string(), organization_name: org.1.to_string(),
            endpoint_url: format!("http://simulated-peer-{}:9090", i+1),
            trust_score: 85.0 + (i as f64 * 3.0), reputation_score: 80.0 + (i as f64 * 5.0),
            status: "ACTIVE".into(), last_seen: Utc::now().to_rfc3339(),
            dna_fingerprint: blake3::hash(org.0.as_bytes()).to_hex().to_string(),
        });
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let mode = env::var("DSRN_MODE").unwrap_or("development".into());
    if mode == "development" { init_simulated_peers(); }
    let port = env::var("DSRN_PEER_PORT").unwrap_or("8060".into());
    HttpServer::new(|| {
        App::new()
            .route("/peer/id", web::get().to(get_peer_id))
            .route("/peer/list", web::get().to(list_peers))
            .route("/peer/connect", web::post().to(connect_peer))
            .route("/peer/disconnect/{peer_id}", web::post().to(disconnect_peer))
            .route("/peer/network/topology", web::get().to(network_topology))
            .route("/peer/health", web::get().to(health))
            .route("/metrics", web::get().to(metrics))
    }).bind(format!("0.0.0.0:{}", port))?.run().await
}
