use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Mutex;
use chrono::Utc;
use blake3;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use lazy_static::lazy_static;

lazy_static! {
    static ref CHAIN: Mutex<Vec<Block>> = {
        let genesis = Block {
            block_number: 0, block_hash: "genesis".into(),
            previous_hash: "0000000000000000".into(),
            merkle_root: blake3::hash(b"genesis").to_hex().to_string(),
            transactions: vec![], validator_signatures: vec!["genesis-sig".into()],
            created_at: Utc::now().to_rfc3339(), proposer_peer_id: "system".into(),
        };
        Mutex::new(vec![genesis])
    };
    static ref TX_BUFFER: Mutex<Vec<Transaction>> = Mutex::new(Vec::new());
}

#[derive(Serialize, Deserialize, Clone)]
struct Transaction {
    tx_id: String,
    tx_type: String,
    data: serde_json::Value,
    timestamp: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Block {
    block_number: u64,
    block_hash: String,
    previous_hash: String,
    merkle_root: String,
    transactions: Vec<Transaction>,
    validator_signatures: Vec<String>,
    created_at: String,
    proposer_peer_id: String,
}

fn compute_merkle(txs: &[Transaction]) -> String {
    let mut hasher = blake3::Hasher::new();
    for tx in txs { hasher.update(tx.tx_id.as_bytes()); }
    hasher.finalize().to_hex().to_string()
}

fn compute_block_hash(block: &Block) -> String {
    let data = format!("{}:{}:{}:{}", block.block_number, block.previous_hash, block.merkle_root, block.created_at);
    blake3::hash(data.as_bytes()).to_hex().to_string()
}

async fn kafka_publish(topic: &str, payload: &str) {
    let broker = env::var("KAFKA_BOOTSTRAP_SERVERS").unwrap_or("kafka:9092".into());
    if let Ok(producer) = ClientConfig::new()
        .set("bootstrap.servers", &broker)
        .set("message.timeout.ms", "5000")
        .create::<FutureProducer>() {
        let _ = producer.send(FutureRecord::to(topic).payload(payload).key("ledger"), std::time::Duration::from_secs(1)).await;
    }
}

async fn create_block() {
    let mut buffer = TX_BUFFER.lock().unwrap();
    if buffer.is_empty() { return; }
    let txs: Vec<Transaction> = buffer.drain(..).collect();
    drop(buffer);

    let mut chain = CHAIN.lock().unwrap();
    let prev = chain.last().unwrap();
    let merkle = compute_merkle(&txs);
    let mut block = Block {
        block_number: prev.block_number + 1, block_hash: String::new(),
        previous_hash: prev.block_hash.clone(), merkle_root: merkle,
        transactions: txs, validator_signatures: vec!["local-sig".into(), "sim1-sig".into(), "sim2-sig".into()],
        created_at: Utc::now().to_rfc3339(), proposer_peer_id: "local-node".into(),
    };
    block.block_hash = compute_block_hash(&block);
    chain.push(block.clone());
    let event = serde_json::to_string(&block).unwrap();
    kafka_publish("dsrn.ledger.block", &event).await;
}

async fn get_blocks(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let chain = CHAIN.lock().unwrap();
    let limit = query.get("limit").and_then(|v| v.parse().ok()).unwrap_or(20usize);
    let blocks: Vec<&Block> = chain.iter().rev().take(limit).collect();
    HttpResponse::Ok().json(serde_json::json!({"blocks": blocks, "total": chain.len()}))
}

async fn get_block(path: web::Path<u64>) -> impl Responder {
    let num = path.into_inner();
    let chain = CHAIN.lock().unwrap();
    if let Some(b) = chain.iter().find(|b| b.block_number == num) {
        return HttpResponse::Ok().json(b);
    }
    HttpResponse::NotFound().json(serde_json::json!({"error": "Block not found"}))
}

async fn verify_chain() -> impl Responder {
    let chain = CHAIN.lock().unwrap();
    let mut valid = true;
    for i in 1..chain.len() {
        if chain[i].previous_hash != chain[i-1].block_hash { valid = false; break; }
        let expected = compute_block_hash(&chain[i]);
        if chain[i].block_hash != expected { valid = false; break; }
    }
    HttpResponse::Ok().json(serde_json::json!({"valid": valid, "block_count": chain.len()}))
}

async fn ledger_stats() -> impl Responder {
    let chain = CHAIN.lock().unwrap();
    let tx_count: usize = chain.iter().map(|b| b.transactions.len()).sum();
    HttpResponse::Ok().json(serde_json::json!({"blocks": chain.len(), "transactions": tx_count, "valid": true}))
}

async fn submit_tx(body: web::Json<serde_json::Value>) -> impl Responder {
    let tx = Transaction {
        tx_id: uuid::Uuid::new_v4().to_string(), tx_type: body.get("type").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
        data: body.into_inner(), timestamp: Utc::now().to_rfc3339(),
    };
    TX_BUFFER.lock().unwrap().push(tx.clone());
    let buf_len = TX_BUFFER.lock().unwrap().len();
    if buf_len >= 100 { create_block().await; }
    HttpResponse::Ok().json(serde_json::json!({"tx_id": tx.tx_id, "buffered": buf_len}))
}

async fn metrics_handler() -> HttpResponse {
    let chain = CHAIN.lock().unwrap();
    HttpResponse::Ok().body(format!("dsrn_ledger_blocks_total {}\n", chain.len()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    // Block creation timer (every 60s)
    tokio::spawn(async { loop { tokio::time::sleep(std::time::Duration::from_secs(60)).await; create_block().await; } });
    let port = env::var("LEDGER_PORT").unwrap_or("8065".into());
    HttpServer::new(|| {
        App::new()
            .route("/ledger/blocks", web::get().to(get_blocks))
            .route("/ledger/block/{number}", web::get().to(get_block))
            .route("/ledger/verify", web::get().to(verify_chain))
            .route("/ledger/stats", web::get().to(ledger_stats))
            .route("/ledger/submit", web::post().to(submit_tx))
            .route("/metrics", web::get().to(metrics_handler))
    }).bind(format!("0.0.0.0:{}", port))?.run().await
}
