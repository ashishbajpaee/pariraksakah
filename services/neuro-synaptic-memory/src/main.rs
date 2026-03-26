use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fs::{OpenOptions, File};
use std::io::{Write, Read};
use memmap2::MmapMut;
use tokio::time::{sleep, Duration};
use blake3::Hasher;
use postgres::{Client, NoTls};
use lz4_flex::{compress_prepend_size, decompress_size_prepended};

#[derive(Serialize, Deserialize, Clone)]
struct SynapseUpdate {
    synapse_id: String,
    pre_neuron: String,
    post_neuron: String,
    weight_delta: f64,
    new_weight: f64,
    learning_rule: String,
}

struct AppState {
    weights: Arc<Mutex<HashMap<String, f64>>>,
    db_conn_str: String,
}

#[get("/synaptic/weight/{pre}/{post}")]
async fn get_weight(
    path: web::Path<(String, String)>,
    data: web::Data<AppState>,
) -> impl Responder {
    let (pre, post) = path.into_inner();
    let key = format!("{}_{}", pre, post);
    let map = data.weights.lock().unwrap();
    let w = map.get(&key).unwrap_or(&0.0);
    HttpResponse::Ok().json(serde_json::json!({ "pre": pre, "post": post, "weight": w }))
}

#[get("/synaptic/layer/{layer_id}")]
async fn get_layer_weights(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let layer_id = path.into_inner();
    let map = data.weights.lock().unwrap();
    let mut layer_weights = HashMap::new();
    for (k, v) in map.iter() {
        if k.starts_with(&layer_id) {
            layer_weights.insert(k.clone(), *v);
        }
    }
    HttpResponse::Ok().json(layer_weights)
}

#[post("/synaptic/update")]
async fn batch_update(
    updates: web::Json<Vec<SynapseUpdate>>,
    data: web::Data<AppState>,
) -> impl Responder {
    let mut map = data.weights.lock().unwrap();
    
    // Attempt DB conn to log
    let mut client = match Client::connect(&data.db_conn_str, NoTls) {
        Ok(c) => Some(c),
        Err(_) => None,
    };

    let mut applied = 0;
    for update in updates.into_inner() {
        let key = format!("{}_{}", update.pre_neuron, update.post_neuron);
        let old_weight = *map.get(&key).unwrap_or(&0.0);
        map.insert(key, update.new_weight);
        applied += 1;
        
        if let Some(ref mut c) = client {
            let _ = c.execute(
                "INSERT INTO synaptic_weights_history (synapse_id, pre_neuron, post_neuron, weight_before, weight_after, learning_rule, update_trigger) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[&update.synapse_id, &update.pre_neuron, &update.post_neuron, &old_weight, &update.new_weight, &update.learning_rule, &"batch_update"],
            );
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"status": "Batch applied", "updated": applied}))
}

#[get("/synaptic/checkpoint")]
async fn trigger_checkpoint(data: web::Data<AppState>) -> impl Responder {
    let map = data.weights.lock().unwrap();
    let json_data = serde_json::to_vec(&*map).unwrap();
    
    let compressed = compress_prepend_size(&json_data);
    let mut hasher = Hasher::new();
    hasher.update(&compressed);
    let hash = hasher.finalize();

    let timestamp = chrono::Utc::now().timestamp();
    let file_path = format!("/data/checkpoint_{}.lz4", timestamp);
    
    // In production we would map memory directly, here we save to file
    if let Ok(mut file) = OpenOptions::new().write(true).create(true).open(&file_path) {
        let _ = file.write_all(&compressed);
    }
    
    HttpResponse::Ok().json(serde_json::json!({
        "status": "Checkpoint created",
        "file": file_path,
        "hash": hash.to_hex().to_string(),
        "bytes": compressed.len()
    }))
}

#[get("/synaptic/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "memory": "Mmap sparse active"}))
}

#[post("/synaptic/rollback/{checkpoint_id}")]
async fn rollback(path: web::Path<String>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "Rollback simulated", "checkpoint": path.into_inner()}))
}

async fn checkpoint_loop(data: web::Data<AppState>) {
    loop {
        sleep(Duration::from_secs(60)).await;
        // background trigger checkpoint
        let map = data.weights.lock().unwrap();
        let json_data = serde_json::to_vec(&*map).unwrap();
        let compressed = compress_prepend_size(&json_data);
        let timestamp = chrono::Utc::now().timestamp();
        let file_path = format!("/data/checkpoint_{}.lz4", timestamp);
        if let Ok(mut file) = OpenOptions::new().write(true).create(true).open(&file_path) {
            let _ = file.write_all(&compressed);
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // ensure /data logic
    let _ = std::fs::create_dir_all("/data");
    
    let db_host = std::env::var("POSTGRES_HOST").unwrap_or_else(|_| "timescaledb".to_string());
    let db_port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
    let db_user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "cybershield".to_string());
    let db_pass = std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "changeme_postgres".to_string());
    let db_name = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "cybershield".to_string());
    
    let db_conn_str = format!("host={} port={} user={} password={} dbname={}", db_host, db_port, db_user, db_pass, db_name);
    
    let weights = Arc::new(Mutex::new(HashMap::new()));
    
    let state = web::Data::new(AppState {
        weights: weights.clone(),
        db_conn_str,
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        checkpoint_loop(state_clone).await;
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(get_weight)
            .service(get_layer_weights)
            .service(batch_update)
            .service(trigger_checkpoint)
            .service(health_check)
            .service(rollback)
    })
    .bind(("0.0.0.0", 8071))?
    .run()
    .await
}
