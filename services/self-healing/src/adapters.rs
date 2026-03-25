use reqwest::Client;
use std::env;
use std::time::Duration;
use tracing::{info, warn, error};
use serde_json::json;

#[derive(Clone)]
pub struct InfraAdapter {
    client: Client,
    docker_host: String,
}

impl InfraAdapter {
    pub fn new() -> Self {
        let docker_host = env::var("DOCKER_API_URL").unwrap_or_else(|_| "http://localhost:2375".to_string());
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build InfraAdapter reqwest client");

        Self { client, docker_host }
    }

    /// Isolates learning components by removing them from their bridged network
    pub async fn isolate_network(&self, container_name: &str) -> Result<(), String> {
        info!("Executing infra action: Isolating network for {}", container_name);
        
        let url = format!("{}/networks/cybershield-net/disconnect", self.docker_host);
        let payload = json!({
            "Container": container_name,
            "Force": true
        });

        match self.client.post(&url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Successfully disconnected {} from cybershield-net", container_name);
                Ok(())
            }
            Ok(resp) => {
                let err_msg = format!("Docker API returned status: {}", resp.status());
                error!("{}", err_msg);
                Err(err_msg)
            }
            Err(e) => {
                let err_msg = format!("Failed to reach Docker API: {}", e);
                error!("{}", err_msg);
                Err(err_msg)
            }
        }
    }

    /// Kills the compromised container and instructs the orchestrator to spin up a new replacement
    pub async fn kill_and_replace(&self, container_name: &str) -> Result<(), String> {
        info!("Executing infra action: Kill and Replace for {}", container_name);
        
        let url = format!("{}/containers/{}/kill", self.docker_host, container_name);
        
        match self.client.post(&url).send().await {
            Ok(resp) if resp.status().is_success() || resp.status() == 404 => {
                info!("Successfully killed {} (or already dead)", container_name);
                // Orchestrators like auto-restart policies or K8s ReplicaSets handle the replacement automatically.
                // In a pure docker-compose environment without restart: always, we would need to call `/containers/{}/start`.
                Ok(())
            }
            Ok(resp) => {
                let err_msg = format!("Docker API kill returned status: {}", resp.status());
                error!("{}", err_msg);
                Err(err_msg)
            }
            Err(e) => {
                let err_msg = format!("Failed to reach Docker API to kill: {}", e);
                error!("{}", err_msg);
                Err(err_msg)
            }
        }
    }

    /// Post-Heal validation runs a health check on the newly spun up component
    pub async fn validate_health(&self, component_url: &str) -> bool {
        info!("Running post-heal validation on {}", component_url);
        let url = format!("{}/health", component_url);
        
        for _ in 0..3 {
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!("✅ Component {} is healthy post-remediation.", component_url);
                    return true;
                }
                _ => {
                    warn!("Health check failed for {}, retrying in 2s...", component_url);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
        
        error!("❌ Component {} failed all post-heal validation checks.", component_url);
        false
    }
}
