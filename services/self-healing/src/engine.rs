use crate::adapters::InfraAdapter;
use crate::db::DbClient;
use crate::models::{RemediationAction, ThreatEvent};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub struct SelfHealingEngine {
    rx: mpsc::Receiver<ThreatEvent>,
    db: DbClient,
    infra: InfraAdapter,
}

impl SelfHealingEngine {
    pub fn new(rx: mpsc::Receiver<ThreatEvent>, db: DbClient, infra: InfraAdapter) -> Self {
        Self { rx, db, infra }
    }

    pub async fn run_loop(mut self) {
        info!("Autonomous Healing Loop started. Waiting for ThreatEvents...");
        while let Some(event) = self.rx.recv().await {
            info!("Received Event: {:?}", event);
            let action = self.evaluate_policy(&event).await;
            
            match self.execute_remediation(&action).await {
                Ok(_) => {
                    self.log_audit(&event, &action, "SUCCESS").await;
                }
                Err(e) => {
                    error!("Failed to remediate: {:?}", e);
                    self.log_audit(&event, &action, "FAILED").await;
                }
            }
        }
    }

    async fn evaluate_policy(&self, event: &ThreatEvent) -> RemediationAction {
        if event.severity.eq_ignore_ascii_case("CRITICAL") {
            warn!("Critical threat detected on {}. Recommending Kill+Replace...", event.component);
            RemediationAction::KillAndReplace(event.component.clone())
        } else if self.db.exceeds_behavioral_baseline(&event.component).await {
            warn!("Component {} exceeds 7-day behavior variance! Escalating to IsolateNetwork.", event.component);
            RemediationAction::IsolateNetwork(event.component.clone())
        } else if event.severity.eq_ignore_ascii_case("HIGH") {
            RemediationAction::IsolateNetwork(event.component.clone())
        } else {
            RemediationAction::AlertOnly(event.component.clone())
        }
    }

    async fn execute_remediation(&self, action: &RemediationAction) -> Result<(), String> {
        info!("Executing automated action: {:?}", action);
        match action {
            RemediationAction::IsolateNetwork(component) => {
                self.infra.isolate_network(component).await?;
            }
            RemediationAction::KillAndReplace(component) => {
                self.infra.kill_and_replace(component).await?;
                // Run a post-heal health check (assuming the component restarts at http://component:port)
                let component_url = format!("http://{}", component);
                self.infra.validate_health(&component_url).await;
            }
            RemediationAction::PatchImage(_) => {
                info!("Patching not yet dynamically supported without CI/CD trigger.");
            }
            RemediationAction::AlertOnly(_) => {
                info!("Alert only - no destructive action taken.");
            }
        }
        Ok(())
    }

    async fn log_audit(&self, event: &ThreatEvent, action: &RemediationAction, status: &str) {
        info!("AUDIT LOG: Status={} | Event={:?} | Action={:?}", status, event.cve_id, action);
        if let Err(e) = self.db.log_autonomous_action(event, action, status).await {
            error!("Failed to write to immutable audit log: {}", e);
        }
    }
}
