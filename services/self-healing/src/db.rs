use crate::models::{RemediationAction, ThreatEvent};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, Row};
use std::env;

#[derive(Clone)]
pub struct DbClient {
    pool: Pool<Postgres>,
}

impl DbClient {
    pub async fn new() -> Self {
        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://cybershield:changeme_postgres@localhost:5432/cybershield".to_string()
        });

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to connect to TimescaleDB Postgres database");

        Self { pool }
    }

    /// Evaluates whether the current threat exceeds the rolling 7-day anomaly behavioral threshold.
    /// This allows us to escalate warnings to Kill triggers if it's statistically significant.
    pub async fn exceeds_behavioral_baseline(&self, component: &str) -> bool {
        let query = r#"
            WITH stats AS (
                SELECT 
                    avg(anomaly_score) as mean_score, 
                    stddev(anomaly_score) as stddev_score
                FROM behavioral_metrics 
                WHERE component = $1 
                  AND timestamp > NOW() - INTERVAL '7 days'
            )
            SELECT
                (SELECT anomaly_score FROM behavioral_metrics WHERE component = $1 ORDER BY timestamp DESC LIMIT 1) as current_score,
                mean_score,
                stddev_score
            FROM stats;
        "#;

        if let Ok(row) = sqlx::query(query).bind(component).fetch_one(&self.pool).await {
            let current_score: f64 = row.try_get("current_score").unwrap_or(0.0);
            let mean: f64 = row.try_get("mean_score").unwrap_or(0.0);
            let stddev: f64 = row.try_get("stddev_score").unwrap_or(1.0);

            // Deviates beyond 2 standard deviations
            if current_score > (mean + 2.0 * stddev) {
                return true;
            }
        }
        false
    }

    /// Appends the autonomous action to an immutable audit trail and forwards to SIEM
    pub async fn log_autonomous_action(
        &self,
        event: &ThreatEvent,
        action: &RemediationAction,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        let cve_id = event.cve_id.clone().unwrap_or_else(|| "UNKNOWN".to_string());
        let action_str = format!("{:?}", action);

        sqlx::query(
            r#"
            INSERT INTO autonomous_audits
            (component, severity, cve_id, threat_description, action_taken, status, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            "#,
        )
        .bind(&event.component)
        .bind(&event.severity)
        .bind(&cve_id)
        .bind(&event.description)
        .bind(&action_str)
        .bind(status)
        .execute(&self.pool)
        .await?;

        // Fire-and-forget SIEM export
        let siem_payload = serde_json::json!({
            "version": "1.0",
            "deviceVendor": "CyberShield-X",
            "deviceProduct": "SelfHealing",
            "signatureId": cve_id,
            "name": format!("Autonomous Action: {}", action_str),
            "severity": event.severity,
            "msg": event.description,
            "dhost": event.component,
            "outcome": status,
        });
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let siem_url = env::var("SIEM_URL").unwrap_or_else(|_| "http://localhost:5050/ingest".to_string());
            let _ = client.post(&siem_url).json(&siem_payload).send().await;
        });

        Ok(())
    }

    /// Fetches the last 30 days of autonomous remediation actions for compliance reporting
    pub async fn get_compliance_report(&self) -> Result<Vec<serde_json::Value>, sqlx::Error> {
        let query = r#"
            SELECT 
                component, severity, cve_id, threat_description, action_taken, status, timestamp
            FROM autonomous_audits
            WHERE timestamp > NOW() - INTERVAL '30 days'
            ORDER BY timestamp DESC
            LIMIT 1000
        "#;

        let rows = sqlx::query(query).fetch_all(&self.pool).await?;
        let mut report = Vec::new();

        use sqlx::Row;
        for row in rows {
            let component: String = row.get("component");
            let severity: String = row.get("severity");
            let cve_id: String = row.get("cve_id");
            let desc: String = row.get("threat_description");
            let action: String = row.get("action_taken");
            let status: String = row.get("status");
            let ts: chrono::NaiveDateTime = row.get("timestamp");

            report.push(serde_json::json!({
                "component": component,
                "severity": severity,
                "cve_id": cve_id,
                "description": desc,
                "action_taken": action,
                "status": status,
                "timestamp": ts.format("%Y-%m-%dT%H:%M:%S").to_string()
            }));
        }

        Ok(report)
    }
}
