use crate::models::ThreatEvent;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::Message;
use std::env;
use tokio::sync::mpsc;

pub struct KafkaEventStream {
    consumer: StreamConsumer,
}

impl KafkaEventStream {
    pub fn new() -> Self {
        let brokers = env::var("KAFKA_BOOTSTRAP_SERVERS").unwrap_or_else(|_| "localhost:9092".into());
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", "self-healing-engine")
            .set("bootstrap.servers", &brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .create()
            .expect("Consumer creation failed");

        consumer
            .subscribe(&["sec-telemetry-events"])
            .expect("Can't subscribe to sec-telemetry-events");

        tracing::info!("Kafka Consumer subscribed to sec-telemetry-events at {}", brokers);
        Self { consumer }
    }

    pub async fn start_streaming(self, tx: mpsc::Sender<ThreatEvent>) {
        loop {
            match self.consumer.recv().await {
                Ok(msg) => {
                    if let Some(payload) = msg.payload() {
                        match serde_json::from_slice::<ThreatEvent>(payload) {
                            Ok(event) => {
                                if let Err(e) = tx.send(event).await {
                                    tracing::error!("Failed to route ThreatEvent to engine: {}", e);
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to deserialize ThreatEvent: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Kafka error: {}", e);
                }
            }
        }
    }
}
