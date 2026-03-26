#!/bin/bash
# Deliverable 2: Kafka Topic Creation + Avro Schema Registration
# Run inside Kafka broker or from a machine with kafka-topics.sh and curl available.

set -euo pipefail

KAFKA_BROKER="${KAFKA_BOOTSTRAP_SERVERS:-kafka:9092}"
SCHEMA_REGISTRY="${SCHEMA_REGISTRY_URL:-http://schema-registry:8081}"

echo "═══ Creating Chaos Kafka Topics ═══"

kafka-topics.sh --create --if-not-exists --topic chaos.experiments \
  --bootstrap-server "$KAFKA_BROKER" --replication-factor 1 --partitions 6 \
  --config retention.ms=604800000 --config cleanup.policy=delete

kafka-topics.sh --create --if-not-exists --topic chaos.results \
  --bootstrap-server "$KAFKA_BROKER" --replication-factor 1 --partitions 6 \
  --config retention.ms=604800000 --config cleanup.policy=delete

kafka-topics.sh --create --if-not-exists --topic chaos.alerts \
  --bootstrap-server "$KAFKA_BROKER" --replication-factor 1 --partitions 3 \
  --config retention.ms=2592000000 --config cleanup.policy=delete

kafka-topics.sh --create --if-not-exists --topic chaos.audit \
  --bootstrap-server "$KAFKA_BROKER" --replication-factor 1 --partitions 3 \
  --config retention.ms=-1 --config cleanup.policy=compact

kafka-topics.sh --create --if-not-exists --topic chaos.control \
  --bootstrap-server "$KAFKA_BROKER" --replication-factor 1 --partitions 1 \
  --config retention.ms=3600000 --config cleanup.policy=delete

echo "═══ Registering Avro Schemas ═══"

# chaos.experiments-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/chaos.experiments-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"ChaosExperiment\",\"namespace\":\"com.cybershield.chaos\",\"fields\":[{\"name\":\"experiment_id\",\"type\":\"string\"},{\"name\":\"scenario_id\",\"type\":\"string\"},{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"status\",\"type\":{\"type\":\"enum\",\"name\":\"ExperimentStatus\",\"symbols\":[\"PENDING\",\"RUNNING\",\"COMPLETED\",\"ABORTED\",\"FAILED\"]}},{\"name\":\"blast_radius\",\"type\":{\"type\":\"enum\",\"name\":\"BlastRadius\",\"symbols\":[\"LOW\",\"MEDIUM\",\"HIGH\"]}},{\"name\":\"target_service\",\"type\":\"string\"},{\"name\":\"mitre_ttp\",\"type\":\"string\"},{\"name\":\"injection_type\",\"type\":\"string\"},{\"name\":\"start_time\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}},{\"name\":\"end_time\",\"type\":[\"null\",{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}],\"default\":null},{\"name\":\"dry_run\",\"type\":\"boolean\",\"default\":false},{\"name\":\"metadata\",\"type\":[\"null\",\"string\"],\"default\":null}]}"
}'

# chaos.results-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/chaos.results-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"ChaosResult\",\"namespace\":\"com.cybershield.chaos\",\"fields\":[{\"name\":\"result_id\",\"type\":\"string\"},{\"name\":\"experiment_id\",\"type\":\"string\"},{\"name\":\"detection_time_ms\",\"type\":\"long\"},{\"name\":\"response_time_ms\",\"type\":\"long\"},{\"name\":\"mttr_ms\",\"type\":\"long\"},{\"name\":\"containment_score\",\"type\":\"double\"},{\"name\":\"resilience_score\",\"type\":\"double\"},{\"name\":\"false_negative_rate\",\"type\":\"double\"},{\"name\":\"gaps_found\",\"type\":\"int\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# chaos.alerts-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/chaos.alerts-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"ChaosAlert\",\"namespace\":\"com.cybershield.chaos\",\"fields\":[{\"name\":\"alert_id\",\"type\":\"string\"},{\"name\":\"experiment_id\",\"type\":\"string\"},{\"name\":\"severity\",\"type\":{\"type\":\"enum\",\"name\":\"AlertSeverity\",\"symbols\":[\"LOW\",\"MEDIUM\",\"HIGH\",\"CRITICAL\"]}},{\"name\":\"gap_type\",\"type\":\"string\"},{\"name\":\"mitre_ttp\",\"type\":\"string\"},{\"name\":\"service\",\"type\":\"string\"},{\"name\":\"description\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# chaos.audit-value
curl -s -X POST "$SCHEMA_REGISTRY/subjects/chaos.audit-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"ChaosAudit\",\"namespace\":\"com.cybershield.chaos\",\"fields\":[{\"name\":\"audit_id\",\"type\":\"string\"},{\"name\":\"action\",\"type\":\"string\"},{\"name\":\"actor\",\"type\":\"string\"},{\"name\":\"experiment_id\",\"type\":[\"null\",\"string\"],\"default\":null},{\"name\":\"outcome\",\"type\":\"string\"},{\"name\":\"details\",\"type\":[\"null\",\"string\"],\"default\":null},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

echo "═══ All Kafka topics and schemas registered ═══"
