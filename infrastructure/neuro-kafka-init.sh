#!/bin/bash
# Deliverable 2: Kafka Topic Creation + Avro Schema Registration for Neuromorphic System
# Run inside Kafka broker or from a machine with kafka-topics.sh and curl available.

set -euo pipefail

KAFKA_BROKER="${KAFKA_BOOTSTRAP_SERVERS:-kafka:9092}"
SCHEMA_REGISTRY="${SCHEMA_REGISTRY_URL:-http://schema-registry:8081}"

echo "═══ Creating Neuromorphic Kafka Topics ═══"

topics=(
  "neuro.spike.events"
  "neuro.pattern.learned"
  "neuro.anomaly.detected"
  "neuro.memory.formed"
  "neuro.memory.recalled"
  "neuro.plasticity.update"
  "neuro.immune.response"
  "neuro.dream.cycle"
  "neuro.evolution.checkpoint"
  "neuro.audit.trail"
)

for topic in "${topics[@]}"; do
  kafka-topics.sh --create --if-not-exists --topic "$topic" \
    --bootstrap-server "$KAFKA_BROKER" --replication-factor 1 --partitions 6 \
    --config retention.ms=604800000 --config cleanup.policy=delete
done

echo "═══ Registering Avro Schemas ═══"

# 1. neuro.spike.events
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.spike.events-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"SpikeEvent\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"neuron_id\",\"type\":\"string\"},{\"name\":\"layer\",\"type\":\"string\"},{\"name\":\"spike_time\",\"type\":\"long\"},{\"name\":\"membrane_potential\",\"type\":\"double\"},{\"name\":\"input_pattern_hash\",\"type\":\"string\"},{\"name\":\"threat_context\",\"type\":[\"null\",\"string\"],\"default\":null},{\"name\":\"recorded_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 2. neuro.pattern.learned
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.pattern.learned-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"PatternLearned\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"pattern_id\",\"type\":\"string\"},{\"name\":\"pattern_hash\",\"type\":\"string\"},{\"name\":\"threat_type\",\"type\":\"string\"},{\"name\":\"mitre_ttp\",\"type\":\"string\"},{\"name\":\"confidence_score\",\"type\":\"double\"},{\"name\":\"synaptic_encoding\",\"type\":\"string\"},{\"name\":\"learned_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 3. neuro.anomaly.detected
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.anomaly.detected-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"AnomalyDetected\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"anomaly_id\",\"type\":\"string\"},{\"name\":\"source_service\",\"type\":\"string\"},{\"name\":\"anomaly_type\",\"type\":\"string\"},{\"name\":\"spike_pattern\",\"type\":\"string\"},{\"name\":\"membrane_potential_trace\",\"type\":\"string\"},{\"name\":\"confidence_score\",\"type\":\"double\"},{\"name\":\"false_positive\",\"type\":\"boolean\",\"default\":false},{\"name\":\"detected_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 4. neuro.memory.formed
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.memory.formed-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"MemoryFormed\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"memory_id\",\"type\":\"string\"},{\"name\":\"threat_id\",\"type\":\"string\"},{\"name\":\"encoding_strength\",\"type\":\"double\"},{\"name\":\"formed_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 5. neuro.memory.recalled
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.memory.recalled-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"MemoryRecalled\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"memory_id\",\"type\":\"string\"},{\"name\":\"trigger_event_hash\",\"type\":\"string\"},{\"name\":\"similarity_score\",\"type\":\"double\"},{\"name\":\"recalled_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 6. neuro.plasticity.update
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.plasticity.update-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"PlasticityUpdate\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"synapse_id\",\"type\":\"string\"},{\"name\":\"pre_neuron\",\"type\":\"string\"},{\"name\":\"post_neuron\",\"type\":\"string\"},{\"name\":\"weight_delta\",\"type\":\"double\"},{\"name\":\"new_weight\",\"type\":\"double\"},{\"name\":\"learning_rule\",\"type\":\"string\"},{\"name\":\"updated_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 7. neuro.immune.response
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.immune.response-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"ImmuneResponse\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"response_id\",\"type\":\"string\"},{\"name\":\"threat_id\",\"type\":\"string\"},{\"name\":\"action\",\"type\":\"string\"},{\"name\":\"target_ip\",\"type\":\"string\"},{\"name\":\"rule_id\",\"type\":\"string\"},{\"name\":\"triggered_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 8. neuro.dream.cycle
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.dream.cycle-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"DreamCycle\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"cycle_id\",\"type\":\"string\"},{\"name\":\"phase\",\"type\":\"string\"},{\"name\":\"duration_ms\",\"type\":\"long\"},{\"name\":\"patterns_consolidated\",\"type\":\"int\"},{\"name\":\"weights_updated\",\"type\":\"int\"},{\"name\":\"completed_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 9. neuro.evolution.checkpoint
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.evolution.checkpoint-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"EvolutionCheckpoint\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"checkpoint_id\",\"type\":\"string\"},{\"name\":\"generation\",\"type\":\"int\"},{\"name\":\"fitness_score\",\"type\":\"double\"},{\"name\":\"changes_applied\",\"type\":\"string\"},{\"name\":\"created_at\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

# 10. neuro.audit.trail
curl -s -X POST "$SCHEMA_REGISTRY/subjects/neuro.audit.trail-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{
  "schema": "{\"type\":\"record\",\"name\":\"NeuroAudit\",\"namespace\":\"com.cybershield.neuromorphic\",\"fields\":[{\"name\":\"audit_id\",\"type\":\"string\"},{\"name\":\"action\",\"type\":\"string\"},{\"name\":\"neuron_layer\",\"type\":\"string\"},{\"name\":\"component\",\"type\":\"string\"},{\"name\":\"outcome\",\"type\":\"string\"},{\"name\":\"spike_signature\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"}}]}"
}'

echo "═══ All Neuromorphic Kafka topics and schemas registered ═══"
