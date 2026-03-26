import os
import json
import time
from kafka import KafkaProducer

class KafkaPublisher:
    def __init__(self):
        self.bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        self.producer = None
        self._connect()

    def _connect(self):
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                retries=5
            )
        except Exception as e:
            print(f"Error connecting to Kafka: {e}")

    def publish_spike(self, neuron_id: str, layer: str, spike_time: float, membrane_potential: float, input_pattern_hash: str, threat_context: dict):
        if not self.producer:
            self._connect()
        if not self.producer:
            return

        # Note: In a real system we would format this with Avro serialization and Confluent Schema Registry.
        # For immediate runnability without Avro schema registry strict validation setup here, we publish JSON formatted as expected.
        payload = {
            "neuron_id": neuron_id,
            "layer": layer,
            "spike_time": int(spike_time * 1000), # to ms
            "membrane_potential": membrane_potential,
            "input_pattern_hash": input_pattern_hash,
            "threat_context": json.dumps(threat_context) if threat_context else None,
            "recorded_at": int(time.time() * 1000)
        }
        try:
            self.producer.send('neuro.spike.events', payload)
            self.producer.flush()
        except Exception as e:
            print(f"Error publishing to Kafka: {e}")
