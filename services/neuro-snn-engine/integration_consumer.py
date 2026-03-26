import os
import json
from kafka import KafkaConsumer
from snn_core import SNNCore
from kafka_publisher import KafkaPublisher
from db_client import DBClient
import hashlib

def start_integration_consumer(snn: SNNCore, pub: KafkaPublisher, db: DBClient):
    bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    
    # Listen to existing stack topics
    topics = ['falco.alerts', 'chaos.results', 'dna.anomalies', 'dsrn.threat.intel']
    
    try:
        consumer = KafkaConsumer(
            *topics,
            bootstrap_servers=bootstrap_servers,
            value_deserializer=lambda x: json.loads(x.decode('utf-8', 'ignore'))
        )
        print(f"Integration Consumer listening on {topics}")
        
        for msg in consumer:
            topic = msg.topic
            data = msg.value
            
            # Formulate severity
            severity = data.get("severity", 5)
            if isinstance(severity, str):
                severity = 8 if severity.upper() in ["HIGH", "CRITICAL"] else 4
                
            input_pattern_hash = hashlib.sha256(str(data).encode()).hexdigest()
            base_intensity = severity * 0.5
            intensities = [base_intensity * (1.0 + i*0.01) for i in range(100)]
            
            # Inject spike
            spikes = snn.inject_input(10.0, intensities)
            
            # Record
            for idx, t_ms in zip(spikes['indices'], spikes['times']):
                neuron_id = f"out_node_{idx}"
                pub.publish_spike(neuron_id, "output", t_ms, -55.0, input_pattern_hash, data)
                db.insert_spike_event(neuron_id, "output", t_ms, -55.0, input_pattern_hash, data)
                
    except Exception as e:
        print(f"Consumer error: {e}")

if __name__ == "__main__":
    snn = SNNCore()
    pub = KafkaPublisher()
    db = DBClient()
    start_integration_consumer(snn, pub, db)
