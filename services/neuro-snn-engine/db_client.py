import os
import json
import psycopg2
from psycopg2.extras import Json
from datetime import datetime

class DBClient:
    def __init__(self):
        self.host = os.environ.get("POSTGRES_HOST", "timescaledb")
        self.port = os.environ.get("POSTGRES_PORT", "5432")
        self.dbname = os.environ.get("POSTGRES_DB", "cybershield")
        self.user = os.environ.get("POSTGRES_USER", "cybershield")
        self.password = os.environ.get("POSTGRES_PASSWORD", "changeme_postgres")
        self.conn = None

    def connect(self):
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password
            )
            self.conn.autocommit = True
        except Exception as e:
            print(f"Error connecting to DB: {e}")

    def insert_spike_event(self, neuron_id: str, layer: str, spike_time: float, membrane_potential: float, input_pattern_hash: str, threat_context: dict):
        if not self.conn:
            self.connect()
        if not self.conn:
            return

        query = """
        INSERT INTO neural_spike_log (neuron_id, layer, spike_time, membrane_potential, input_pattern_hash, threat_context, recorded_at)
        VALUES (%s, %s, to_timestamp(%s), %s, %s, %s, %s)
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, (
                    neuron_id,
                    layer,
                    spike_time,
                    membrane_potential,
                    input_pattern_hash,
                    Json(threat_context) if threat_context else None,
                    datetime.utcnow()
                ))
        except Exception as e:
            print(f"Error inserting spike event: {e}")
            self.conn = None # force reconnect
