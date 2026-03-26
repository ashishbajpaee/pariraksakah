from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, List
import time
import hashlib
from snn_core import SNNCore
from kafka_publisher import KafkaPublisher
from db_client import DBClient

app = FastAPI(title="Spiking Neural Network Engine API")

snn = SNNCore()
kafka_pub = KafkaPublisher()
db = DBClient()

class SNNInput(BaseModel):
    event_type: str
    severity: int
    context: Dict[str, Any]

@app.post("/snn/input")
async def inject_event(payload: SNNInput, bg_tasks: BackgroundTasks):
    pattern_hash = hashlib.sha256(str(payload).encode()).hexdigest()
    
    # Map severity to current intensity for input neurons
    base_intensity = payload.severity * 0.5 # Maps 0-10 severity to 0.0-5.0 nA
    intensities = [base_intensity * (1.0 + i*0.01) for i in range(100)]
    
    # Run SNN
    spikes = snn.inject_input(duration_ms=10.0, intensities=intensities)
    
    # Background save to DB & publish
    def process_spikes(spike_data, expected_hash, threat_ctx):
        for idx, t_ms in zip(spike_data['indices'], spike_data['times']):
            neuron_id = f"out_node_{idx}"
            v_m = -55.0 # Fixed at threshold for the event
            kafka_pub.publish_spike(neuron_id, "output", t_ms, v_m, expected_hash, threat_ctx)
            db.insert_spike_event(neuron_id, "output", t_ms, v_m, expected_hash, threat_ctx)

    bg_tasks.add_task(process_spikes, spikes, pattern_hash, payload.context)

    return {"status": "Spike train injected", "spikes_generated": len(spikes['indices'])}

@app.get("/snn/state")
async def get_state():
    return snn.get_state()

@app.get("/snn/topology")
async def get_topology():
    return {
        "layers": {
            "input_encoding": {"neurons": 100, "type": "LIF rate coding"},
            "convolutional": {"neurons": 200, "type": "LIF Spatiotemporal"},
            "recurrent": {"neurons": 300, "type": "LIF Reservoir computing"},
            "output_classification": {"neurons": 50, "type": "LIF integration"}
        },
        "parameters": {
            "V_REST": "-70mV",
            "R": "10MOhm",
            "tau": "20ms",
            "threshold": "-55mV",
            "refractory": "2ms"
        }
    }

@app.get("/snn/activity")
async def get_activity():
    return {"message": "Requires websocket or direct prometheus queries for real-time WebGL."}

@app.post("/snn/reset")
async def reset_network():
    snn.reset()
    return {"status": "Network reset to V_REST baseline state"}
