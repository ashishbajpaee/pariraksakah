from fastapi import FastAPI, BackgroundTasks
from typing import List, Dict, Any
from plasticity_core import PlasticityCore
import requests
import os
import json
import time

app = FastAPI(title="Synaptic Plasticity Manager")

core = PlasticityCore()
SYNAPTIC_MEMORY_URL = os.environ.get("SYNAPTIC_MEMORY_URL", "http://neuro-synaptic-memory:8071")

@app.get("/plasticity/rules")
async def get_rules():
    return {
        "STDP": {"A_plus": core.A_plus, "A_minus": core.A_minus, "tau": core.tau_plus},
        "Hebbian": {"enabled": True},
        "Homeostatic": {"target_rate_hz": core.target_rate},
        "Neuromodulators": {
            "dopamine": core.dopamine_level,
            "norepinephrine": core.norepinephrine_level,
            "acetylcholine": core.acetylcholine_level
        }
    }

@app.post("/plasticity/trigger/{rule}")
async def trigger_rule(rule: str, bg_tasks: BackgroundTasks):
    def update_task():
        # In a real system, this fetches recent spike trains and applies the rule across the weight matrix
        # Then calls the batch update API of the Synaptic Memory service
        pass
    bg_tasks.add_task(update_task)
    return {"status": f"Rule {rule} triggered"}

@app.get("/plasticity/history")
async def get_history():
    return {"message": "Query TimescaleDB `synaptic_weights_history` for full log."}

@app.post("/plasticity/reward/{pattern_id}")
async def reward(pattern_id: str):
    core.apply_reward()
    return {"status": "Reward applied, dopamine increased", "dopamine": core.dopamine_level}

@app.post("/plasticity/punish/{pattern_id}")
async def punish(pattern_id: str):
    core.apply_punish()
    return {"status": "Punish applied, dopamine decreased", "dopamine": core.dopamine_level}
