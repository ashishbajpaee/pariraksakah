from fastapi import FastAPI, BackgroundTasks
from evolution_core import EvolutionCore
import uuid

app = FastAPI(title="Neuromorphic Evolution System")
evo = EvolutionCore()

@app.get("/evolution/fitness")
async def get_fitness():
    return {"current_fitness": evo.current_fitness, "history": evo.history}

@app.get("/evolution/generation")
async def get_generation():
    return {"generation": evo.generation, "active_architecture": "LIF-Sparse-Hypergraph-v" + str(evo.generation)}

@app.post("/evolution/trigger")
async def trigger_evolution(bg_tasks: BackgroundTasks):
    improved, best = evo.trigger_evolution_cycle()
    
    def log_to_kafka_mlflow():
        # Here we would publish to neuro.evolution.checkpoint
        # And register the model version in MLFlow
        pass
        
    if improved:
        bg_tasks.add_task(log_to_kafka_mlflow)
        
    return {"status": "Evaluation completed", "promoted": improved, "best_candidate": best}

@app.get("/evolution/candidates")
async def get_candidates():
    return {"shadow_candidates": evo.candidates}

@app.get("/evolution/history")
async def get_history():
    return {"history": evo.history}
