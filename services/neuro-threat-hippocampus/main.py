from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import List
from hippocampus_core import HippocampusCore

app = FastAPI(title="Threat Hippocampus Memory System")

hippo = HippocampusCore()

class EncodingRequest(BaseModel):
    threat_id: str
    spike_pattern: List[float]
    severity: int
    confidence: float

class RecallRequest(BaseModel):
    spike_pattern: List[float]

@app.post("/memory/encode")
async def encode_memory(req: EncodingRequest, bg_tasks: BackgroundTasks):
    mem_id = hippo.encode(req.threat_id, req.spike_pattern, req.severity, req.confidence)
    def bg_link():
        hippo.link_in_neo4j(mem_id, req.threat_id)
        # Publish neuro.memory.formed here
    bg_tasks.add_task(bg_link)
    return {"status": "Memory encoded", "memory_id": mem_id}

@app.post("/memory/recall") # Using POST since we pass list body instead of param url limit
async def recall_memory(req: RecallRequest):
    recalled = hippo.recall(req.spike_pattern)
    return {"recalled_memories": recalled}

@app.get("/memory/list")
async def list_memories():
    return {"memories": list(hippo.memories.keys())}

@app.delete("/memory/prune")
async def prune_memories():
    pruned_count = hippo.prune_decayed()
    return {"status": "Pruning complete", "pruned": pruned_count}

@app.get("/memory/associations/{memory_id}")
async def get_associations(memory_id: str):
    return {"message": "Requires Neo4j traversal. Traversal simulated here.", "associations": []}

@app.get("/memory/stats")
async def stats():
    return {"total_active_memories": len(hippo.memories)}
