import time
import math
import numpy as np
from scipy.spatial.distance import cosine

class HippocampusCore:
    def __init__(self):
        self.memories = {}

    def encode(self, threat_id: str, spike_pattern: list, severity: int, confidence: float) -> str:
        memory_id = f"mem_{int(time.time()*1000)}"
        
        # Strength based on severity & confidence
        encoding_strength = (severity / 10.0) * confidence
        
        decay_rate = 0.001 if encoding_strength > 0.8 else 0.05
        
        # Mock sparse representation
        sparse_rep = np.array(spike_pattern)
        
        self.memories[memory_id] = {
            "threat_id": threat_id,
            "sparse_rep": sparse_rep,
            "strength": encoding_strength,
            "decay_rate": decay_rate,
            "recall_count": 0,
            "formed_at": time.time()
        }
        
        return memory_id

    def recall(self, spike_pattern: list) -> list:
        # Search all memories for cosine similarity > 0.85
        pattern = np.array(spike_pattern)
        recalled = []
        for mem_id, mem_data in self.memories.items():
            rep = mem_data["sparse_rep"]
            if len(rep) == len(pattern):
                sim = 1 - cosine(rep, pattern)
                if sim > 0.85:
                    mem_data["recall_count"] += 1
                    mem_data["strength"] = min(1.0, mem_data["strength"] + 0.1) # Boost
                    recalled.append({"memory_id": mem_id, "similarity": sim})
        return recalled

    def prune_decayed(self):
        now = time.time()
        to_delete = []
        for mem_id, mem_data in self.memories.items():
            age_days = (now - mem_data["formed_at"]) / 86400
            current_strength = mem_data["strength"] * math.exp(-mem_data["decay_rate"] * age_days)
            if current_strength < 0.1:
                to_delete.append(mem_id)
        
        for k in to_delete:
            del self.memories[k]
        return len(to_delete)

    def link_in_neo4j(self, memory_id: str, threat_id: str):
        # Mocks actual DB push to Neo4j
        pass
