import time
import requests
import uuid

class DreamCore:
    def __init__(self):
        self.is_dreaming = False
        self.current_phase = "AWAKE"
        self.insights = []

    def run_dream_cycle(self):
        if self.is_dreaming:
            return
        
        self.is_dreaming = True
        cycle_id = str(uuid.uuid4())
        
        try:
            # 1. NREM Phase 1 - Light Consolidation (accelerated replay)
            self.current_phase = "NREM_1"
            # Simulate 10 min phase
            time.sleep(2) # speeded up for testing
            weights_updated = 150
            
            # 2. NREM Phase 2 - Deep Consolidation (rewards, memory strengthening)
            self.current_phase = "NREM_2"
            time.sleep(2)
            patterns_consolidated = 42
            memories_strengthened = 10
            memories_pruned = 5
            
            # 3. REM Phase - Creative Synthesis (synthetic novel scenarios)
            self.current_phase = "REM"
            time.sleep(2)
            self.insights.append("Identified potential gap in lateral movement detection for sub-T1001 pattern.")
            
            # Clean up & checkpoint
            self.current_phase = "AWAKE"
            self.is_dreaming = False
            
            # Here we would normally trigger checkpoint
            # requests.get("http://neuro-synaptic-memory:8071/synaptic/checkpoint")
            
            return {
                "cycle_id": cycle_id,
                "status": "Completed",
                "patterns_consolidated": patterns_consolidated,
                "weights_updated": weights_updated,
                "memories_strengthened": memories_strengthened,
                "memories_pruned": memories_pruned
            }
            
        except Exception as e:
            self.current_phase = "AWAKE"
            self.is_dreaming = False
            return {"status": "Aborted", "error": str(e)}

    def abort(self):
        if self.is_dreaming:
            self.is_dreaming = False
            self.current_phase = "AWAKE"
            return True
        return False
