import random
import time
import uuid

class EvolutionCore:
    def __init__(self):
        self.generation = 1
        self.current_fitness = 85.0
        self.history = []
        self.candidates = []
        
        # Initial candidates
        for i in range(5):
            self.candidates.append(self._generate_random_candidate(f"gen1_{i}"))
            
    def _generate_random_candidate(self, cid: str):
        return {
            "id": cid,
            "fitness": random.uniform(70.0, 88.0),
            "hyperparams": {
                "neurons_network_cortex": random.randint(150, 300),
                "neurons_log_cortex": random.randint(100, 250),
                "learning_rate_stdp": random.uniform(0.005, 0.02)
            }
        }
        
    def calculate_fitness(self, tpr, fpr, novel_dr, resp_time_ms, mem_eff):
        # normalize and weight
        norm_tpr = min(1.0, tpr)
        norm_fpr = 1.0 - min(1.0, fpr) # inverted
        norm_novel = min(1.0, novel_dr)
        norm_resp = max(0.0, 1.0 - (resp_time_ms / 100.0))
        norm_mem = min(1.0, mem_eff / 1000.0)
        
        score = (norm_tpr * 0.35) + (norm_fpr * 0.25) + (norm_novel * 0.20) + (norm_resp * 0.10) + (norm_mem * 0.10)
        return score * 100.0

    def trigger_evolution_cycle(self):
        # evaluate candidates
        best_candidate = max(self.candidates, key=lambda c: c["fitness"])
        
        improved = False
        if best_candidate["fitness"] > self.current_fitness + 3.0:
            # Promote
            self.history.append({
                "generation": self.generation,
                "old_fitness": self.current_fitness,
                "new_fitness": best_candidate["fitness"],
                "timestamp": time.time()
            })
            self.current_fitness = best_candidate["fitness"]
            self.generation += 1
            improved = True
            
        # Re-populate candidates
        new_candidates = []
        # Elitism + mutation
        new_candidates.append(best_candidate)
        for i in range(4):
            mutated = self._generate_random_candidate(f"gen{self.generation}_{i}")
            new_candidates.append(mutated)
            
        self.candidates = new_candidates
        
        return improved, best_candidate
