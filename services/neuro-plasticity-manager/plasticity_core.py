import math

class PlasticityCore:
    def __init__(self):
        self.A_plus = 0.01
        self.A_minus = 0.012
        self.tau_plus = 20.0
        self.tau_minus = 20.0
        self.target_rate = 10.0 # Hz
        
        # Neuromodulators
        self.dopamine_level = 1.0 # Reward, scales up LTP
        self.norepinephrine_level = 1.0 # Attention, speeds learning
        self.acetylcholine_level = 1.0 # Memory, enhances encoding
        
    def calculate_stdp(self, pre_time: float, post_time: float, current_weight: float) -> float:
        delta_t = post_time - pre_time
        if delta_t > 0 and delta_t <= 20.0:
            # pre before post
            delta_w = self.A_plus * math.exp(-delta_t / self.tau_plus)
            return current_weight + (delta_w * self.dopamine_level * self.norepinephrine_level)
        elif delta_t < 0 and delta_t >= -20.0:
            # post before pre
            delta_w = -self.A_minus * math.exp(delta_t / self.tau_minus)
            return current_weight + (delta_w * self.norepinephrine_level)
        return current_weight

    def calculate_hebbian(self, current_weight: float, co_activation_rate: float) -> float:
        # Simple Hebbian: fire together, wire together
        delta = 0.05 * co_activation_rate * self.acetylcholine_level
        return current_weight + delta

    def calculate_homeostatic(self, current_weight: float, current_rate: float) -> float:
        if current_rate > self.target_rate * 1.2:
            return current_weight * 0.95 # scale down
        elif current_rate < self.target_rate * 0.8:
            return current_weight * 1.05 # scale up
        return current_weight

    def apply_reward(self):
        self.dopamine_level = min(5.0, self.dopamine_level + 1.0)
        
    def apply_punish(self):
        self.dopamine_level = max(0.1, self.dopamine_level * 0.5)

    def decay_neuromodulators(self):
        # Naturally return to baseline
        self.dopamine_level += (1.0 - self.dopamine_level) * 0.1
        self.norepinephrine_level += (1.0 - self.norepinephrine_level) * 0.1
        self.acetylcholine_level += (1.0 - self.acetylcholine_level) * 0.1
