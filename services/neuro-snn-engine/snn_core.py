from brian2 import *
import numpy as np

# Biological parameters
V_REST = -70 * mV
R_MEM = 10 * Mohm
TAU = 20 * ms
V_THRESH = -55 * mV
V_RESET = -70 * mV
T_REF = 2 * ms

# Equation for Leaky Integrate-and-Fire
eqs = '''
dv/dt = (-(v - V_REST) + R_MEM * I) / TAU : volt (unless refractory)
I : amp
'''

class SNNCore:
    def __init__(self):
        # Start Brian2 core initialization
        start_scope()

        # Input Encoding Layer (convert security events to rate/timing)
        self.input_layer = NeuronGroup(100, eqs, threshold='v > V_THRESH', reset='v = V_RESET', refractory=T_REF, method='exact')
        self.input_layer.v = V_REST
        
        # Convolutional Spike Layer (synthetic abstraction for Brian2)
        self.conv_layer = NeuronGroup(200, eqs, threshold='v > V_THRESH', reset='v = V_RESET', refractory=T_REF, method='exact')
        self.conv_layer.v = V_REST
        
        # Recurrent Spike Layer (Reservoir)
        self.recurrent_layer = NeuronGroup(300, eqs, threshold='v > V_THRESH', reset='v = V_RESET', refractory=T_REF, method='exact')
        self.recurrent_layer.v = V_REST
        
        # Output Classification Layer
        self.output_layer = NeuronGroup(50, eqs, threshold='v > V_THRESH', reset='v = V_RESET', refractory=T_REF, method='exact')
        self.output_layer.v = V_REST

        # Synapses
        self.syn_in_conv = Synapses(self.input_layer, self.conv_layer, 'w : volt', on_pre='v_post += w')
        self.syn_in_conv.connect(p=0.5)
        self.syn_in_conv.w = 'rand() * 5 * mV'

        self.syn_conv_rec = Synapses(self.conv_layer, self.recurrent_layer, 'w : volt', on_pre='v_post += w')
        self.syn_conv_rec.connect(p=0.4)
        self.syn_conv_rec.w = 'rand() * 4 * mV'

        self.syn_rec_rec = Synapses(self.recurrent_layer, self.recurrent_layer, 'w : volt', on_pre='v_post += w')
        self.syn_rec_rec.connect(p=0.1)
        self.syn_rec_rec.w = 'rand() * 2 * mV'

        self.syn_rec_out = Synapses(self.recurrent_layer, self.output_layer, 'w : volt', on_pre='v_post += w')
        self.syn_rec_out.connect(p=1.0) # Fully connected to output
        self.syn_rec_out.w = 'rand() * 6 * mV'

        # Monitors
        self.M_in = StateMonitor(self.input_layer, 'v', record=True)
        self.S_in = SpikeMonitor(self.input_layer)

        self.M_out = StateMonitor(self.output_layer, 'v', record=True)
        self.S_out = SpikeMonitor(self.output_layer)
        
        # Network object
        self.net = Network(self.input_layer, self.conv_layer, self.recurrent_layer, self.output_layer, 
                           self.syn_in_conv, self.syn_conv_rec, self.syn_rec_rec, self.syn_rec_out,
                           self.M_in, self.S_in, self.M_out, self.S_out)

    def inject_input(self, duration_ms: float, intensities: list):
        # intensities scale input current
        if len(intensities) < 100:
            intensities += [0.0] * (100 - len(intensities))
        
        self.input_layer.I = np.array(intensities[:100]) * nA
        self.net.run(duration_ms * ms)
        
        # Extract spike times
        spikes = {
            "indices": self.S_out.i[:].tolist(),
            "times": (self.S_out.t[:] / ms).tolist()
        }
        return spikes

    def get_state(self):
        return {
            "input_v": (self.input_layer.v[:] / mV).tolist(),
            "output_v": (self.output_layer.v[:] / mV).tolist()
        }
        
    def reset(self):
        self.input_layer.v = V_REST
        self.conv_layer.v = V_REST
        self.recurrent_layer.v = V_REST
        self.output_layer.v = V_REST
        self.net.t = 0 * ms
