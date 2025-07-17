import random
from datetime import datetime
import logging
import time

logger = logging.getLogger('SensorReader')

class SensorReader:
    def __init__(self, simulation=True):
        self.simulation = simulation
        self.last_value = 2.0  # Valor base
        self.min_production = 0.5
        self.max_production = 5.0
        
    def read_production(self):
        if self.simulation:
            return self._simulate_production()
        else:
            # Implementação real aqui
            raise NotImplementedError("Leitura de sensor real não implementada")
    
    def _simulate_production(self):
        # Gera valor com base no anterior + variação
        variation = random.uniform(-0.5, 0.5)
        new_value = max(self.min_production, min(self.max_production, self.last_value + variation))
        self.last_value = new_value
        
        return {
            "timestamp": datetime.now().isoformat(),
            "production_kwh": round(new_value, 2)
        }