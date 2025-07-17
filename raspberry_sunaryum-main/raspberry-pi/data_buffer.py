import logging
from collections import deque

logger = logging.getLogger('RingBuffer')

class RingBuffer:
    def __init__(self, size=3):
        self.buffer = deque(maxlen=size)
    
    def add_reading(self, reading):
        self.buffer.append(reading)
    
    def get_all_readings(self):
        return list(self.buffer)
    
    def get_latest_reading(self):
        """Retorna a leitura mais recente"""
        if self.buffer:
            return self.buffer[-1]
        return None
    
    def clear(self):
        self.buffer.clear()