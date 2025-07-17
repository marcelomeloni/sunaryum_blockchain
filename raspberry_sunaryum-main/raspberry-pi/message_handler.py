import time
from datetime import datetime
class MessageHandler:
    def create_minute_summary(self, readings):
        """Cria mensagem com resumo de 1 minuto usando as leituras fornecidas"""
        if not readings:
            return None
            
        total_kwh = sum(r['kwh'] for r in readings)
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        return {
            "type": "MINUTE_PROD",
            "public_address": self.wallet.public_key,
            "total_kwh": total_kwh,
            "timestamp": timestamp
        }
    
    # Mantém outros métodos para compatibilidade
    def create_daily_summary(self, *args, **kwargs):
        return self.create_minute_summary(*args, **kwargs)