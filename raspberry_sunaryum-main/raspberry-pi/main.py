import sys
import time
import logging
import threading
import json
from datetime import datetime, timezone
from wallet_manager import WalletManager
from sensor_reader import SensorReader
from data_buffer import RingBuffer
from scheduler import FastScheduler
from p2p_client import P2PClient
from config_manager import ConfigManager
from peer_discovery import PeerDiscovery

# Configuração básica de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger('SunaryumNode')

class SunaryumNode:
    def __init__(self, config):
        self.config = config
        self.wallet_manager = None
        self.sensor_reader = SensorReader()
        self.data_buffer = RingBuffer(size=3)  # Buffer menor para envios rápidos
        self.scheduler = FastScheduler()
        self.p2p_client = P2PClient()
        self.peers = []
        # Descoberta de peers
        self.discovery = PeerDiscovery(config)
        self.discovery.start()
        
        # Atualizar lista de peers imediatamente
        self.update_peers()
        
        # Atualizar lista de peers periodicamente
        threading.Thread(target=self.update_peers_periodically, daemon=True).start()

    def update_peers_periodically(self):
        while True:
            self.update_peers()
            time.sleep(60)

    def update_peers(self):
        discovered_peers = self.discovery.get_peers()
        if discovered_peers:
            self.peers = discovered_peers
            logger.info(f"Peers atualizados: {len(self.peers)} encontrados")
        else:
            logger.warning("Nenhum peer encontrado. Tentando novamente...")

    def initialize(self):
        seed_phrase = self.config.get_seed_phrase()
        self.wallet_manager = WalletManager(seed_phrase)
        logger.info(f"Carteira inicializada. Endereço: {self.wallet_manager.get_public_address()}")
        logger.info(f"Modo rápido ativo: Leituras e envios a cada 10s")

    def read_and_send_data(self):
        """Lê dados do sensor e envia imediatamente"""
        try:
            # 1. Ler dados do sensor
            data = self.sensor_reader.read_production()
            self.data_buffer.add_reading(data)
            logger.debug(f"Leitura adicionada: {data['production_kwh']} kWh")
            
            # 2. Preparar e enviar dados imediatamente
            self.send_production_data()
                
        except Exception as e:
            logger.error(f"Erro na leitura/envio: {str(e)}")

    def send_production_data(self):
        """Envia dados de produção imediatamente"""
        try:
            # Obtém a leitura mais recente
            recent_data = self.data_buffer.get_latest_reading()
            if not recent_data:
                logger.warning("Nenhum dado recente para enviar")
                return
                
            public_address = self.wallet_manager.get_public_address()
            
            # Usar datetime com timezone UTC
            timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
            
            # Prepara a mensagem
            message = {
                "type": "MINUTE_PROD",
                "public_address": public_address,
                "timestamp": timestamp,
                "total_kwh": recent_data['production_kwh'],
                "is_partial": True  # Indica que é uma leitura parcial
            }

            # Converter para JSON string ordenado
            message_json = json.dumps(message, sort_keys=True)

            # Assinar a mensagem
            signature = self.wallet_manager.sign_message(message_json)
            if not signature:
                logger.error("Falha ao assinar mensagem")
                return

            # Adicionar assinatura ao payload
            message['signature'] = signature
            
            # Envia para peers descobertos
            own_ip = "127.0.0.1"
            own_port = self.config.get_network_setting('listen_port', 5002, int)
            valid_peers = [peer for peer in self.peers if peer != (own_ip, own_port)]
            
            if not valid_peers:
                logger.error("Nenhum peer válido disponível para envio")
                return
                
            for peer in valid_peers:
                try:
                    # Envia a mensagem assinada
                    response = self.p2p_client.send_message(peer, message)
                    
                    if response == "ACK":
                        logger.debug(f"Enviado {recent_data['production_kwh']}kWh para {peer[0]}:{peer[1]}")
                    else:
                        logger.debug(f"Resposta de {peer[0]}:{peer[1]}: {response}")
                        
                except Exception as e:
                    logger.debug(f"Falha ao enviar para {peer[0]}:{peer[1]} - {str(e)}")
                
        except Exception as e:
            logger.error(f"Erro no envio rápido: {str(e)}", exc_info=True)

    def start(self):
        self.initialize()
        # Agendar leitura e envio a cada 10 segundos
        self.scheduler.schedule_job(self.read_and_send_data, interval=10)
        logger.info("Nó Sunaryum iniciado em modo rápido (envios a cada 10s)")
        self.scheduler.run_forever()

if __name__ == "__main__":
    try:
        # Carrega configuração
        config = ConfigManager()
        logging.basicConfig(
            level=config.get_log_level(),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            stream=sys.stdout
        )
        
        node = SunaryumNode(config)
        node.start()
        
    except KeyboardInterrupt:
        logger.info("Nó encerrado pelo usuário")
    except Exception as e:
        logger.exception(f"Erro fatal: {str(e)}")
        sys.exit(1)