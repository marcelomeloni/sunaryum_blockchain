import time
import configparser
import logging
from core.blockchain import Blockchain
from core.mempool import Mempool
from core.gossip import GossipManager
from core.peer_discovery import PeerDiscovery
from core.wallet import Wallet
import threading
from core.vrf import VRFNode
from datetime import datetime, timezone
from collections import defaultdict

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('FullNode')

def get_config_value(config, section, key, default=None, cast=str):
    """Obtém valor da configuração com fallback para default"""
    try:
        value = config.get(section, key)
        return cast(value) if cast else value
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default

def main():
    logger.info("Iniciando Full Node...")
    
    try:
        # Carregar configuração
        config = configparser.ConfigParser()
        config.read('config.ini')
        
        # Inicializar carteira com chave privada do config
        private_key = get_config_value(config, 'Node', 'private_key', None)
        wallet = Wallet(private_key=private_key)
        logger.info(f"Carteira inicializada. Endereço público: {wallet.public_key[:10]}...")
        
        # Inicializar Blockchain
        blockchain = Blockchain(wallet)
        
        mempool = Mempool()
        
        # Configurações de rede com fallbacks
        broadcast_ip = get_config_value(config, 'Network', 'broadcast_ip', '224.0.0.114')
        broadcast_port = get_config_value(config, 'Network', 'broadcast_port', 5001, int)
        listen_port = get_config_value(config, 'Network', 'listen_port', 5000, int)
        advertised_ip = get_config_value(config, 'Network', 'advertised_ip', '127.0.0.1')
        
        network_config = {
            'broadcast_ip': broadcast_ip,
            'broadcast_port': broadcast_port,
            'listen_port': listen_port,
            'advertised_ip': advertised_ip,
            'peers': get_config_value(config, 'Network', 'peers', '')
        }

        # Descoberta de peers
        discovery = PeerDiscovery(config={'Network': network_config})
        logger.info(f"Peers configurados: {len(discovery.peers)}")
        vrf_secret = get_config_value(config, 'VRF', 'vrf_secret', private_key)
        vrf_node = VRFNode(vrf_secret)
        gossip = GossipManager(
            config=config,
            blockchain=blockchain,
            mempool=mempool,
            discovery=discovery,
            wallet=wallet,
            vrf=vrf_node 
        )
        
        # Iniciar servidor P2P
        gossip.start_server()
        
        # Dar tempo para o servidor iniciar
        time.sleep(2)
        
        # Sincronizar blockchain inicialmente
        discovery.sync_blockchain(blockchain)
        
        # Variável para controlar tempo da última eleição forçada
        last_forced_election = 0
        election_cooldown = 300  # 5 minutos entre eleições forçadas
        
        logger.info(f"Full Node iniciado na porta {listen_port}. Aguardando dados...")
        
        # Loop principal simplificado
        last_forced_check = 0
        while True:
            try:
                # Obter peers ativos EXTERNOS
                active_peers = discovery.get_active_peers()
                
                # Log de diagnóstico
                logger.info(f"Peers ativos detectados: {len(active_peers)}")
                
                # Verificar isolamento apenas se não houver peers externos
                if len(active_peers) == 0:
                    current_time = time.time()
                    # Verificar a cada 5 minutos
                    if current_time - last_forced_check > 300:
                        last_forced_check = current_time
                        last_block = blockchain.get_last_block()
                        if last_block:
                            # Converter para UTC
                            last_block_time = datetime.fromisoformat(
                                last_block['timestamp'].replace('Z', '+00:00')
                            ).replace(tzinfo=timezone.utc)
                            
                            elapsed = (datetime.now(timezone.utc) - last_block_time).total_seconds()
                            logger.info(f"Tempo desde último bloco: {elapsed:.1f}s")
                            
                            # Verificar se passou mais de 1.5x o intervalo de bloco
                            if elapsed > gossip.block_interval * 1.5:
                                logger.info("Nó isolado e sem novos blocos. Aguardando ciclo de eleição.")
                
                # Sincronizar blockchain periodicamente
                time.sleep(30)
                discovery.sync_blockchain(blockchain)
                
            except Exception as e:
                logger.error(f"Erro no loop principal: {str(e)}", exc_info=True)
                time.sleep(30)
                
    
                
    except Exception as e:
        logger.error(f"Erro fatal: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()