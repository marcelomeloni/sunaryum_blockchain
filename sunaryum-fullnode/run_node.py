import time
import configparser
import logging
from core.blockchain import Blockchain
from core.mempool import Mempool
from core.gossip import GossipManager
from core.peer_discovery import PeerDiscovery
from core.wallet import Wallet
import threading
from datetime import datetime, timezone  # Importe timezone
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
        
        gossip = GossipManager(
            config=config,
            blockchain=blockchain,
            mempool=mempool,
            discovery=discovery,
            wallet=wallet
        )
        
        # Iniciar servidor P2P
        gossip.start_server()
        
        # Iniciar processo de eleição imediatamente
        threading.Thread(target=gossip._election_worker, daemon=True).start()
        
        logger.info(f"Full Node iniciado na porta {listen_port}. Aguardando dados...")
        
        # Sincronizar blockchain inicialmente
        discovery.sync_blockchain(blockchain)
        
        # Loop principal simplificado
        while True:
            try:
                # Verificar se estamos isolados e precisa iniciar eleição
                active_peers = discovery.get_active_peers()
                if len(active_peers) <= 1:  # Somente nós mesmos
                    # Verificar se já passou tempo suficiente desde o último bloco
                    last_block = blockchain.get_last_block()
                    if last_block:
                        # Usar timezone UTC
                        last_block_time = datetime.fromisoformat(
                            last_block['timestamp'].replace('Z', '+00:00')
                        ).replace(tzinfo=timezone.utc)
                        
                        # Usar datetime com timezone UTC
                        elapsed = (datetime.now(timezone.utc) - last_block_time).total_seconds()
                        
                        if elapsed > gossip.block_interval * 1.5:
                            logger.info("Nó isolado e sem novos blocos, forçando eleição")
                            gossip._run_election()
                
                # Sincronizar periodicamente
                time.sleep(30)
                discovery.sync_blockchain(blockchain)
                discovery.sync_mempool(mempool)
                
            except Exception as e:
                logger.error(f"Erro no loop principal: {str(e)}", exc_info=True)
                time.sleep(30)
                
    except Exception as e:
        logger.error(f"Erro fatal: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()