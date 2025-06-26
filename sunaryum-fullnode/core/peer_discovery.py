import threading
import time
import logging
import socket
import json

logger = logging.getLogger('PeerDiscovery')

class PeerDiscovery:
    def __init__(self, config):
        self.config = config['Network']  # Acessa a seção de rede
        self.peers = set()
        self.running = True
        
        # Extrai parâmetros com valores padrão
        self.broadcast_ip = self.config.get('broadcast_ip', '224.0.0.114')
        self.broadcast_port = int(self.config.get('broadcast_port', 5001))
        self.listen_port = int(self.config.get('listen_port', 5000))
        self.advertised_ip = self.config.get('advertised_ip', self.get_local_ip())
        
        # Carrega peers da configuração
        self.load_peers_from_config()
        
        logger.info(f"PeerDiscovery iniciado. IP: {self.advertised_ip}, Porta: {self.listen_port}")
        logger.info(f"Broadcast: {self.broadcast_ip}:{self.broadcast_port}")
    def send_message(self, peer, message, timeout=5.0):
        """Envia uma mensagem para um peer e retorna a resposta"""
        host, port = peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.sendall(message.encode())
                response = sock.recv(65536)
                return response.decode()
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem para {host}:{port}: {str(e)}")
            return None
    def load_peers_from_config(self):
        """Carrega peers do arquivo de configuração"""
        if 'peers' in self.config:  # Remova ['Network'] aqui
            peers_str = self.config['peers']
            for peer in peers_str.split(','):
                peer = peer.strip()
                if peer:
                    parts = peer.split(':')
                    if len(parts) == 2:
                        self.peers.add((parts[0], int(parts[1])))

        logger.info(f"Peers configurados: {len(self.peers)}")
    
    def get_local_ip(self):
        """Obtém o IP local automaticamente"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    def get_active_peers(self):
        """Retorna apenas peers ativos"""
        active_peers = []
        for peer in self.get_peers():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect(peer)
                    s.sendall(b"PING")
                    if s.recv(4) == b"PONG":
                        active_peers.append(peer)
            except:
                continue
        return active_peers
    def get_peers(self):
        """Retorna lista de peers incluindo a si mesmo (para testes)"""
        all_peers = list(self.peers)
        all_peers.append((self.advertised_ip, self.listen_port))  # Corrigido para listen_port
        return all_peers
    def get_active_peers_count(self):
        """Retorna o número de peers ativos (incluindo a si mesmo)"""
        return len(self.get_peers())
    def sync_blockchain(self, blockchain):
        """Sincroniza a blockchain com os peers"""
        for peer in self.peers:
            if peer == (self.config['advertised_ip'], self.config['listen_port']):
                continue
                
            try:
                # Obter altura local
                local_height = blockchain.height
                
                # Solicitar blocos desde a altura local + 1
                message = json.dumps({
                    "type": "SYNC_REQUEST",
                    "start_index": local_height + 1
                })
                
                response = self.send_message(peer, message)
                if not response:
                    continue
                    
                blocks = json.loads(response)
                if not blocks:
                    continue
                    
                logger.info(f"Recebidos {len(blocks)} blocos de {peer[0]}")
                
                # Adicionar blocos à blockchain
                for block in blocks:
                    # Validação básica antes de salvar
                    if 'index' in block and 'hash' in block:
                        blockchain.save_block(block)
                
                return True
            except Exception as e:
                logger.error(f"Erro ao sincronizar com {peer[0]}:{peer[1]} - {str(e)}")
        return False
    def sync_mempool(self, mempool):
        """Sincroniza o mempool com os peers"""
        logger.info("Iniciando sincronização de mempool...")
        
        for peer in self.get_peers():
            if peer == (self.advertised_ip, self.listen_port):
                continue
                
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5.0)
                    sock.connect(peer)
                    
                    # Envia solicitação de mempool
                    sock.sendall(json.dumps({"type": "MEMPOOL_REQUEST"}).encode())
                    
                    # Recebe o mempool
                    response = sock.recv(65536)
                    if response:
                        mempool_data = json.loads(response.decode())
                        
                        # CORREÇÃO: Verificar tipo de energy_data
                        energy_data = mempool_data.get('energy_data', {})
                        
                        # Se for lista, converter para dicionário
                        if isinstance(energy_data, list):
                            energy_dict = {item['id']: item for item in energy_data}
                        else:
                            energy_dict = energy_data
                        
                        # Adiciona registros de energia
                        for record_id, record in energy_dict.items():
                            mempool.add_energy_data(record)
                            
                        # Adiciona transações
                        for tx in mempool_data.get('transactions', []):
                            mempool.add_transaction(tx)
                            
                        logger.info(f"Mempool sincronizado com {peer[0]}")
            except Exception as e:
                logger.error(f"Erro ao sincronizar mempool com {peer[0]}:{peer[1]} - {str(e)}")