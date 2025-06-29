import threading
import time
import logging
import socket
import json

logger = logging.getLogger('PeerDiscovery')

class PeerDiscovery:
    def __init__(self, config):
        self.config = config['Network']
        self.peers = set()
        self.running = True
        
        self.broadcast_ip = self.config.get('broadcast_ip', '224.0.0.114')
        self.broadcast_port = int(self.config.get('broadcast_port', 5001))
        self.listen_port = int(self.config.get('listen_port', 5000))
        self.advertised_ip = self.config.get('advertised_ip', self.get_local_ip())
        
        self.load_peers_from_config()
        logger.info(f"PeerDiscovery iniciado. IP: {self.advertised_ip}, Porta: {self.listen_port}")
        logger.info(f"Peers: {self.peers}")

    def send_message(self, peer, message, timeout=2.0):
        """Envia mensagem para peer via TCP com tratamento robusto"""
        host, port = peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                
                # Enviar mensagem como bytes
                if isinstance(message, str):
                    message = message.encode()
                sock.sendall(message)
                
                # Receber resposta (não tenta interpretar como JSON)
                response = sock.recv(1024)
                return response.decode('utf-8', errors='ignore') if response else None
                
        except socket.timeout:
            logger.debug(f"Timeout ao comunicar com {host}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"Conexão recusada por {host}:{port}")
        except Exception as e:
            logger.error(f"Erro ao enviar para {host}:{port}: {str(e)}")
        return None

    def load_peers_from_config(self):
        """Carrega peers do arquivo de configuração"""
        if 'peers' in self.config:
            peers_str = self.config['peers']
            for peer in peers_str.split(','):
                peer = peer.strip()
                if peer:
                    parts = peer.split(':')
                    if len(parts) == 2:
                        try:
                            # Garantir conversão correta para int
                            self.peers.add((parts[0], int(parts[1])))
                        except ValueError:
                            logger.error(f"Porta inválida: {parts[1]}")
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

    # Em PeerDiscovery.py
    def get_active_peers(self, exclude_self=False):
        """Retorna peers ativos, opcionalmente excluindo o próprio nó"""
        active_peers = []
        self_peer = (self.advertised_ip, self.listen_port)

        for peer in self.get_peers():
            host, port = peer
            if exclude_self and peer == self_peer:
                continue
            
            logger.debug(f"Verificando peer ativo: {host}:{port}")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect((host, port))

                    # Enviar PING como string simples
                    s.sendall(b"PING")

                    # Receber resposta (aceita múltiplos formatos)
                    response = s.recv(1024)

                    # Aceitar QUALQUER resposta que contenha "PONG"
                    if response and b"PONG" in response:
                        logger.debug(f"Peer {host}:{port} ativo")
                        active_peers.append(peer)
                    else:
                        logger.debug(f"Resposta inválida de {host}:{port}")

            except Exception as e:
                logger.debug(f"Peer inativo {host}:{port}: {str(e)}")

        # Adicionar fallback para peers configurados
        if not active_peers:
            logger.warning("Nenhum peer ativo, usando lista configurada")
            return list(self.get_peers())

        return active_peers

    def get_peers(self):
        """Retorna lista de peers EXCLUINDO a si mesmo"""
        return list(self.peers)

    def get_active_peers_count(self):
        return len(self.get_active_peers())

    def sync_blockchain(self, blockchain):
        """Sincroniza a blockchain com os peers"""
        for peer in self.get_peers():
            try:
                local_height = blockchain.height
                message = json.dumps({
                    "type": "SYNC_REQUEST",
                    "start_index": local_height + 1
                })
                
                response = self.send_message(peer, message)
                if not response:
                    continue
                    
                try:
                    blocks = json.loads(response)
                except json.JSONDecodeError:
                    logger.warning(f"Resposta inválida de {peer}: {response[:100] if response else 'Sem resposta'}...")
                    continue
                    
                if blocks and isinstance(blocks, list):
                    logger.info(f"Recebidos {len(blocks)} blocos de {peer[0]}")
                    for block in blocks:
                        if 'index' in block and 'hash' in block:
                            blockchain.save_block(block)
                    return True
            except Exception as e:
                logger.error(f"Erro sinc blockchain com {peer}: {str(e)}")
        return False

    def sync_mempool(self, mempool):
        """Sincroniza o mempool com os peers"""
        logger.info("Iniciando sincronização de mempool...")
        
        for peer in self.get_peers():
            try:
                response = self.send_message(peer, json.dumps({"type": "MEMPOOL_REQUEST"}))
                if not response:
                    continue
                    
                try:
                    mempool_data = json.loads(response)
                    energy_data = mempool_data.get('energy_data', {})
                    
                    if isinstance(energy_data, list):
                        for record in energy_data:
                            mempool.add_energy_data(record)
                    else:  # Formato dicionário
                        for record_id, record in energy_data.items():
                            mempool.add_energy_data(record)
                        
                    for tx in mempool_data.get('transactions', []):
                        mempool.add_transaction(tx)
                        
                    logger.info(f"Mempool sincronizado com {peer[0]}")
                except json.JSONDecodeError:
                    logger.warning(f"Resposta inválida de {peer}: {response[:100] if response else 'Sem resposta'}...")
                    
            except Exception as e:
                logger.error(f"Erro sinc mempool com {peer}: {str(e)}")