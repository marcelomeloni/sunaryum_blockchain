import socket
import threading
import time
import logging
import json

logger = logging.getLogger('PeerDiscovery')

class PeerDiscovery:
    def __init__(self, config):
        self.config = config
        self.peers = set()
        self.running = True
        
        # Parâmetros de rede
        self.broadcast_ip = config.get_network_setting('broadcast_ip', '224.0.0.114')
        self.broadcast_port = config.get_network_setting('broadcast_port', 5001, int)
        self.listen_port = config.get_network_setting('listen_port', 5000, int)
        self.advertised_ip = config.get_network_setting('advertised_ip', None)
        
        # Configurar socket multicast
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(5)
        
        # Carrega peers estáticos da configuração
        self.load_static_peers()
        
        logger.info(f"PeerDiscovery iniciado. Porta: {self.listen_port}")
        logger.info(f"Broadcast: {self.broadcast_ip}:{self.broadcast_port}")
    
    def load_static_peers(self):
        """Carrega peers estáticos do arquivo de configuração"""
        peers_str = self.config.get_network_setting('peers', '')
        if peers_str:
            for peer in peers_str.split(','):
                peer = peer.strip()
                if peer:
                    parts = peer.split(':')
                    if len(parts) == 2:
                        ip = parts[0].strip()
                        port = int(parts[1].strip())
                        self.peers.add((ip, port))
                        logger.info(f"Peer estático adicionado: {ip}:{port}")
    
    def start(self):
        threading.Thread(target=self.listen, daemon=True).start()
        threading.Thread(target=self.advertise, daemon=True).start()
        threading.Thread(target=self.discover, daemon=True).start()
    
    def listen(self):
        """Escuta por anúncios de peers"""
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.bind(('0.0.0.0', self.broadcast_port))
        
        try:
            mreq = socket.inet_aton(self.broadcast_ip) + socket.inet_aton('0.0.0.0')
            listen_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception as e:
            logger.error(f"Erro ao entrar no grupo multicast: {str(e)}")
        
        while self.running:
            try:
                data, addr = listen_sock.recvfrom(1024)
                message = json.loads(data.decode())
                
                if message['type'] == 'PEER_ADVERT':
                    ip = message['ip']
                    port = message['port']
                    peer = (ip, port)
                    
                    if peer not in self.peers:
                        self.peers.add(peer)
                        logger.info(f"Novo peer descoberto: {ip}:{port}")
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Erro na descoberta de peers: {str(e)}")
    
    def advertise(self):
        """Anuncia a própria presença na rede"""
        while self.running:
            try:
                if self.advertised_ip:
                    message = json.dumps({
                        'type': 'PEER_ADVERT',
                        'ip': self.advertised_ip,
                        'port': self.listen_port
                    })
                    self.sock.sendto(
                        message.encode(), 
                        (self.broadcast_ip, self.broadcast_port)
                    )
            except Exception as e:
                logger.error(f"Erro ao anunciar peer: {str(e)}")
            
            time.sleep(30)
    
    def discover(self):
        """Busca ativamente por peers na rede"""
        while self.running:
            try:
                # Envia solicitação de descoberta
                message = json.dumps({'type': 'PEER_DISCOVERY'})
                self.sock.sendto(
                    message.encode(), 
                    (self.broadcast_ip, self.broadcast_port)
                )
            except Exception as e:
                logger.error(f"Erro na busca por peers: {str(e)}")
            
            time.sleep(60)
    
    def get_peers(self):
        return list(self.peers)