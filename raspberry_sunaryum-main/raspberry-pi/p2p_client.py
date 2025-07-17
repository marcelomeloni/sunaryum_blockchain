import socket
import json
import logging

logger = logging.getLogger('P2PClient')

class P2PClient:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def send_message(self, peer, message):
        host, port = peer
        try:
            with socket.create_connection((host, port), self.timeout) as sock:
                # Envia a mensagem
                sock.sendall(json.dumps(message).encode('utf-8'))
                
                # Configura timeout para resposta
                sock.settimeout(5.0)
                
                # Aguarda confirmação
                response = sock.recv(1024).decode()
                logger.debug(f"Resposta de {host}:{port}: {response}")
                return response
                    
        except socket.timeout:
            logger.warning(f"Timeout ao aguardar resposta de {host}:{port}")
            return "TIMEOUT"
        except ConnectionRefusedError:
            logger.error(f"Conexão recusada por {host}:{port}")
            return "CONNECTION_REFUSED"
        except Exception as e:
            logger.error(f"Erro ao conectar com {host}:{port}: {str(e)}")
            return "ERROR"