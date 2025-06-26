import socket
import threading
import json
import logging
import traceback
from datetime import datetime, timezone
import time
import hashlib
import random
from .vrf import VRFNode, elect_proposer
from collections import defaultdict 
logger = logging.getLogger('Gossip')

class GossipManager:
    def __init__(self, config, blockchain, mempool, discovery, wallet):
        self.config = config
        self.blockchain = blockchain
        self.mempool = mempool
        self.discovery = discovery
        self.wallet = wallet
        self.running = True
        self.listen_port = int(config['Network']['listen_port'])
        self.vrf_threshold = float(config['VRF']['difficulty'])
        self.vrf = VRFNode(wallet.private_key)
        self.sent_messages_cache = set()
        self.received_messages_cache = set()
        self.block_interval = 80  # 80 segundos para testes
        self.last_block_time = time.time()
        self.election_interval = 80  # Intervalo entre eleições (80 segundos)
        
        self.vrf_announcements = []
        self.current_proposer = None
        self.vrf_output = None
        self.vrf_proof = None
        self.last_election_time = 0

    def is_peer_active(self, peer):
        """Verifica se um peer está ativo com um ping rápido"""
        host, port = peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((host, port))
                sock.sendall(b"PING")
                response = sock.recv(4)
                return response == b"PONG"
        except:
            return False

    def _cache_cleaner_worker(self):
        """Limpa caches periodicamente"""
        while self.running:
            time.sleep(300)
            self.sent_messages_cache.clear()
            self.received_messages_cache.clear()
            logger.info("Caches de mensagens limpos")

    def start_server(self):
        threading.Thread(target=self.run_server, daemon=True).start()
        threading.Thread(target=self._election_worker, daemon=True).start()
        threading.Thread(target=self._cache_cleaner_worker, daemon=True).start()
    
    def _election_worker(self):
        """Worker que realiza eleições periódicas"""
        while self.running:
            try:
                # Executa eleição a cada 80 segundos
                self._run_election()
                self.last_election_time = time.time()
                time.sleep(self.election_interval)
                
            except Exception as e:
                logger.error(f"Erro no worker de eleição: {str(e)}", exc_info=True)
                time.sleep(10)
    
    def _run_election(self):
        """Executa o processo de eleição com modo solo automático"""
        logger.info("Iniciando nova eleição...")
        
        # Resetar anúncios
        self.vrf_announcements = []
        
        # Obtém o seed (hash do último bloco)
        last_block = self.blockchain.get_last_block()
        seed = last_block['hash'] if last_block else "genesis_seed"
        
        # Calcula o VRF local
        self.vrf_output, self.vrf_proof = self.vrf.compute_vrf(seed)
        if not self.vrf_output:
            logger.error("Falha ao calcular VRF, pulando eleição")
            return
        
        # Adiciona próprio anúncio
        self.vrf_announcements.append({
            "public_key": self.wallet.public_key,
            "vrf_output": self.vrf_output,
            "vrf_proof": self.vrf_proof,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Verifica peers ativos (excluindo a si mesmo)
        active_peers = [
            p for p in self.discovery.get_peers() 
            if p != (self.config['Network']['advertised_ip'], self.listen_port)
        ]
        
        if active_peers:
            # Propagar anúncio se houver peers
            self.propagate_vrf_announcement(self.vrf_output, self.vrf_proof)
            logger.info("Esperando 10 segundos para coletar anúncios VRF...")
            time.sleep(10)
        else:
            logger.info("Modo solo: sem peers ativos")

        # Prepara os dados para a eleição
        nodes_data = []
        for ann in self.vrf_announcements:
            nodes_data.append((ann['public_key'], ann['vrf_output'], ann['vrf_proof']))
        
        # Usa o índice do bloco como "day_index"
        block_index = self.blockchain.height + 1
        
        # Eleição
        elected_public_key = elect_proposer(
            nodes_data,
            seed,
            self.vrf_threshold,
            block_index
        )
        
        if not elected_public_key:
            logger.warning("Nenhum candidato válido, usando chave local")
            elected_public_key = self.wallet.public_key
            
        self.current_proposer = elected_public_key
        logger.info(f"Propositor eleito: {elected_public_key[:10]}...")
        
        # Se este nó for o eleito, inicia a preparação do bloco
        if elected_public_key == self.wallet.public_key:
            self._prepare_block()
    
    def propagate_vrf_announcement(self, output, proof):
        """Propaga o anúncio VRF para a rede."""
        message = {
            "type": "VRF_ANNOUNCE",
            "public_key": self.wallet.public_key,
            "vrf_output": output,
            "vrf_proof": proof,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.propagate(message)
    
    def _prepare_block(self):
        logger.info("Este nó foi eleito, preparando novo bloco...")

        # 1. Obter registros de energia
        last_block = self.blockchain.get_last_block()
        if not last_block:
            logger.error("Não foi possível obter o último bloco")
            return

        # Converter para UTC naive
        last_block_time = datetime.fromisoformat(
            last_block['timestamp'].replace('Z', '+00:00')
        ).replace(tzinfo=None)

        energy_records = []
        for record in self.mempool.energy_data.values():
            try:
                # Converter registro para UTC naive
                record_time = datetime.fromisoformat(
                    record['timestamp'].replace('Z', '+00:00')
                ).replace(tzinfo=None)
                
                if record_time > last_block_time:
                    energy_records.append(record)
            except Exception as e:
                logger.error(f"Erro ao processar timestamp: {str(e)}")

        # 2. Criar UTXOs de recompensa
        reward_transaction = self.create_reward_transaction(energy_records)

        # 3. Obter transações normais do mempool
        transactions = self.mempool.get_pending_transactions()

        # 4. Adicionar recompensa se válida
        if reward_transaction:
            transactions.insert(0, reward_transaction)
        else:
            logger.warning("Nenhuma transação de recompensa criada")

        # 5. Criar novo bloco se houver transações
        if transactions:
            new_block = self.blockchain.create_block(
                transactions=transactions,
                proposer=self.wallet.public_key
            )

            # 6. Assinar e propagar o bloco
            new_block['hash'] = self.blockchain.calculate_block_hash(new_block)
            new_block['signature'] = self.wallet.sign_block(new_block)
            
            if self.blockchain.save_block(new_block):
                logger.info(f"Novo bloco salvo: #{new_block['index']}")
                
                # LIMPEZA LOCAL PARA O NÓ PROPOSITOR
                self.mempool.clear_processed_data(new_block)
                
                # Propagação
                self.propagate({
                    "type": "NEW_BLOCK",
                    "block": new_block,
                    "vrf_output": self.vrf_output,
                    "vrf_proof": self.vrf_proof
                })
            else:
                logger.error("Falha ao salvar novo bloco")
        else:
            logger.warning("Nenhuma transação para incluir no bloco, pulando criação")

        # 8. Limpar dados processados
        self.vrf_announcements = []
    
    def create_reward_transaction(self, energy_records):
        if not energy_records:
            logger.warning("Nenhum registro de energia para recompensar")
            return None

        # Agrupar produção por endereço com soma determinística
        production_sum = defaultdict(float)
        record_ids = []  # Lista para armazenar IDs dos registros

        for record in energy_records:
            address = record['producer']
            production_sum[address] += record['total_kwh']
            record_ids.append(record['id'])  # Coleta IDs

        # Criar outputs UTXO (1 token = 100 kWh)
        outputs = []
        for address, kwh in sorted(production_sum.items()):
            tokens = kwh / 100.0
            if tokens > 0:
                outputs.append({
                    "address": address,
                    "amount": round(tokens, 6)
                })

        if not outputs:
            logger.error("Nenhum output válido para recompensa")
            return None

        # ID determinístico baseado nos outputs
        output_hash = hashlib.sha256(
            json.dumps(outputs, sort_keys=True).encode()
        ).hexdigest()

        unique_seed = f"reward_{output_hash}_{datetime.utcnow().isoformat()}"
        tx_id = hashlib.sha256(unique_seed.encode()).hexdigest()

        # Criar transação de recompensa COM os IDs dos registros
        tx = {
            "id": tx_id,
            "proposer": self.wallet.public_key,
            "inputs": [],
            "outputs": outputs,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "energy_record_ids": record_ids  # Adiciona IDs dos registros aqui
        }

        tx['signature'] = self.wallet.sign_transaction(tx)
        return tx
        
    def run_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', self.listen_port))
            sock.listen(5)
            logger.info(f"Servidor TCP iniciado na porta {self.listen_port}")
            
            while self.running:
                try:
                    client, addr = sock.accept()
                    threading.Thread(target=self.handle_client, args=(client, addr)).start()
                except Exception as e:
                    logger.error(f"Erro na conexão: {str(e)}")
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(65536)
            if not data:
                return
                
            # Verificar se é um PING
            if data == b"PING":
                client.sendall(b"PONG")
                return
                
            # Gerar ID único da mensagem
            msg_id = hashlib.sha256(data).hexdigest()
            
            # Se já processou esta mensagem, ignore
            if msg_id in self.received_messages_cache:
                logger.debug(f"Mensagem duplicada de {addr}, ignorando")
                return
                
            self.received_messages_cache.add(msg_id)
            
            message = json.loads(data.decode())
            logger.info(f"Recebido de {addr}: {message['type']}")
            
            # --- TIPOS DE MENSAGEM PARA SINCRONIZAÇÃO ---
            if message["type"] == "SYNC_REQUEST":
                start_index = message["start_index"]
                blocks = self.blockchain.get_blocks_since(start_index)
                client.sendall(json.dumps(blocks).encode())
                return
                
            elif message["type"] == "MEMPOOL_REQUEST":
                mempool_data = {
                    "energy_data": list(self.mempool.energy_data.values()),
                    "transactions": self.mempool.get_pending_transactions()
                }
                client.sendall(json.dumps(mempool_data).encode())
                return
            # --- FIM SINCRONIZAÇÃO ---
                
            elif message["type"] == "MINUTE_PROD":
                # Verificar assinatura
                if not self.verify_signature(message):
                    client.sendall(b"INVALID_SIGNATURE")
                    return
                
                # Extrair dados
                try:
                    energy_record = {
                        "producer": message["public_address"],
                        "timestamp": message["timestamp"],
                        "total_kwh": message["total_kwh"],
                        "date": datetime.fromisoformat(message["timestamp"]).strftime("%Y-%m-%d"),
                        "id": hashlib.sha256(f"{message['public_address']}{message['timestamp']}".encode()).hexdigest()
                    }
                    
                    self.mempool.add_energy_data(energy_record)
                    client.sendall(b"ACK")
                    logger.info(f"Dados de produção adicionados: {message['total_kwh']}kWh de {message['public_address'][:10]}...")
                    
                    # PROPAGAÇÃO PARA OUTROS NÓS
                    self.propagate(message, exclude=[addr])
                    
                except KeyError as e:
                    logger.error(f"Campo faltando na mensagem: {str(e)}")
                    client.sendall(b"INVALID_FORMAT")
            
            elif message["type"] == "NEW_BLOCK":
                if self._validate_new_block(message):
                    block = message["block"]
                    
                    if self.blockchain.save_block(block):
                        client.sendall(b"ACCEPTED")
                        
                        # LIMPEZA PARA NÓS QUE RECEBEM O BLOCO
                        self.mempool.clear_processed_data(block)
                        
                        self.propagate(message, exclude=[addr])
                    else:
                        client.sendall(b"REJECTED")
                else:
                    client.sendall(b"REJECTED")
            
            elif message["type"] == "VRF_ANNOUNCE":
                # Armazena o anúncio VRF
                self.vrf_announcements.append({
                    "public_key": message["public_key"],
                    "vrf_output": message["vrf_output"],
                    "vrf_proof": message["vrf_proof"],
                    "timestamp": message["timestamp"]
                })
                client.sendall(b"ACK_VRF")
            
            else:
                client.sendall(b"UNKNOWN_TYPE")
                
        except json.JSONDecodeError:
            logger.error(f"Mensagem inválida de {addr}")
            client.sendall(b"INVALID_JSON")
        except Exception as e:
            logger.error(f"Erro no cliente {addr}: {str(e)}\n{traceback.format_exc()}")
        finally:
            client.close()

    def _validate_new_block(self, message):
        """Valida um novo bloco recebido."""
        try:
            block = message["block"]
            
            # 1. Verificar assinatura do bloco
            if not self.wallet.verify_block(block):
                logger.error("Assinatura do bloco inválida")
                return False
                
            # 2. Verificar o VRF do propositor
            last_block = self.blockchain.get_last_block()
            seed = last_block['hash'] if last_block else "genesis_seed"
            
            logger.info(f"Validando VRF para bloco #{block['index']}")
            logger.info(f"Propositor: {block['proposer'][:10]}...")
            logger.info(f"Seed: {seed[:16]}...")
            logger.info(f"VRF Output: {message['vrf_output'][:16]}...")
            logger.info(f"VRF Proof: {message['vrf_proof'][:16]}...")
            
            if not VRFNode.verify_vrf(
                block['proposer'],
                seed,
                message['vrf_output'],
                message['vrf_proof']
            ):
                logger.error("Prova VRF inválida")
                return False
                
            # 3. Verificar se o output VRF está abaixo do threshold
            try:
                # CORREÇÃO: Usar apenas 8 bytes (16 caracteres hex)
                output_bytes = bytes.fromhex(message['vrf_output'][:16])
                output_int = int.from_bytes(output_bytes, 'big')
                max_value = 0xFFFF_FFFF_FFFF_FFFF  # 8 bytes (64 bits)
                normalized = output_int / max_value
                logger.info(f"VRF Normalizado: {normalized} (Threshold: {self.vrf_threshold})")
                
                if normalized >= self.vrf_threshold:
                    logger.error(f"Output VRF acima do threshold: {normalized} >= {self.vrf_threshold}")
                    return False
            except Exception as e:
                logger.error(f"Erro ao normalizar VRF output: {str(e)}", exc_info=True)
                return False
                
            # 4. Validar o bloco com a blockchain
            if not self.blockchain.validate_block(block):
                logger.error("Bloco inválido pela blockchain")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Erro na validação do bloco: {str(e)}", exc_info=True)
            return False

    def verify_signature(self, message):
        """Verifica a assinatura da mensagem (implementação simplificada)"""
        try:
            # Em uma implementação real, você validaria a assinatura
            # usando a chave pública do remetente
            if "signature" not in message:
                logger.warning("Mensagem sem assinatura")
                return False
            
            # Aqui você implementaria a verificação real
            # return self.wallet.verify_message(...)
            return True  # Temporariamente aceita todas as assinaturas
            
        except Exception as e:
            logger.error(f"Erro na verificação de assinatura: {str(e)}")
            return False
    
    def propagate(self, message, exclude=[]):
        """Propaga mensagem para todos os peers ativos"""
        msg_id = hashlib.sha256(json.dumps(message).encode()).hexdigest()
        if msg_id in self.sent_messages_cache:
            return

        self.sent_messages_cache.add(msg_id)
        
        for peer in self.discovery.get_peers():
            if peer not in exclude and peer != (self.config['Network']['advertised_ip'], self.listen_port):
                # Verificar se o peer está ativo antes de enviar
                if self.is_peer_active(peer):
                    self.send_message(peer, message)
    
    def send_message(self, peer, message):
        host, port = peer
        max_retries = 2  # Máximo de 2 tentativas

        for attempt in range(max_retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5.0)
                    sock.connect((host, port))
                    sock.sendall(json.dumps(message).encode())

                    response = sock.recv(1024).decode()
                    logger.debug(f"Resposta de {host}:{port}: {response}")
                    return True  # Sucesso, não precisa retentar

            except socket.timeout:
                logger.warning(f"Timeout ao enviar para {host}:{port} (tentativa {attempt+1}/{max_retries})")
            except ConnectionRefusedError:
                logger.warning(f"Conexão recusada por {host}:{port} (tentativa {attempt+1}/{max_retries})")
                time.sleep(1)  # Espera antes de retentar
            except Exception as e:
                logger.error(f"Erro ao enviar para {host}:{port}: {str(e)}")

        logger.error(f"Falha ao enviar para {host}:{port} após {max_retries} tentativas")
        return False