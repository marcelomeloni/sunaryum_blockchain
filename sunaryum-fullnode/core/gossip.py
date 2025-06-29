import socket
import threading
import json
import logging
import traceback
from datetime import datetime, time as dt_time, timezone, timedelta
import time
import hashlib
import random
from .vrf import VRFNode, elect_proposer
from collections import defaultdict

logger = logging.getLogger('Gossip')

# Configurações de recompensa
NODE_REWARD_PERCENTAGE = 0.05
MIN_NODE_REWARD = 0.001

class GossipManager:
    def __init__(self, config, blockchain, mempool, discovery, wallet, vrf=None):
        self.config = config
        self.blockchain = blockchain
        self.mempool = mempool
        self.discovery = discovery
        self.wallet = wallet
        self.running = True
        
        # Configurações de rede
        self.listen_port = int(config['Network']['listen_port'])
        self.vrf_threshold = float(config['VRF']['difficulty'])
        # Usar instância VRF passada ou criar nova
        self.vrf = vrf if vrf else VRFNode(wallet.private_key)
        
        # Controle de mensagens
        self.sent_messages_cache = set()
        self.received_messages_cache = set()
   
        threading.Thread(target=self._cache_cleaner_worker, daemon=True).start()
        self.election_lock = threading.Lock()
        self.pending_energy_data = []
        # Estado do sistema
        self.last_election_date = None
        self.election_in_progress = False
        self.vrf_announcements = []
        self.current_proposer = None
        self.last_election_attempt = 0
        self.pending_transactions = []
        
        # Configurações de recompensa
        self.node_reward_percentage = float(config.get('Rewards', 'node_percentage', fallback=NODE_REWARD_PERCENTAGE))
        self.min_node_reward = float(config.get('Rewards', 'min_node_reward', fallback=MIN_NODE_REWARD))
        
        # Horários UTC para operação diária
        self.ENERGY_COLLECTION_START = dt_time(19, 46, tzinfo=timezone.utc)
        self.ENERGY_COLLECTION_END = dt_time(21, 40, tzinfo=timezone.utc)
        self.ELECTION_TIME = dt_time(21, 40, tzinfo=timezone.utc)
        
        # Iniciar workers
        threading.Thread(target=self._election_worker, daemon=True).start()
        threading.Thread(target=self._cache_cleaner_worker, daemon=True).start()
        threading.Thread(target=self._daily_cycle_worker, daemon=True).start()
        threading.Thread(target=self.start_server, daemon=True).start()

    def _daily_cycle_worker(self):
        while self.running:
            try:
                now_utc = datetime.now(timezone.utc)
                today = now_utc.date()

                # Não verificar eleição se já foi feita hoje
                if self.last_election_date == today:
                    time.sleep(60)  # Verificar a cada minuto
                    continue

                # Criar objetos datetime completos
                election_datetime = datetime.combine(
                    today,
                    self.ELECTION_TIME,
                    tzinfo=timezone.utc
                )

                # Janela de 5 minutos para a eleição
                if (election_datetime <= now_utc < election_datetime + timedelta(minutes=5) and \
                   not self.election_in_progress and \
                   time.time() - self.last_election_attempt > 300):

                    logger.info("Iniciando processo diário de eleição")
                    self.last_election_attempt = time.time()
                    self.election_in_progress = True
                    self.last_election_date = today  # Marcar data
                    self.start_election_process()

                time.sleep(5)
            except Exception as e:  # ADICIONE ESTA CLÁUSULA EXCEPT
                logger.error(f"Erro no worker de ciclo: {e}")
                time.sleep(10)

    def initiate_global_sync(self):
        """Sincronização global da mempool antes da eleição"""
        active_peers = self.discovery.get_active_peers()
        if not active_peers:
            return

        logger.info(f"Sincronizando mempool com {len(active_peers)} peers")
        
        threads = []
        for peer in active_peers:
            t = threading.Thread(target=self.sync_mempool_with_peer, args=(peer,))
            t.start()
            threads.append(t)
        
        # Timeout de 15 segundos para sincronização
        start_time = time.time()
        for t in threads:
            t.join(timeout=15)
            if time.time() - start_time > 15:
                break

    def sync_mempool_with_peer(self, peer):
            """Sincroniza mempool com um peer específico com tratamento robusto"""
            host, port = peer
            peer_str = f"{host}:{port}"

            try:
                logger.debug(f"Solicitando mempool de {peer_str}")

                # Enviar solicitação
                response = self._send_direct_message(peer, json.dumps({"type": "MEMPOOL_REQUEST"}))

                if not response:
                    logger.error(f"Resposta vazia de {peer_str}")
                    return

                # Tentar parsear como JSON
                try:
                    mempool_data = json.loads(response)
                except json.JSONDecodeError as e:
                    # Tentar interpretar mensagens de erro comuns
                    if "ACK" in response or "PONG" in response:
                        logger.debug(f"Peer {peer_str} respondeu mas sem dados: {response}")
                        return
                    elif "ERROR" in response:
                        logger.error(f"Peer {peer_str} retornou erro: {response}")
                        return
                    else:
                        logger.error(f"Resposta inválida de {peer_str}: {response[:100]}")
                        return

                # Sincronizar dados de energia
                added_energy = 0
                for record in mempool_data.get('energy_data', []):
                    try:
                        # Gerar ID se não existir
                        record_id = record.get('id') or hashlib.sha256(
                            f"{record['producer']}{record['timestamp']}".encode()
                        ).hexdigest()

                        if not self.mempool.energy_data_exists(record_id):
                            self.mempool.add_energy_data(record)
                            added_energy += 1
                    except KeyError as e:
                        logger.warning(f"Registro de energia inválido de {peer_str}: campo faltando {e}")
                    except Exception as e:
                        logger.error(f"Erro ao adicionar registro de {peer_str}: {str(e)}")

                # Sincronizar transações
                added_txs = 0
                for tx in mempool_data.get('transactions', []):
                    try:
                        tx_id = tx.get('id')
                        if not tx_id:
                            logger.warning(f"Transação sem ID de {peer_str}")
                            continue

                        if not self.mempool.transaction_exists(tx_id):
                            self.mempool.add_transaction(tx)
                            added_txs += 1
                    except KeyError as e:
                        logger.warning(f"Transação inválida de {peer_str}: campo faltando {e}")
                    except Exception as e:
                        logger.error(f"Erro ao adicionar transação de {peer_str}: {str(e)}")

                logger.info(f"Mempool sincronizada com {peer_str}: "
                           f"{added_energy} registros de energia, {added_txs} transações adicionadas")

            except Exception as e:
                logger.error(f"Erro crítico na sincronização com {peer_str}: {str(e)}")
                logger.debug(traceback.format_exc())
    def _send_direct_message(self, peer, message):
        """Envia mensagem diretamente sem usar cache"""
        host, port = peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((host, port))
                sock.sendall(message.encode())
                return sock.recv(65536).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Erro ao enviar mensagem para {host}:{port}: {e}")
            return None

    def should_accept_energy_data(self):
        """Verifica se está no horário permitido para coleta de dados de energia"""
        now_utc = datetime.now(timezone.utc).time()
        return self.ENERGY_COLLECTION_START <= now_utc < self.ENERGY_COLLECTION_END

    def start_election_process(self):
        """Inicia o processo de eleição se necessário"""
        if not self.election_lock.locked():
            threading.Thread(target=self._run_election).start()

    def _election_worker(self):
        """Monitora o estado da eleição"""
        while self.running:
            time.sleep(5)

    def _run_election(self):
        if not self.election_lock.acquire(blocking=False):
            logger.debug("Eleição já em andamento")
            return

        try:
            logger.info("🚀 Iniciando nova eleição diária...")
            start_time = time.time()

            # Resetar anúncios
            self.vrf_announcements = []
            active_peers = self.discovery.get_active_peers(exclude_self=True)
            logger.info(f"Peers ativos para eleição: {len(active_peers)}")

            # Obter seed (hash do último bloco)
            last_block = self.blockchain.get_last_block()
            if not last_block:
                logger.error("Não foi possível obter o último bloco para seed VRF")
                return

            seed = last_block['hash']
            logger.debug(f"Usando seed VRF: {seed[:16]}...")

            # Calcular VRF local com verificação robusta
            vrf_output, vrf_proof = self.vrf.compute_vrf(seed)
            if not vrf_output or not vrf_proof or len(vrf_output) < 10 or len(vrf_proof) < 10:
                logger.error("Falha crítica ao calcular VRF. Abortando eleição.")
                return

            # Adicionar próprio anúncio
            self.vrf_announcements.append({
                "public_key": self.wallet.public_key,
                "vrf_output": vrf_output,
                "vrf_proof": vrf_proof,
                "timestamp": datetime.utcnow().isoformat()
            })

            # Propagar anúncio se houver peers
            if active_peers:
                self.propagate({
                    "type": "VRF_ANNOUNCE",
                    "public_key": self.wallet.public_key,
                    "vrf_output": vrf_output,
                    "vrf_proof": vrf_proof,
                    "timestamp": datetime.utcnow().isoformat(),
                    "ttl": 5  # Adicionar TTL inicial
                })

                # Coletar anúncios por tempo limitado
                logger.info("Coletando anúncios VRF por 15s...")
                time.sleep(15)

            # Filtrar anúncios únicos por public_key
            unique_announcements = {}
            for ann in self.vrf_announcements:
                pk = ann['public_key']
                if pk not in unique_announcements or ann['timestamp'] > unique_announcements[pk]['timestamp']:
                    unique_announcements[pk] = ann

            # Filtrar anúncios VRF válidos
            valid_announcements = []
            for ann in unique_announcements.values():
                # Verificação adicional de conteúdo
                if (len(ann['vrf_output']) >= 64 and len(ann['vrf_proof']) >= 140 and
                    VRFNode.verify_vrf(ann['public_key'], seed, ann['vrf_output'], ann['vrf_proof'])):
                    valid_announcements.append(ann)

            logger.info(f"{len(valid_announcements)} anúncios VRF válidos coletados")
            self.vrf_announcements = valid_announcements

            # Preparar dados para eleição
            nodes_data = [(ann['public_key'], ann['vrf_output'], ann['vrf_proof']) 
                         for ann in self.vrf_announcements]

            # Eleger propositor
            block_index = self.blockchain.get_block_height() + 1
            elected_public_key = elect_proposer(
                nodes_data,
                seed,
                self.vrf_threshold,
                block_index
            ) if nodes_data else self.wallet.public_key

            self.current_proposer = elected_public_key
            logger.info(f"✅ Propositor eleito: {elected_public_key[:10]}...")

            # Preparar bloco se este nó for eleito
            if elected_public_key == self.wallet.public_key:
                # Salvar VRF para uso posterior
                self.vrf_output = vrf_output
                self.vrf_proof = vrf_proof
                self._prepare_block()

            logger.info(f"Eleição concluída em {time.time()-start_time:.2f}s")
        except Exception as e:
            logger.error(f"Erro crítico na eleição: {e}\n{traceback.format_exc()}")
        finally:
            self.election_in_progress = False
            self.election_lock.release()
            self.reprocess_pending_data()
    
    def propagate_vrf_announcement(self):
        """Propaga o anúncio VRF para a rede"""
        message = {
            "type": "VRF_ANNOUNCE",
            "public_key": self.wallet.public_key,
            "vrf_output": self.vrf_output,  # Use self.vrf_output
            "vrf_proof": self.vrf_proof,    # Use self.vrf_proof
            "timestamp": datetime.utcnow().isoformat()
        }
        self.propagate(message)
    
    def _prepare_block(self):
        """Prepara e propaga novo bloco diário"""
        logger.info("Preparando novo bloco diário...")
    
        # Obter registros de energia
        energy_records = list(self.mempool.energy_data.values())
        transactions = []
    
        # Criar transação de recompensa
        if energy_records:
            if reward_tx := self.create_reward_transaction(energy_records):
                transactions.append(reward_tx)
    
        # Adicionar transações regulares
        transactions.extend(self.mempool.get_pending_transactions())
    
        # Criar novo bloco
        new_block = self.blockchain.create_block(
            transactions=transactions,
            proposer=self.wallet.public_key
        )
    
        # Assinar e salvar bloco
        new_block['hash'] = self.blockchain.calculate_block_hash(new_block)
        new_block['signature'] = self.wallet.sign_block(new_block)
    
        if self.blockchain.save_block(new_block):
            logger.info(f"Bloco #{new_block['index']} criado com {len(transactions)} transações")
            
            # Propagação do bloco com VRF
            self.propagate({
                "type": "NEW_BLOCK",
                "block": new_block,
                "vrf_output": self.vrf_output,
                "vrf_proof": self.vrf_proof
            })
            
            # Limpar dados processados
            self.mempool.clear_processed_data(new_block)
        else:
            logger.error("Falha ao salvar bloco")
            
    def create_reward_transaction(self, energy_records):
        # 1. Calcular produção total
        production_sum = defaultdict(float)
        record_ids = []
        total_kwh = 0.0
    
        for record in energy_records:
            address = record['producer']
            kwh = record['total_kwh']
            production_sum[address] += kwh
            total_kwh += kwh
            record_ids.append(record['id'])
    
        # 2. Calcular tokens totais (1 token = 100 kWh)
        total_tokens = total_kwh / 100.0
        node_reward_pool = total_tokens * self.node_reward_percentage
        producer_tokens = total_tokens - node_reward_pool
        
        # 3. Calcular tokens por produtor
        producer_outputs = []
        for address, kwh in production_sum.items():
            share = kwh / total_kwh
            tokens = producer_tokens * share
            if tokens > 0:
                producer_outputs.append({
                    "address": address,
                    "amount": round(tokens, 6)
                })
    
        # 4. Calcular recompensa por nó
        active_nodes = {ann['public_key'] for ann in self.vrf_announcements}
        node_outputs = []
        
        if active_nodes:
            reward_per_node = node_reward_pool / len(active_nodes)
            if reward_per_node >= self.min_node_reward:
                for node_address in active_nodes:
                    node_outputs.append({
                        "address": node_address,
                        "amount": round(reward_per_node, 6)
                    })
            else:
                # Redistribuir para produtores
                for output in producer_outputs:
                    share = output['amount'] / producer_tokens
                    output['amount'] += round(share * node_reward_pool, 6)
        else:
            # Redistribuir para produtores
            for output in producer_outputs:
                share = output['amount'] / producer_tokens
                output['amount'] += round(share * node_reward_pool, 6)
    
        # 5. Combinar saídas
        all_outputs = producer_outputs + node_outputs
        
        # CORREÇÃO: Adicionar encode()
        output_str = json.dumps(all_outputs, sort_keys=True)
        output_hash = hashlib.sha256(output_str.encode('utf-8')).hexdigest()
        
        # CORREÇÃO: Adicionar encode()
        tx_data = f"reward_{output_hash}_{datetime.utcnow().isoformat()}"
        tx_id = hashlib.sha256(tx_data.encode('utf-8')).hexdigest()
    
        tx = {
            "id": tx_id,
            "proposer": self.wallet.public_key,
            "inputs": [],
            "outputs": all_outputs,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "energy_record_ids": record_ids,
            "node_rewards": bool(node_outputs)
        }
    
        tx['signature'] = self.wallet.sign_transaction(tx)
        logger.info(f"Transação de recompensa criada: {total_tokens:.6f} tokens")
        return tx

    def start_server(self):
        """Inicia servidor TCP para receber conexões"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', self.listen_port))
            sock.listen(10)
            logger.info(f"Servidor iniciado na porta {self.listen_port}")
            
            while self.running:
                try:
                    client, addr = sock.accept()
                    threading.Thread(target=self.handle_client, args=(client, addr)).start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Erro na conexão: {e}")
    
    def handle_client(self, client, addr):
        """Manipula conexões de clientes"""
        try:
            data = client.recv(65536)
            if not data:
                return

            # Processar PING diretamente
            if data == b"PING":
                client.sendall(b"PONG")
                return

            # Gerar ID único da mensagem
            msg_id = hashlib.sha256(data).hexdigest()

            # Verificar duplicata
            if msg_id in self.received_messages_cache:
                client.sendall(b"DUPLICATE")
                return

            try:
                message = json.loads(data.decode())
            except:
                logger.warning(f"Mensagem inválida de {addr}")
                client.sendall(b"INVALID")
                return

            # Adicionar ao cache antes de processar
            self.received_messages_cache.add(msg_id)
            message_type = message.get("type")
            
            if not message_type:
                client.sendall(b"INVALID_TYPE")
                return

            # Rotas de mensagens otimizadas
            handlers = {
                "SYNC_REQUEST": self.handle_sync_request,
                "MEMPOOL_REQUEST": self.handle_mempool_request,
                "MINUTE_PROD": self.handle_energy_data,
                "USER_TX": self.handle_transaction,
                "VRF_ANNOUNCE": self.handle_vrf_announce,
                "NEW_BLOCK": self.handle_new_block
            }

            if handler := handlers.get(message_type):
                handler(message, client, addr)
            else:
                client.sendall(b"UNKNOWN_TYPE")
                
        except Exception as e:
            logger.error(f"Erro no cliente {addr}: {e}")
        finally:
            client.close()

    def handle_sync_request(self, message, client, addr):
        """Manipula solicitação de sincronização de blockchain"""
        start_index = message["start_index"]
        blocks = self.blockchain.get_blocks_since(start_index)
        client.sendall(json.dumps(blocks).encode())

    def handle_mempool_request(self, message, client, addr):
        """Responde com estado atual da mempool"""
        try:
            mempool_data = {
                "energy_data": list(self.mempool.energy_data.values()),
                "transactions": self.mempool.get_pending_transactions()
            }
            response = json.dumps(mempool_data).encode()
            client.sendall(response)
        except Exception as e:
            logger.error(f"Erro ao preparar resposta MEMPOOL: {e}")
            client.sendall(b"ERROR")
    def handle_energy_data(self, message, client, addr):
        """Processa e propaga dados de produção de energia imediatamente"""
        # Verificar se está no período de coleta
        now_utc = datetime.now(timezone.utc)
        today = now_utc.date()
        
        # Criar datetime completo para verificação
        energy_collection_end = datetime(
            today.year, today.month, today.day,
            self.ENERGY_COLLECTION_END.hour,
            self.ENERGY_COLLECTION_END.minute,
            self.ENERGY_COLLECTION_END.second,
            tzinfo=timezone.utc
        )
        
        if now_utc >= energy_collection_end:
            logger.warning("Rejeitando dados de energia após o horário limite")
            client.sendall(b"REJECTED:TIME_WINDOW")
            return
    
        # Se estiver em eleição, armazenar pendente
        if self.election_in_progress:
            logger.warning("Dados de energia recebidos durante eleição, armazenando pendente")
            self.pending_energy_data.append(message)
            client.sendall(b"PENDING_ELECTION")
            return
    
        # Validar assinatura
        if not self.verify_signature(message):
            client.sendall(b"INVALID_SIGNATURE")
            return
    
        try:
            # Criar registro de energia
            public_address = message["public_address"]
            timestamp = message["timestamp"]
            total_kwh = message["total_kwh"]
            
            record_id = hashlib.sha256(
                f"{public_address}{timestamp}".encode()
            ).hexdigest()
            
            # Converter timestamp para objeto datetime
            try:
                # Tentar converter com timezone
                record_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                # Fallback para conversão sem timezone
                record_date = datetime.fromisoformat(timestamp)
                
            energy_record = {
                "id": record_id,
                "producer": public_address,
                "timestamp": timestamp,
                "total_kwh": total_kwh,
                "date": record_date.strftime("%Y-%m-%d")
            }
    
            # Adicionar e propagar se for novo
            if not self.mempool.energy_data_exists(record_id):
                self.mempool.add_energy_data(energy_record)
                client.sendall(b"ACK")
                logger.info(f"Dados de produção adicionados: {total_kwh}kWh de {public_address[:10]}...")
                
                # Propagação IMEDIATA para todos os peers
                self.propagate(message, exclude=[addr])
            else:
                client.sendall(b"DUPLICATE")
        except KeyError as e:
            logger.error(f"Campo faltando: {e}")
            client.sendall(b"INVALID_FORMAT")
    def _send_to_peer(self, peer, message):
        """Envio assíncrono para peer específico"""
        host, port = peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((host, port))
                sock.sendall(message.encode())
        except:
            pass  
    def handle_transaction(self, message, client, addr):
        """Processa e propaga imediatamente transações regulares"""
        # Bloqueio apenas durante eleição
        if self.election_in_progress:
            logger.warning("Transação recebida durante eleição, armazenando pendente")
            self.pending_transactions.append(message)
            client.sendall(b"PENDING_ELECTION")
            return
            
        tx = message["transaction"]
        
        if self.mempool.transaction_exists(tx['id']):
            client.sendall(b"DUPLICATE")
            return

        if not self.validate_transaction_signature(tx):
            client.sendall(b"INVALID_SIGNATURE")
            return

        if self.mempool.add_transaction(tx):
            client.sendall(b"ACCEPTED")
            logger.info(f"Transação adicionada: {tx['id'][:10]}...")
            
            # Propagação IMEDIATA para todos os peers
            self.propagate(message, exclude=[addr])
            return True
        else:
            client.sendall(b"REJECTED:INVALID_TX")
            return False
    def _send_direct_message(self, peer, message):
        host, port = peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((host, port))
                
                # Se for string, converter para bytes
                if isinstance(message, str):
                    message = message.encode()
                    
                sock.sendall(message)
                
                # Receber resposta em chunks
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    
                return response.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Erro ao enviar mensagem para {host}:{port}: {e}")
            return None
    def reprocess_pending_data(self):
        """Reprocessa e propaga pendentes após eleição"""
        # Processar transações pendentes
        for msg in self.pending_transactions[:]:
            # Usar um cliente fictício para reprocessamento
            class DummyClient:
                def sendall(self, data):
                    pass
                    
            dummy_client = DummyClient()
            success = self.handle_transaction(msg, dummy_client, None)
            if success:
                self.pending_transactions.remove(msg)
        
        # Processar dados de energia pendentes
        for msg in self.pending_energy_data[:]:
            success = self.handle_energy_data(msg, dummy_client, None)
            if success:
                self.pending_energy_data.remove(msg)
    def handle_vrf_announce(self, message, client, addr):
            """Processa anúncios VRF"""
            # 1. Verificar campos obrigatórios
            required_fields = ['public_key', 'vrf_output', 'vrf_proof', 'timestamp']
            if not all(field in message for field in required_fields):
                logger.error(f"Mensagem VRF_ANNOUNCE incompleta: {message}")
                client.sendall(b"INVALID_FORMAT")
                return

            # 2. Verificar tipos dos campos
            if (not isinstance(message['public_key'], str) or \
               (not isinstance(message['vrf_output'], str)) or \
               (not isinstance(message['vrf_proof'], str)) or \
               (not isinstance(message['timestamp'], str))):
                logger.error(f"Tipos inválidos na mensagem VRF: "
                             f"public_key={type(message['public_key'])}, "
                             f"output={type(message['vrf_output'])}, "
                             f"proof={type(message['vrf_proof'])}, "
                             f"timestamp={type(message['timestamp'])}")
                client.sendall(b"INVALID_TYPES")
                return

            # 2.5 Verificar campos não vazios
            if (not message['public_key'].strip() or 
                not message['vrf_output'].strip() or 
                not message['vrf_proof'].strip() or 
                not message['timestamp'].strip()):
                logger.error(f"Campos VRF vazios: {message}")
                client.sendall(b"INVALID_EMPTY_FIELD")
                return

            # 2.6 Verificar comprimento mínimo
            if len(message['vrf_output']) < 64 or len(message['vrf_proof']) < 140:
                logger.error(f"Comprimento inválido: output={len(message['vrf_output'])}, proof={len(message['vrf_proof'])}")
                client.sendall(b"INVALID_LENGTH")
                return

            # 3. Verificar timestamp
            try:
                ts = message["timestamp"].replace('Z', '+00:00')
                announcement_time = datetime.fromisoformat(ts)
                now = datetime.now(timezone.utc)

                # Converter para UTC se necessário
                if announcement_time.tzinfo is None:
                    announcement_time = announcement_time.replace(tzinfo=timezone.utc)
                else:
                    announcement_time = announcement_time.astimezone(timezone.utc)

                # Verificar expiração (30 segundos)
                if (now - announcement_time).total_seconds() > 30:
                    client.sendall(b"REJECTED:EXPIRED")
                    return
            except ValueError:
                logger.error(f"Formato de timestamp inválido: {message['timestamp']}")
                client.sendall(b"INVALID_FORMAT")
                return

            # 4. Verificar duplicata
            ann_id = hashlib.sha256(
                (message["public_key"] + message["vrf_output"]).encode()
            ).hexdigest()

            if any(ann.get('id') == ann_id for ann in self.vrf_announcements):
                client.sendall(b"DUPLICATE")
                return

            # 5. Armazenar e propagar
            self.vrf_announcements.append({
                "id": ann_id,
                "public_key": message["public_key"],
                "vrf_output": message["vrf_output"],
                "vrf_proof": message["vrf_proof"],
                "timestamp": message["timestamp"]
            })
            client.sendall(b"ACK_VRF")

            # Propagação com TTL reduzido
            ttl = message.get('ttl', 5)
            if ttl > 1:
                message = message.copy()
                message["id"] = ann_id
                message['ttl'] = ttl - 1
                self.propagate(message, exclude=[addr])

    def handle_new_block(self, message, client, addr):
        """Processa novos blocos recebidos"""
        if self._validate_new_block(message):
            block = message["block"]
            if self.blockchain.save_block(block):
                client.sendall(b"ACCEPTED")
                self.mempool.clear_processed_data(block)
                
                # Propagação com TTL reduzido
                ttl = message.get('ttl', 5)
                if ttl > 1:
                    message['ttl'] = ttl - 1
                    self.propagate(message, exclude=[addr])
            else:
                client.sendall(b"REJECTED")
        else:
            client.sendall(b"REJECTED")

    def _validate_new_block(self, message):
        """Valida um novo bloco recebido"""
        try:
            block = message["block"]
            
            # 1. Verificar assinatura do bloco
            if not self.wallet.verify_block(block):
                logger.error("Assinatura do bloco inválida")
                return False
                
            # 2. Verificar VRF
            last_block = self.blockchain.get_last_block()
            seed = last_block['hash'] if last_block else "genesis_seed"
            
            # Verificar parâmetros VRF
            if ('vrf_output' not in message or 
                'vrf_proof' not in message or 
                not message['vrf_output'] or 
                not message['vrf_proof']):
                logger.error("Dados VRF ausentes no bloco")
                return False
                
            if not VRFNode.verify_vrf(
                block['proposer'],
                seed,
                message['vrf_output'],
                message['vrf_proof']
            ):
                logger.error("Prova VRF inválida")
                return False
                
            # 3. Validar dificuldade VRF
            try:
                output_bytes = bytes.fromhex(message['vrf_output'][:64])
                output_int = int.from_bytes(output_bytes, 'big')
                max_value = (1 << 256) - 1
                normalized = output_int / max_value
                
                if normalized >= self.vrf_threshold:
                    logger.error(f"VRF acima do threshold: {normalized} >= {self.vrf_threshold}")
                    return False
            except:
                logger.error("Erro ao processar output VRF")
                return False
                
            # 4. Validar bloco
            if not self.blockchain.validate_block(block):
                logger.error("Bloco inválido")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Erro na validação do bloco: {e}")
            return False

    def validate_transaction_signature(self, tx):
        """Valida assinatura de transação"""
        try:
            tx_data = {k: v for k, v in tx.items() if k != "signature"}
            public_key = tx["inputs"][0]["address"]
            serialized = json.dumps(tx_data, sort_keys=True)
            return self.wallet.verify_signature(public_key, serialized, tx["signature"])
        except Exception as e:
            logger.error(f"Erro na validação de transação: {e}")
            return False

    def verify_signature(self, message):
        """Verifica assinatura da mensagem (simplificado para produção)"""
        # IMPLEMENTAÇÃO REAL DEVERÁ SER ADICIONADA AQUI
        return True

    def propagate(self, message, exclude=[]):
        """Propagação eficiente para todos os peers ativos"""
        try:
            # Serializar apenas uma vez
            if isinstance(message, dict):
                message = json.dumps(message)
            
            # Obter peers ativos
            peers = self.discovery.get_active_peers()
            self_ip = self.config['Network']['advertised_ip']
            self_port = self.listen_port
            
            # Enviar para todos os peers em threads paralelas
            for peer in peers:
                if peer == (self_ip, self_port) or peer in exclude:
                    continue
                
                threading.Thread(
                    target=self._send_to_peer,
                    args=(peer, message),
                    daemon=True
                ).start()
        except Exception as e:
            logger.error(f"Erro na propagação: {e}")
    def _cache_cleaner_worker(self):
        """Limpa caches periodicamente"""
        while self.running:
            time.sleep(300)
            self.sent_messages_cache.clear()
            self.received_messages_cache.clear()
            logger.debug("Caches de mensagens limpos")

