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
         # --- NOVO: Parâmetro para o bônus do propositor ---
        # Define a porcentagem do pool de recompensa dos nós que vai como bônus para o propositor.
        # Ex: 0.5 significa 50%.
        self.proposer_bonus_percentage = float(config.get('Rewards', 'proposer_bonus_percentage', fallback=0.5))

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
        self.ENERGY_COLLECTION_START = dt_time(14, 11, tzinfo=timezone.utc)
        self.ENERGY_COLLECTION_END = dt_time(14, 11, tzinfo=timezone.utc)
        self.ELECTION_TIME = dt_time(14, 11, tzinfo=timezone.utc)
        
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
        """Sincronização global da mempool com timeout otimizado"""
        active_peers = self.discovery.get_active_peers()
        if not active_peers:
            logger.info("Nenhum peer ativo para sincronização")
            return

        logger.info(f"Iniciando sincronização de mempool com {len(active_peers)} peers")

        # Usando ThreadPoolExecutor para melhor controle
        from concurrent.futures import ThreadPoolExecutor, as_completed

        start_time = time.time()
        timeout = 15  # segundos

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.sync_mempool_with_peer, peer): peer for peer in active_peers}

            for future in as_completed(futures, timeout=timeout):
                peer = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Erro ao sincronizar com {peer}: {e}")

        logger.info(f"Sincronização concluída em {time.time()-start_time:.2f}s")

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

                added_energy = 0
                for record in mempool_data.get('energy_data', []):
                    try:
                        # Usar ID existente ou gerar se necessário
                        record_id = record.get('id') or hashlib.sha256(
                            f"{record['producer']}{record['timestamp']}".encode()
                        ).hexdigest()

                        record['id'] = record_id  # Garantir que o ID existe

                        if not self.mempool.energy_data_exists(record_id):
                            self.mempool.add_energy_data(record)
                            added_energy += 1
                        else:
                            logger.debug(f"Registro de energia já existe: {record_id}")
                    except KeyError as e:
                        logger.warning(f"Registro de energia inválido: campo faltando {e}")
                    except Exception as e:
                        logger.error(f"Erro ao adicionar registro: {str(e)}")

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
            logger.info("🚀 FASE 1: Iniciando coleta de anúncios VRF...")
            start_time = time.time()

            # Sincronização prévia da mempool continua sendo uma boa prática
            self.initiate_global_sync()
            
            # Resetar estado da eleição
            self.vrf_announcements = []
            self.election_participants = []
            
            last_block = self.blockchain.get_last_block()
            if not last_block:
                logger.error("Não foi possível obter o último bloco para seed VRF")
                return

            seed = last_block['hash']
            
            # Calcular e propagar o próprio VRF
            vrf_output, vrf_proof = self.vrf.compute_vrf(seed)
            if vrf_output and vrf_proof:
                # Adicionar o próprio anúncio imediatamente
                self.handle_vrf_announce({
                    "public_key": self.wallet.public_key,
                    "vrf_output": vrf_output,
                    "vrf_proof": vrf_proof,
                    "timestamp": datetime.utcnow().isoformat()
                }, None, None) # client e addr são None pois é uma chamada interna

                self.propagate({
                    "type": "VRF_ANNOUNCE",
                    "public_key": self.wallet.public_key,
                    "vrf_output": vrf_output,
                    "vrf_proof": vrf_proof,
                    "timestamp": datetime.utcnow().isoformat(),
                    "ttl": 5
                })
            else:
                 logger.error("Falha crítica ao calcular VRF local. Não participando da eleição.")
                 return

            # Janela para coletar anúncios dos outros
            logger.info("Coletando anúncios VRF por 15 segundos...")
            time.sleep(15)

            # --- NOVA FASE DE SINCRONIA ---
            logger.info("🚀 FASE 2: Período de Cooldown para sincronia final (5 segundos)...")
            time.sleep(5)
            
            # --- FASE 3: ELEIÇÃO DETERMINÍSTICA ---
            logger.info("🚀 FASE 3: Eleição e possível criação do bloco...")
            
            # Agora, a lista de anúncios deve ser a mesma para todos os nós
            valid_announcements = self.vrf_announcements # Usar a lista que foi preenchida pelo handle_vrf_announce

            logger.info(f"{len(valid_announcements)} anúncios VRF válidos para a eleição.")
            
            if not valid_announcements:
                logger.warning("Nenhum anúncio VRF válido recebido. Abortando eleição.")
                return

            self.election_participants = [ann['public_key'] for ann in valid_announcements]
            
            nodes_data = [(ann['public_key'], ann['vrf_output'], ann['vrf_proof']) 
                          for ann in valid_announcements]

            block_index = self.blockchain.get_block_height() + 1
            elected_public_key = elect_proposer(
                nodes_data,
                seed,
                self.vrf_threshold,
                block_index
            )

            if not elected_public_key:
                logger.error("Nenhum propositor pôde ser eleito. Abortando.")
                return

            self.current_proposer = elected_public_key
            logger.info(f"✅ Propositor eleito por consenso da rede: {elected_public_key[:10]}...")

            # APENAS o nó eleito prepara o bloco
            if elected_public_key == self.wallet.public_key:
                logger.info("Este nó foi eleito! Preparando novo bloco...")
                self.vrf_output = vrf_output # Salva para incluir na propagação
                self.vrf_proof = vrf_proof
                self._prepare_block()
            else:
                logger.info("Aguardando bloco do propositor eleito...")

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
        """
        Cria a transação de recompensa com bônus para o propositor.
        """
        # 1. Calcular produção total de energia
        production_sum = defaultdict(float)
        total_kwh = sum(record['total_kwh'] for record in energy_records)
        if total_kwh == 0:
            logger.warning("Nenhum kWh produzido, transação de recompensa não será criada.")
            return None

        for record in energy_records:
            production_sum[record['producer']] += record['total_kwh']

        # 2. Calcular tokens totais e dividir entre produtores e nós
        total_tokens = total_kwh / 100.0
        node_reward_pool = total_tokens * self.node_reward_percentage
        producer_tokens = total_tokens - node_reward_pool

        # 3. Criar saídas para os produtores de energia
        producer_outputs = []
        if producer_tokens > 0:
            for address, kwh in production_sum.items():
                share = kwh / total_kwh
                tokens = producer_tokens * share
                if tokens > 0:
                    producer_outputs.append({
                        "address": address,
                        "amount": round(tokens, 8)
                    })
        
        # 4. MODIFICADO: Calcular recompensa dos nós com bônus para o propositor
        node_outputs = []
        participants = getattr(self, 'election_participants', [])
        proposer_pk = self.wallet.public_key # Chave do nó que está criando o bloco

        if participants and node_reward_pool > 0:
            # Dicionário para acumular recompensas
            node_rewards = defaultdict(float)

            # Calcular o bônus do propositor e o pool compartilhado
            proposer_bonus = node_reward_pool * self.proposer_bonus_percentage
            shared_pool = node_reward_pool - proposer_bonus
            
            # Dividir o pool compartilhado entre todos os participantes
            if shared_pool > 0:
                reward_per_participant = shared_pool / len(participants)
                for pk in participants:
                    node_rewards[pk] += reward_per_participant
            
            # Adicionar o bônus ao propositor (que também deve estar na lista de participantes)
            node_rewards[proposer_pk] += proposer_bonus
            
            # Converter o dicionário de recompensas em lista de saídas
            for address, amount in node_rewards.items():
                if amount > 0:
                    node_outputs.append({
                        "address": address,
                        "amount": round(amount, 8)
                    })
            logger.info(f"Recompensa dos nós distribuída. Bônus do propositor: {proposer_bonus:.8f}. "
                        f"Compartilhado: {shared_pool:.8f}.")
        elif node_reward_pool > 0:
            # Fallback: se não houver participantes, o propositor leva tudo
            node_outputs.append({"address": proposer_pk, "amount": round(node_reward_pool, 8)})


        # 5. Combinar saídas, criar e assinar a transação
        all_outputs = producer_outputs + node_outputs

        tx = {
            "id": "",  
            "inputs": [],
            "outputs": all_outputs,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "proposer": proposer_pk
        }
        
        tx_data_for_id = json.dumps({k: v for k, v in tx.items() if k not in ['id', 'signature']}, sort_keys=True)
        tx["id"] = hashlib.sha256(tx_data_for_id.encode()).hexdigest()
        tx["signature"] = self.wallet.sign_transaction(tx)

        logger.info(f"Transação de recompensa criada com {len(all_outputs)} saídas. Total de {total_tokens:.6f} tokens.")
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

            self.vrf_announcements.append({
                "id": ann_id,
                "public_key": message["public_key"],
                "vrf_output": message["vrf_output"],
                "vrf_proof": message["vrf_proof"],
                "timestamp": message["timestamp"]
            })

            # >>>>> CORREÇÃO: Só responder se houver client real <<<<<
            if client is not None:
                client.sendall(b"ACK_VRF")

            # Propagação com TTL reduzido
            ttl = message.get('ttl', 5)
            if ttl > 1:
                message = message.copy()
                message["id"] = ann_id
                message['ttl'] = ttl - 1
                self.propagate(message, exclude=[addr])

    def handle_new_block(self, message, client, addr):
        """Processa novos blocos recebidos com sincronização de mempool"""
        try:
            # 1. Sincronizar mempool antes de validar o bloco
            logger.info("Sincronizando mempool antes de validar novo bloco...")
            self.initiate_global_sync()

            # 2. Validar o bloco
            if not self._validate_new_block(message):
                client.sendall(b"REJECTED")
                return

            block = message["block"]

            # 3. Salvar o bloco
            if not self.blockchain.save_block(block):
                client.sendall(b"REJECTED")
                return

            # 4. Limpar dados processados e responder
            client.sendall(b"ACCEPTED")
            self.mempool.clear_processed_data(block)

            # 5. Propagação com TTL reduzido
            ttl = message.get('ttl', 5)
            if ttl > 1:
                message['ttl'] = ttl - 1
                self.propagate(message, exclude=[addr])

        except Exception as e:
            logger.error(f"Erro ao processar novo bloco: {e}")
            client.sendall(b"REJECTED")
    def _validate_new_block(self, message):
        """Valida um novo bloco recebido"""
        try:
            block = message["block"]
            block_index = block["index"]
            
            logger.info(f"Validando novo bloco #{block_index}...")
            current_height = self.blockchain.get_block_height()
    
            # 1. Verificar se o bloco já existe
            if block_index <= current_height:
                existing_block = self.blockchain.get_block(block_index)
                if existing_block and existing_block['hash'] == block['hash']:
                    logger.info(f"Bloco #{block_index} já existe na blockchain")
                    return True
                elif existing_block:
                    logger.warning(f"Conflito: bloco #{block_index} diferente já existe")
                    # Resolver conflito usando PoW implícito (menor hash ganha)
                    if block['hash'] < existing_block['hash']:
                        logger.info(f"Substituindo bloco #{block_index} por hash menor")
                        return True
                    return False
    
            # 2. Obter a seed correta (hash do bloco ANTERIOR)
            if block_index == 0:
                seed = "genesis_seed"
            else:
                previous_block = self.blockchain.get_block(block_index - 1)
                if not previous_block:
                    logger.error(f"Bloco anterior (#{block_index-1}) não encontrado")
                    return False
                seed = previous_block['hash']
            
            logger.info(f"Usando seed VRF: {seed[:16]}...")
    
            # 3. Verificar consistência com o previous_hash do bloco
            if block_index > 0 and block['previous_hash'] != seed:
                logger.error(f"Hash anterior do bloco não coincide com a seed: "
                            f"{block['previous_hash'][:16]} vs {seed[:16]}")
                return False
    
            # 4. Verificar VRF com seed do bloco anterior
            if not VRFNode.verify_vrf(
                block['proposer'],
                seed,
                message['vrf_output'],
                message['vrf_proof']
            ):
                logger.error("Prova VRF inválida para a seed do bloco anterior")
                return False
                
            # 5. Validar dificuldade VRF
            try:
                output_bytes = bytes.fromhex(message['vrf_output'][:64])
                output_int = int.from_bytes(output_bytes, 'big')
                max_value = (1 << 256) - 1
                normalized = output_int / max_value
                
                logger.debug(f"VRF normalizado: {normalized:.6f} (threshold: {self.vrf_threshold})")
                
                if normalized >= self.vrf_threshold:
                    logger.error(f"VRF acima do threshold: {normalized} >= {self.vrf_threshold}")
                    return False
            except Exception as e:
                logger.error(f"Erro ao processar output VRF: {e}")
                return False
            if not hasattr(self, 'election_participants') or block['proposer'] not in self.election_participants:
                logger.error("Propositor não está na lista de participantes da eleição")
                return False    
            # 6. Validar estrutura do bloco
            if not self.blockchain.validate_block(block):
                logger.error("Bloco inválido")
                return False
                
            logger.info(f"Bloco #{block_index} validado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro crítico na validação do bloco: {e}")
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

