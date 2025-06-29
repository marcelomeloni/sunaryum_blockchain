import os
import json
import hashlib
from datetime import datetime
import logging
import copy 
logger = logging.getLogger('Blockchain')
class UTXO:
    def __init__(self, txid, index, address, amount):
        self.txid = txid        # ID da transação que criou o UTXO
        self.index = index       # Índice na lista de outputs
        self.address = address   # Endereço do proprietário
        self.amount = amount     # Quantidade de tokens
        self.spent = False       # Flag para gasto

class UTXOSet:
    def __init__(self, data_dir='data/utxoset.json'):
        self.data_dir = data_dir
        self.utxos = {}  # {f"{txid}:{index}": UTXO}
        self.load()
    
    def load(self):
        if os.path.exists(self.data_dir):
            try:
                with open(self.data_dir, 'r') as f:
                    data = json.load(f)
                    self.utxos = {}
                    for key, utxo_data in data.items():
                        # Crie o UTXO manualmente em vez de usar **
                        utxo = UTXO(
                            txid=utxo_data['txid'],
                            index=utxo_data['index'],
                            address=utxo_data['address'],
                            amount=utxo_data['amount']
                        )
                        utxo.spent = utxo_data['spent']
                        self.utxos[key] = utxo
            except Exception as e:
                logger.error(f"Erro ao carregar UTXO set: {str(e)}")
                self.utxos = {}
    
    def save(self):
        serialized = {
            f"{utxo.txid}:{utxo.index}": utxo.__dict__ 
            for utxo in self.utxos.values()
        }
        with open(self.data_dir, 'w') as f:
            json.dump(serialized, f)
    
    def add_utxo(self, utxo):
        key = f"{utxo.txid}:{utxo.index}"
        self.utxos[key] = utxo
        self.save()
    
    def spend_utxo(self, txid, index):
        key = f"{txid}:{index}"
        if key in self.utxos:
            self.utxos[key].spent = True
            self.save()
    
    def get_balance(self, address):
        balance = 0
        for utxo in self.utxos.values():
            if utxo.address == address and not utxo.spent:
                balance += utxo.amount
        return balance
    
    def get_unspent_utxos(self, address):
        return [
            utxo for utxo in self.utxos.values()
            if utxo.address == address and not utxo.spent
        ]
class Blockchain:
    def __init__(self, wallet, data_dir='data/blocks'):  # Adicione wallet como parâmetro
        self.wallet = wallet  # Armazene a referência à carteira
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.height = self.get_block_height()
        self.utxo_set = UTXOSet(os.path.join(data_dir, 'utxoset.json'))
        # Cria bloco gênese se necessário
        if self.height < 0:
            self.create_genesis_block()
            self.height = 0
        else:
            logger.info(f"Blockchain carregada com altura: {self.height}")
    def get_last_block_timestamp(self):
        """Retorna o timestamp do último bloco."""
        last_block = self.get_last_block()
        return last_block['timestamp'] if last_block else "1970-01-01T00:00:00Z"
    def get_block_height(self):
        try:
            # Lista todos os arquivos de bloco
            block_files = [f for f in os.listdir(self.data_dir) if f.endswith('.json')]
            
            if not block_files:
                return -1  # Indica que não há blocos
                
            # Encontra o maior número de bloco
            indices = [int(f.split('.')[0]) for f in block_files]
            return max(indices)
        except FileNotFoundError:
            return -1
        except Exception as e:
            logger.error(f"Erro ao obter altura do bloco: {str(e)}")
            return -1
    
    def create_genesis_block(self):
        genesis = {
            "index": 0,
            "timestamp": "2025-01-01T00:00:00Z",
            "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "proposer": "genesis",
          
            "transactions": []
        }
        genesis["hash"] = self.calculate_block_hash(genesis)
        self.save_block(genesis)
        logger.info("Bloco gênese criado")
    def get_blocks_since(self, index):
        """Retorna todos os blocos a partir de um determinado índice."""
        blocks = []
        for height in range(index, self.height + 1):
            block = self.get_block(height)
            if block:
                blocks.append(block)
        return blocks   
    def get_last_block(self):
        try:
            if self.height < 0:
                return None
                
            return self.get_block(self.height)
        except Exception as e:
            logger.error(f"Erro ao obter último bloco: {str(e)}")
            # Retorna um bloco genesis fictício para evitar quebras
            return {
                "index": -1,
                "hash": "0000000000000000000000000000000000000000000000000000000000000000"
            }
    def get_block_height(self):
        try:
            # Lista apenas arquivos numéricos (.json)
            block_files = [
                f for f in os.listdir(self.data_dir) 
                if f.endswith('.json') and f.split('.')[0].isdigit()
            ]

            if not block_files:
                return -1

            indices = [int(f.split('.')[0]) for f in block_files]
            return max(indices)
        except Exception as e:
            logger.error(f"Erro ao obter altura do bloco: {str(e)}")
            return -1
    def get_block(self, height):
        file_path = os.path.join(self.data_dir, f"{height}.json")
        if not os.path.exists(file_path):
            logger.error(f"Bloco {height} não encontrado")
            return None
            
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Erro ao ler bloco {height}: {str(e)}")
            return None
    
    def calculate_block_hash(self, block):
        """Calcula o hash SHA-256 do bloco, ignorando campos não essenciais."""
        # Cria uma cópia para remover campos que não devem ser incluídos no hash
        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_copy.pop('signature', None)
        
        # Ordena as chaves para garantir consistência
        block_str = json.dumps(block_copy, sort_keys=True)
        return hashlib.sha256(block_str.encode()).hexdigest()
    def update_utxo_set(self, block):
        for tx in block['transactions']:
            # Marcar inputs como gastos
            for input in tx.get('inputs', []):
                self.utxo_set.spend_utxo(input['txid'], input['index'])
            
            # Adicionar novos UTXOs
            for i, output in enumerate(tx['outputs']):
                utxo = UTXO(
                    txid=tx['id'],
                    index=i,
                    address=output['address'],
                    amount=output['amount']
                )
                self.utxo_set.add_utxo(utxo)
    def save_block(self, block):
        """Salva um bloco no sistema de arquivos e atualiza a altura da blockchain."""
        height = block['index']
        file_path = os.path.join(self.data_dir, f"{height}.json")
        
        # Verificar se o bloco já existe
        if os.path.exists(file_path):
            try:
                # Carregar bloco existente para verificar se é o mesmo
                with open(file_path, 'r') as f:
                    existing_block = json.load(f)
                    
                # Verificar se é o mesmo bloco pelo hash
                if existing_block.get('hash') == block.get('hash'):
                    logger.info(f"Bloco #{height} já existe (mesmo hash).")
                    return True
                else:
                    # Bloco conflitante encontrado!
                    existing_hash = existing_block.get('hash', '')[:16] + '...' if 'hash' in existing_block else 'N/A'
                    new_hash = block.get('hash', '')[:16] + '...'
                    logger.warning(f"Conflito no bloco #{height}! Hash existente: {existing_hash}, Hash novo: {new_hash}")
                    return False
            except Exception as e:
                logger.error(f"Erro ao verificar bloco existente #{height}: {str(e)}")
                return False
                
        try:
            # Salvar o novo bloco
            with open(file_path, 'w') as f:
                json.dump(block, f, indent=2)
            
            # Atualizar UTXO set apenas para novos blocos
            self.update_utxo_set(block)
            
            # Atualizar altura da blockchain
            if height > self.height:
                self.height = height
                logger.info(f"Novo bloco salvo: #{height}")
            else:
                logger.info(f"Bloco histórico salvo: #{height}")
                
            return True
        except Exception as e:
            logger.error(f"Erro ao salvar bloco #{height}: {str(e)}")
            return False
    
    def create_block(self, transactions, proposer):
        last_block = self.get_last_block()
        index = last_block['index'] + 1

        block = {
            "index": index,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "previous_hash": last_block['hash'],  # Use o hash real
            "proposer": proposer,
            "transactions": transactions
        }

        block["hash"] = self.calculate_block_hash(block)
        return block
    def validate_transaction(self, tx, utxo_set):
        # 1. Verificar assinatura
        if not self.wallet.verify_transaction(tx):
            logger.error(f"Assinatura inválida na transação: {tx.get('id')}")
            return False

        # Transações coinbase (sem inputs) são sempre válidas
        if not tx.get('inputs'):
            logger.debug("Transação coinbase validada")
            return True

        # 2. Verificar inputs apenas para transações não-coinbase
        input_sum = 0
        for input in tx['inputs']:
            key = f"{input['txid']}:{input['index']}"
            utxo = utxo_set.utxos.get(key)
            if not utxo or utxo.spent:
                logger.error(f"UTXO não encontrado ou já gasto: {key}")
                return False
            input_sum += utxo.amount

        # 3. Verificar outputs
        output_sum = sum(output['amount'] for output in tx['outputs'])

        # 4. Verificar se inputs cobrem outputs
        if input_sum < output_sum:
            logger.error(f"Inputs insuficientes: {input_sum} < {output_sum}")
            return False
            
        return True

    def validate_block(self, block):
        """Valida a integridade do bloco e sua ligação com a blockchain."""
        # 1. Verifica se o bloco tem um índice sequencial
        last_block = self.get_last_block()
        if not last_block or block['index'] != last_block['index'] + 1:
            logger.error(f"Índice do bloco fora de sequência: esperado {last_block['index'] + 1}, recebido {block['index']}")
            return False
        
        # 2. Verifica se o hash anterior está correto
        if block['previous_hash'] != last_block['hash']:
            logger.error("Hash anterior não coincide")
            logger.error(f"Esperado: {last_block['hash']}")
            logger.error(f"Recebido: {block['previous_hash']}")
            return False
        
        # 3. Verifica o hash do bloco
        calculated_hash = self.calculate_block_hash(block)
        if block['hash'] != calculated_hash:
            logger.error("Hash do bloco inválido")
            logger.error(f"Esperado: {calculated_hash}")
            logger.error(f"Recebido: {block['hash']}")
            return False
        
        # 4. Valida a estrutura do bloco
        required_fields = [
            'index', 'timestamp', 'previous_hash', 'proposer',
             'transactions', 'hash'
        ]
        for field in required_fields:
            if field not in block:
                logger.error(f"Campo obrigatório faltando: {field}")
                return False
        
        # 5. Valida formato do timestamp
        try:
            datetime.fromisoformat(block['timestamp'].replace('Z', '+00:00'))
        except ValueError:
            logger.error("Formato de timestamp inválido")
            return False
        
       
        
        # 7. Valida transações (formato básico)
        if not isinstance(block['transactions'], list):
            logger.error("Transações devem ser uma lista")
            return False
        temp_utxo_set = copy.deepcopy(self.utxo_set)

        for tx in block['transactions']:
            if not self.validate_transaction(tx, temp_utxo_set):
                logger.error(f"Transação inválida: {tx.get('id')}")
                return False
                
            # Atualizar UTXO set temporário
            for input in tx.get('inputs', []):
                temp_utxo_set.spend_utxo(input['txid'], input['index'])
            
            for i, output in enumerate(tx['outputs']):
                utxo = UTXO(
                    txid=tx['id'],
                    index=i,
                    address=output['address'],
                    amount=output['amount']
                )
                temp_utxo_set.add_utxo(utxo)
        
        
        # Aqui você pode adicionar validações mais detalhadas das transações...
        
        logger.info(f"Bloco #{block['index']} validado com sucesso")
        return True
    
    def get_block_by_hash(self, block_hash):
        """Busca um bloco pelo seu hash."""
        for height in range(self.height + 1):
            block = self.get_block(height)
            if block and block['hash'] == block_hash:
                return block
        return None
    
    def get_blocks_since(self, index):
        """Retorna todos os blocos a partir de um determinado índice."""
        return [self.get_block(i) for i in range(index, self.height + 1)]