import json
import os
from datetime import datetime
import logging
import hashlib
from collections import defaultdict

logger = logging.getLogger('Mempool')

class Mempool:
    def __init__(self, file_path='data/mempool.json'):
        self.file_path = file_path
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Estrutura correta: dicionário de registros por ID
        self.energy_data = {}
        self.transactions = []
        
        self.load()

    def load(self):
        try:
            if not os.path.exists(self.file_path):
                self.save()
                return
                
            with open(self.file_path, 'r') as f:
                if os.stat(self.file_path).st_size == 0:
                    logger.warning("Arquivo mempool vazio. Inicializando...")
                    self.save()
                    return
                    
                data = json.load(f)
                # Carrega energy_data como dicionário de registros
                self.energy_data = data.get('energy_data', {})
                self.transactions = data.get('transactions', [])
                
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Erro ao carregar mempool: {str(e)}. Inicializando novo mempool.")
            try:
                os.rename(self.file_path, f"{self.file_path}.corrupt")
            except Exception as backup_error:
                logger.error(f"Falha no backup: {str(backup_error)}")
            self.energy_data = {}
            self.transactions = []
            self.save()
    def clear_processed_data(self, block):
        """Remove todos os dados processados por um bloco"""
        try:
            block_time = datetime.fromisoformat(block['timestamp'].replace('Z', '+00:00'))
            removed_records = 0
            removed_transactions = 0
            
            # 1. Remover transações do bloco
            tx_ids_in_block = [tx['id'] for tx in block['transactions']]
            self.transactions = [tx for tx in self.transactions if tx['id'] not in tx_ids_in_block]
            removed_transactions = len(tx_ids_in_block) - len(self.transactions)
            
            # 2. Remover registros de energia vinculados
            for tx in block['transactions']:
                if "energy_record_ids" in tx:
                    for rid in tx["energy_record_ids"]:
                        if rid in self.energy_data:
                            del self.energy_data[rid]
                            removed_records += 1
            
            # 3. Remover registros antigos por timestamp
            for record_id, record in list(self.energy_data.items()):
                try:
                    record_time = datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
                    if record_time <= block_time:
                        del self.energy_data[record_id]
                        removed_records += 1
                except Exception:
                    continue
            
            self.save()
            logger.info(f"Removidos {removed_records} registros e {removed_transactions} transações processadas pelo bloco #{block['index']}")
            return True
        except Exception as e:
            logger.error(f"Erro ao limpar mempool: {str(e)}")
            return False

    def add_transaction(self, transaction):
        """Adiciona uma transação ao mempool"""
        # Verifique se já existe
        if any(tx['id'] == transaction['id'] for tx in self.transactions):
            return

        self.transactions.append(transaction)
        self.save()
    def save(self):
        try:
            with open(self.file_path, 'w') as f:
                json.dump({
                    "energy_data": self.energy_data,
                    "transactions": self.transactions
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Erro ao salvar mempool: {str(e)}")

    def add_energy_data(self, record):
        # Gerar ID único baseado no conteúdo
        record_id = hashlib.sha256(
            f"{record['producer']}{record['timestamp']}{record['total_kwh']}".encode()
        ).hexdigest()
        
        record['id'] = record_id
        self.energy_data[record_id] = record
        self.save()  # Salvar após adicionar
        logger.debug(f"Registro de energia adicionado: {record_id}")

    def get_records_since(self, timestamp):
        """Retorna todos os registros de energia desde o timestamp especificado."""
        records = []
        for record in self.energy_data.values():
            try:
                # Converter para objeto datetime para comparação
                record_time = datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
                if record_time > timestamp:
                    records.append(record)
            except Exception as e:
                logger.error(f"Erro ao processar timestamp: {str(e)}")
        return records

    def get_pending_transactions(self):
        return self.transactions

    def remove_energy_records(self, record_ids):
        """Remove registros específicos pelo ID."""
        for rid in record_ids:
            if rid in self.energy_data:
                del self.energy_data[rid]
        self.save()

    def remove_transactions(self, tx_ids):
        """Remove transações específicas pelo ID."""
        self.transactions = [tx for tx in self.transactions if tx['id'] not in tx_ids]
        self.save()