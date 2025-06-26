from ecdsa import SigningKey, SECP256k1, VerifyingKey, util
import hashlib
import json
import logging
import ecdsa
from datetime import datetime

logger = logging.getLogger('Wallet')

class Wallet:
    def __init__(self, private_key=None):
        if private_key:
            self.sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        else:
            self.sk = SigningKey.generate(curve=SECP256k1)
        self.vk = self.sk.get_verifying_key()
        self.public_key = self.vk.to_string().hex()
        self.private_key = self.sk.to_string().hex()
    
    def sign(self, data):
        """Assina dados binários usando SHA-256"""
        if isinstance(data, str):
            data = data.encode()
        return self.sk.sign(data, hashfunc=hashlib.sha256).hex()

    def verify(self, signature, data, public_key=None):
        """Verifica dados binários usando SHA-256"""
        if isinstance(data, str):
            data = data.encode()
        sig_bytes = bytes.fromhex(signature)
        
        if public_key:
            vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
        else:
            vk = self.vk
            
        try:
            return vk.verify(sig_bytes, data, hashfunc=hashlib.sha256)
        except ecdsa.BadSignatureError:
            return False
        except Exception as e:
            logger.error(f"Erro na verificação: {str(e)}")
            return False

    def sign_transaction(self, tx):
        """Assina uma transação UTXO"""
        # Serialização determinística
        tx_copy = {
            "id": tx.get("id", ""),
            "proposer": tx.get("proposer", ""),
            "inputs": sorted(tx.get("inputs", []), key=lambda i: f"{i['txid']}{i['index']}"),
            "outputs": sorted(tx.get("outputs", []), key=lambda o: f"{o['address']}{o['amount']}"),
            "timestamp": tx.get("timestamp", ""),
            "energy_record_ids": sorted(tx.get("energy_record_ids", []))
        }
        tx_str = json.dumps(tx_copy, sort_keys=True)
        return self.sign(tx_str)
    
    def verify_transaction(self, tx):
        """Verifica a assinatura de uma transação"""
        # Extrair assinatura
        signature = tx.get('signature')
        if not signature:
            return False
            
        # Reconstruir payload exato usado na assinatura
        tx_copy = {
            "id": tx.get("id", ""),
            "proposer": tx.get("proposer", ""),
            "inputs": sorted(tx.get("inputs", []), key=lambda i: f"{i['txid']}{i['index']}"),
            "outputs": sorted(tx.get("outputs", []), key=lambda o: f"{o['address']}{o['amount']}"),
            "timestamp": tx.get("timestamp", ""),
            "energy_record_ids": sorted(tx.get("energy_record_ids", []))
        }
        tx_str = json.dumps(tx_copy, sort_keys=True)
        
        # Obter chave pública do propositor
        public_key = tx.get('proposer', '')
        if not public_key:
            return False
            
        return self.verify(signature, tx_str, public_key)
    
    def sign_block(self, block):
        """Assina o hash de um bloco."""
        block_hash = self.calculate_block_hash(block)
        return self.sign(block_hash)
    
    def verify_block(self, block):
        """Verifica a assinatura de um bloco"""
        signature = block.get('signature')
        if not signature:
            return False
            
        block_hash = self.calculate_block_hash(block)
        proposer_public_key = block.get('proposer', '')
        
        if not proposer_public_key:
            return False
            
        return self.verify(signature, block_hash, proposer_public_key)
    
    @staticmethod
    def calculate_block_hash(block):
        """Calcula o hash do bloco de forma determinística"""
        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_copy.pop('signature', None)
        
        # Ordenar transações por ID
        if 'transactions' in block_copy:
            block_copy['transactions'] = sorted(
                block_copy['transactions'], 
                key=lambda tx: tx.get('id', '')
            )
            
        block_str = json.dumps(block_copy, sort_keys=True)
        return hashlib.sha256(block_str.encode()).hexdigest()