from ecdsa import SigningKey, SECP256k1, VerifyingKey, util
import hashlib
import json
import logging
import ecdsa
from datetime import datetime
from ecdsa.util import sigencode_der, sigdecode_der
from decimal import Decimal, ROUND_DOWN
import logging

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
        """Assina dados serializados"""
        return self.sk.sign(data.encode(), 
                           hashfunc=hashlib.sha256, 
                           sigencode=sigencode_der).hex()

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

    def _normalize_data(self, data):
        """Normaliza recursivamente os dados para serialização determinística"""
        if isinstance(data, list):
            return sorted((self._normalize_data(item) for item in data), key=str)
        elif isinstance(data, dict):
            return {k: self._normalize_data(v) for k, v in sorted(data.items())}
        elif isinstance(data, float):
            # Converter float para string decimal com 6 casas
            return str(Decimal(str(data)).quantize(Decimal('0.000001'), rounding=ROUND_DOWN))
        else:
            return data

    def _serialize_for_signing(self, tx):
        """Serializa a transação de forma determinística para assinatura"""
        # Criar cópia e remover assinatura existente
        tx_copy = tx.copy()
        tx_copy.pop("signature", None)
        
        # Normalizar dados
        normalized_tx = self._normalize_data(tx_copy)
        
        # Serialização compacta sem espaços
        return json.dumps(normalized_tx, sort_keys=True, indent=None, separators=(',', ':'))

    def sign_transaction(self, tx):
        """Assina uma transação UTXO com serialização determinística"""
        # Serializar transação
        tx_str = self._serialize_for_signing(tx)
        
        # Calcular ID se necessário
        if not tx.get("id"):
            tx_id = hashlib.sha256(tx_str.encode()).hexdigest()
            tx["id"] = tx_id
            # Re-serializar com o novo ID
            tx_str = self._serialize_for_signing(tx)
        
        return self.sign(tx_str)
    
    def verify_transaction(self, tx):
        """Verifica a assinatura de uma transação usando serialização determinística"""
        signature = tx.get('signature')
        if not signature:
            return False
            
        # Usar o mesmo método de serialização usado na assinatura
        tx_str = self._serialize_for_signing(tx)
        
        # Obter chave pública do propositor
        public_key = tx.get('proposer', '')
        if not public_key:
            logger.error("Transação sem campo 'proposer'")
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