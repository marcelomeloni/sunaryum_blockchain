from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
import hashlib
import hmac
import json
import logging

logger = logging.getLogger('WalletManager')

class WalletManager:
    def __init__(self, seed_phrase):
        self.private_key, self.public_key = self._derive_keys_bip39(seed_phrase)
    
    def _derive_keys_bip39(self, seed_phrase):
        """Deriva chave privada e pública a partir do mnemonic BIP39 + HMAC-SHA512 (SunaryumDerivation)"""
        mnemo = Mnemonic('english')
        seed_bytes = mnemo.to_seed(seed_phrase, passphrase="")  # padrão BIP39

        # Deriva key material via HMAC-SHA512 com "SunaryumDerivation"
        derived = hmac.new(b"SunaryumDerivation", seed_bytes, hashlib.sha512).digest()
        priv_key_bytes = derived[:32]  # primeiros 32 bytes

        # Cria chaves ECDSA SECP256k1
        sk = SigningKey.from_string(priv_key_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        return sk, vk

    def get_public_address(self):
        """Gera o endereço público (hash SHA256 da chave pública, cortado em 40 hex)"""
        pub_bytes = self.public_key.to_string()
        return hashlib.sha256(pub_bytes).hexdigest()[:40]

    def sign_message(self, message_str):
        """Assina uma string de mensagem e retorna a assinatura em formato hexadecimal"""
        try:
            # Garantir que temos bytes para assinar
            if isinstance(message_str, str):
                data = message_str.encode('utf-8')
            else:
                data = message_str
                
            signature = self.private_key.sign(data)
            return signature.hex()
        except Exception as e:
            logger.error(f"Erro ao assinar mensagem: {str(e)}")
            return None

    def sign_transaction(self, tx):
        """Assina uma transação (dicionário) e retorna a assinatura"""
        try:
            # Converter para string JSON ordenada
            tx_str = json.dumps(tx, sort_keys=True)
            return self.sign_message(tx_str)
        except Exception as e:
            logger.error(f"Erro ao assinar transação: {str(e)}")
            return None