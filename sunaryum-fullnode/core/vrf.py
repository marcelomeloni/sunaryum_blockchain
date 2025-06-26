import hashlib
import logging
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der

logger = logging.getLogger('VRF')

class VRFNode:
    def __init__(self, secret_key):
        try:
            self.sk = SigningKey.from_string(bytes.fromhex(secret_key), curve=SECP256k1)
            self.vk = self.sk.get_verifying_key()
            self.public_key = self.vk.to_string().hex()
        except Exception as e:
            logger.error(f"Erro ao inicializar VRFNode: {str(e)}")
            raise
        
    def compute_vrf(self, seed):
        """Gera output e proof VRF usando assinatura ECDSA determinística"""
        try:
            # Garante que a seed seja tratada corretamente
            if isinstance(seed, str):
                seed_bytes = seed.encode('utf-8')
            else:
                seed_bytes = seed
                
            # Gera assinatura determinística em formato DER
            signature = self.sk.sign_deterministic(
                seed_bytes, 
                hashfunc=hashlib.sha256,
                sigencode=sigencode_der
            )
            
            # O output é o hash SHA-256 da assinatura
            output = hashlib.sha256(signature).hexdigest()
            return output, signature.hex()
        except Exception as e:
            logger.error(f"Erro ao calcular VRF: {str(e)}")
            return None, None

    @staticmethod
    def verify_vrf(public_key, seed, output, proof):
        """Verifica a validade do VRF"""
        try:
            # Garante que a seed seja tratada corretamente
            if isinstance(seed, str):
                seed_bytes = seed.encode('utf-8')
            else:
                seed_bytes = seed
                
            # Converte a prova para bytes
            signature = bytes.fromhex(proof)
            
            # Verifica se o output fornecido é válido
            expected_output = hashlib.sha256(signature).hexdigest()
            if output != expected_output:
                logger.error(f"Output VRF não corresponde: esperado {expected_output[:16]}..., recebido {output[:16]}...")
                return False
            
            # Carrega a chave pública
            vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
            
            # Verifica a assinatura usando DER
            return vk.verify(
                signature, 
                seed_bytes, 
                hashfunc=hashlib.sha256,
                sigdecode=sigdecode_der
            )
        except Exception as e:
            logger.error(f"Erro na verificação VRF: {str(e)}")
            return False

def elect_proposer(nodes, seed, threshold, day_index):
    valid_candidates = []
    
    if not nodes:
        logger.warning("Nenhum nó participou da eleição")
        return None
    
    for public_key, output, proof in nodes:
        if VRFNode.verify_vrf(public_key, seed, output, proof):
            try:
                # CORREÇÃO: Usar apenas 8 bytes (16 caracteres hex)
                output_bytes = bytes.fromhex(output[:16])
                output_int = int.from_bytes(output_bytes, 'big')
                max_value = 0xFFFF_FFFF_FFFF_FFFF  # 8 bytes (64 bits)
                normalized = output_int / max_value
                
                if normalized < threshold:
                    valid_candidates.append((public_key, normalized))
            except Exception as e:
                logger.error(f"Erro ao normalizar output VRF: {str(e)}")
                continue
    
    if valid_candidates:
        # Seleciona o candidato com menor valor normalizado
        valid_candidates.sort(key=lambda x: x[1])
        return valid_candidates[0][0]
    
    # Fallback round-robin
    logger.warning("Nenhum candidato válido, usando fallback round-robin")
    return nodes[day_index % len(nodes)][0]