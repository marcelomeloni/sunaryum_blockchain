import hashlib
import logging
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
import random

logger = logging.getLogger('VRF')

class VRFNode:
    def __init__(self, secret_key):
        logger.info(f"Inicializando VRFNode com chave: {secret_key[:16]}...")
        try:
            if not secret_key or len(secret_key) != 64:
                logger.error("Chave secreta inválida. Deve ser string hexadecimal de 64 caracteres")
                raise ValueError("Chave secreta inválida")
            
            self.sk = SigningKey.from_string(bytes.fromhex(secret_key), curve=SECP256k1)
            self.vk = self.sk.get_verifying_key()
            self.public_key = self.vk.to_string().hex()
            logger.info(f"VRFNode inicializado com sucesso. Chave pública: {self.public_key[:16]}...")
        except Exception as e:
            logger.error(f"Erro crítico ao inicializar VRFNode: {str(e)}", exc_info=True)
            raise
        
    def compute_vrf(self, seed):
        """Gera output e proof VRF usando assinatura ECDSA determinística"""
        logger.info(f"Computando VRF para seed: {seed[:64]}...")
        
        try:
            # Validação da seed
            if seed is None or (isinstance(seed, str) and len(seed) == 0):
                logger.error("Seed inválida (None ou vazia)")
                return None, None
                
            # Conversão para bytes
            seed_bytes = seed.encode('utf-8') if isinstance(seed, str) else seed
            logger.debug(f"Seed em bytes: {seed_bytes[:16].hex()}... (tamanho: {len(seed_bytes)})")
            
            # Geração da assinatura determinística
            logger.debug("Gerando assinatura determinística...")
            signature = self.sk.sign_deterministic(
                seed_bytes, 
                hashfunc=hashlib.sha256,
                sigencode=sigencode_der
            )
            logger.debug(f"Assinatura gerada: {signature[:16].hex()}... (tamanho: {len(signature)})")
            
            # Cálculo do output VRF
            output = hashlib.sha256(signature).hexdigest()
            proof_hex = signature.hex()
            logger.info(f"VRF computado com sucesso. Output: {output[:16]}..., Proof: {proof_hex[:16]}...")
            
            return output, proof_hex
        except Exception as e:
            logger.error(f"Erro crítico ao calcular VRF: {str(e)}", exc_info=True)
            # Gerar valores fallback seguros
            fallback_output = hashlib.sha256(seed.encode()).hexdigest()
            fallback_proof = "00" * 64  # Prova inválida mas não vazia
            return fallback_output, fallback_proof

    @staticmethod
    def verify_vrf(public_key, seed, output, proof):
        # Verificação crítica de valores None ou vazios
        if not all([public_key, seed, output, proof]):
            logger.error(f"Parâmetros VRF inválidos: "
                        f"PK={bool(public_key)}, Seed={bool(seed)}, "
                        f"Output={bool(output)}, Proof={bool(proof)}")
            return False
        logger.info(f"Iniciando verificação VRF para chave: {public_key[:16]}...")
        
        try:
            # Validação básica dos inputs
            if not public_key or len(public_key) != 128:
                logger.error(f"Chave pública inválida: {public_key}")
                return False
                
            if not seed:
                logger.error("Seed vazia ou None")
                return False
                
            if not output or len(output) != 64:
                logger.error(f"Output VRF inválido: {output}")
                return False
                
            if not proof or len(proof) == 0:
                logger.error("Prova VRF vazia ou None")
                return False
                
            # Conversão da seed para bytes
            seed_bytes = seed.encode('utf-8') if isinstance(seed, str) else seed
            logger.debug(f"Seed em bytes: {seed_bytes[:16].hex()}... (tamanho: {len(seed_bytes)})")
            
            # Conversão da prova para bytes
            logger.debug(f"Convertendo prova hexadecimal: {proof[:32]}...")
            signature = bytes.fromhex(proof)
            logger.debug(f"Prova em bytes: {signature[:16].hex()}... (tamanho: {len(signature)})")
            
            logger.info(f"Verificando VRF: "
                         f"PK={public_key[:16]}... "
                         f"Seed={seed_bytes[:16].hex()}... "
                         f"Output={output[:16]}... "
                         f"Proof={signature[:16].hex()}...")

            # Verificação da consistência do output
            logger.debug("Verificando consistência do output...")
            computed_output = hashlib.sha256(signature).hexdigest()
            if computed_output != output:
                logger.error(f"INCONSISTÊNCIA: Hash da proof não coincide com o output! "
                            f"Esperado: {computed_output}, Recebido: {output}")
                return False
            logger.debug("Consistência do output verificada com sucesso")

            # Verificação da assinatura ECDSA
            logger.debug("Convertendo chave pública...")
            vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
            
            logger.debug("Verificando assinatura ECDSA...")
            is_valid = vk.verify(
                signature, 
                seed_bytes, 
                hashfunc=hashlib.sha256, 
                sigdecode=sigdecode_der
            )
            
            if is_valid:
                logger.info("Verificação VRF bem-sucedida")
            else:
                logger.error("Falha na verificação ECDSA da assinatura")
                
            return is_valid

        except Exception as e:
            logger.error(f"Erro crítico na verificação VRF: {str(e)}", exc_info=True)
            return False

# elect_proposer corrigido
def elect_proposer(nodes, seed, threshold, day_index):
    logger.info(f"Iniciando eleição de propositor. Seed: {seed[:16]}..., Threshold: {threshold}, Dia: {day_index}")
    logger.info(f"Total de participantes: {len(nodes)}")
    
    valid_candidates = []
    invalid_count = 0
    
    if not nodes:
        logger.warning("Nenhum nó participou da eleição")
        return None
    
    for i, (public_key, output, proof) in enumerate(nodes):
        logger.info(f"Processando nó {i+1}/{len(nodes)}: {public_key[:16]}...")
        
        # Verificação robusta de valores vazios (MODIFICADO)
        if not output or not proof or output.strip() == "" or proof.strip() == "":
            logger.warning(f"  ⚠️ VRF inválido: output ou proof vazio")
            logger.debug(f"  Output: {output}, Proof: {proof}")
            invalid_count += 1
            continue
            
        try:
            logger.debug(f"  Convertendo output para bytes...")
            output_bytes = bytes.fromhex(output)
            output_int = int.from_bytes(output_bytes, 'big')
            max_value = (1 << 256) - 1
            normalized = output_int / max_value
            
            logger.debug(f"  VRF {public_key[:10]}... normalizado: {normalized:.6f} (threshold: {threshold})")
            
            if normalized < threshold:
                logger.info(f"  ✅ Candidato válido: {public_key[:16]}... (normalized: {normalized:.6f})")
                valid_candidates.append((public_key, normalized))
            else:
                logger.info(f"  ❌ Normalizado acima do threshold: {normalized:.6f} >= {threshold}")
        except Exception as e:
            logger.error(f"  Erro ao processar VRF: {str(e)}")
            invalid_count += 1
    
  
        else:
            logger.warning(f"  ❌ VRF inválido para {public_key[:16]}...")
            invalid_count += 1
    
    logger.info(f"Candidatos válidos encontrados: {len(valid_candidates)}")
    logger.info(f"Candidatos inválidos: {invalid_count}")
    
    if valid_candidates:
        valid_candidates.sort(key=lambda x: x[1])
        winner = valid_candidates[0][0]
        logger.info(f"Propositor eleito: {winner[:16]}... com normalized: {valid_candidates[0][1]:.6f}")
        return winner
    
    logger.warning("Nenhum candidato válido, usando fallback aleatório")
    if nodes:
        winner = random.choice([node[0] for node in nodes])
        logger.warning(f"Propositor escolhido aleatoriamente: {winner[:16]}...")
        return winner
    
    logger.error("Nenhum nó disponível para fallback!")
    return None