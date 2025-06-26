import json
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger('Validator')

def validate_incoming_data(data):
    """Valida dados simplificados (sem readings)"""
    # Campos obrigatórios simplificados
    required_fields = ['public_address', 'timestamp', 'total_kwh', 'signature']
    for field in required_fields:
        if field not in data:
            logger.error(f"Campo faltando: {field}")
            return False

    # Valida assinatura digital (sem readings)
    return validate_signature(
        public_key=data['public_address'],
        message=data,
        signature=data['signature']
    )
def validate_signature(public_key, message, signature):
    """
    Valida uma assinatura ECDSA usando curva secp256k1
    """
    try:
        # Remove a assinatura para verificação
        message_to_verify = {k: v for k, v in message.items() if k != 'signature'}
        message_str = json.dumps(message_to_verify, sort_keys=True)
        message_bytes = message_str.encode('utf-8')
        
        # Carrega a chave pública
        public_key_bytes = bytes.fromhex(public_key)
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), 
            public_key_bytes
        )
        
        # Verifica assinatura
        key.verify(
            bytes.fromhex(signature),
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        logger.warning("Assinatura inválida")
        return False
    except Exception as e:
        logger.error(f"Erro na verificação de assinatura: {str(e)}")
        return False