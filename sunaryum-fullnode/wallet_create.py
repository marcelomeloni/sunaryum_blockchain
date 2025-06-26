from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
import hashlib
import hmac

# Gera uma nova carteira
mnemo = Mnemonic('english')
seed_phrase = mnemo.generate(strength=128)  # 12 palavras

# Deriva a chave privada
seed_bytes = mnemo.to_seed(seed_phrase, passphrase="")
derived_key = hmac.new(b"SunaryumDerivation", seed_bytes, hashlib.sha512).digest()
private_key_bytes = derived_key[:32]

# Converte para objetos ECDSA
priv_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
pub_key = priv_key.get_verifying_key()

# Formata as chaves
private_key_hex = priv_key.to_string().hex()
public_key_hex = pub_key.to_string("compressed").hex()
address = hashlib.sha256(pub_key.to_string()).hexdigest()[:40]

print("SEED PHRASE (Guarde com segurança!):")
print(seed_phrase)
print("\nCONFIG.INI:")
print(f"[Node]")
print(f"wallet_address = {address}")
print(f"private_key = {private_key_hex}")