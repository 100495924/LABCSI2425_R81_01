import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from json_manager import JsonKeyRing

################## ATENCIÓN CLAVE MAESTRA ESCRITA EN EL CÓDIGO ##################################
ASSYMETRIC_KEYS_PWD = b"100495924_100495839"

"""MASTER_SALT = b';\x16\xdeW\x19~\xcc\x96\x7f\xa2&\x9d\x1a/%:'
kdf = Scrypt(
    salt=MASTER_SALT,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
ASSYMETRIC_KEYS_ENCRYPTION_KEY = kdf.derive(ASSYMETRIC_KEYS_PWD)"""
###################### RECONOCEMOS LA MALA PRÁCTICA DE AQUÍ #####################################

# Creamos un archivo Json para guardar el par de claves.
jsonKeyring = JsonKeyRing("pem_keys.json")

# Creamos un par de claves RSA.
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serializando clave privada.
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(ASSYMETRIC_KEYS_PWD)
)

# Serializando clave pública.
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

pem_dict = {"public_key": base64.b64encode(public_pem).decode('utf-8'),
            "private_key": base64.b64encode(private_pem).decode('utf-8')}

# Guardar el par de claves en el fichero json.
jsonKeyring.insert_dict_json(pem_dict)
