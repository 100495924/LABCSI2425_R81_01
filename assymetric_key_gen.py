import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from json_manager import JsonKeyRing

################## ATENCIÓN CLAVE MAESTRA ESCRITA EN EL CÓDIGO ##################################
ASSYMETRIC_KEYS_PWD = b"100495924_100495839"

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

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Generamos el CSR para que sea firmado por la AC de nuestro banco.
system_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Información sobre esta sucursal.
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Banko Moderno S.L."),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Banko Moderno Entidad Central"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Banko Moderno"),
])).sign(private_key, hashes.SHA256())

# Write our CSR out to disk.
with open("./PKI_infrastructure/System_cert/System_req.pem", "wb") as f:
    f.write(system_csr.public_bytes(serialization.Encoding.PEM))
