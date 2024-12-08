import base64
import json

from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone


class InvalidCertificate(Exception):
    pass


class JsonFile:
    def __init__(self, path):
        self.file_path = path


class JsonUserDatabase(JsonFile):
    def create_user_json(self, user_dict: dict) -> None:
        """Añade un nuevo usuario al archivo json"""

        # Abrir en modo read and write
        with open(self.file_path, "r+", encoding="utf-8") as open_file:
            # Almacenar el contenido del json en una variable
            json_data = json.load(open_file)
            # Eliminar el contenido del archivo
            open_file.seek(0)
            open_file.truncate(0)
            # Añadir el usuario a la lista de usuarios del json
            json_data.append(user_dict)
            # Escribir el contenido de la variable en el archivo
            json.dump(json_data, open_file, indent=4)

        open_file.close()

    def search_user_json(self, key, value) -> dict | None:
        """Buscar el usuario que contenga el valor (key, value) si existe"""

        # Abrir el archivo en modo read only
        with open(self.file_path, "r", encoding="utf-8") as open_file:
            json_data = json.load(open_file)

        # Recorre todos los usuarios en busca de un match y lo devuelve al encontrarlo
        for user in json_data:
            if user[key] == value:
                open_file.close()
                return user

        # No se encontró un usuario con esas características
        open_file.close()
        return None

    def delete_user_json(self, user_dict: dict) -> None:
        """Elimina un usuario con todos sus datos del archivo json"""

        with open(self.file_path, "r+", encoding="utf-8") as open_file:
            json_data = json.load(open_file)
            # Eliminar el contenido del archivo
            open_file.seek(0)
            open_file.truncate(0)

            # Añadir a la lista todos los usuarios excepto el que hay que eliminar
            new_json = []
            for user in json_data:
                if user["BankNum"] != user_dict["BankNum"]:
                    new_json.append(user)

            json.dump(new_json, open_file, indent=4)

        open_file.close()

    def update_user_json(self, user_dict: dict, keys: list) -> None:
        """Actualizar los datos del usuario especificados en keys cuando este modifica sus datos"""

        # Abrir en modo read and write
        with open(self.file_path, "r+", encoding="utf-8") as open_file:
            json_data = json.load(open_file)
            # Eliminar el contenido del archivo
            open_file.seek(0)
            open_file.truncate(0)

            for user in json_data:
                if user["BankNum"] == user_dict["BankNum"]:
                    for key in keys:
                        user[key] = user_dict[key]

            json.dump(json_data, open_file, indent=4)

        open_file.close()


class JsonKeyRing(JsonFile):
    def insert_dict_json(self, dict_to_insert: dict) -> None:
        """Transforma el diccionario dado en el contenido del archivo json"""

        # Abrir en modo read and write (crear archivo si no existe, si existe truncarlo)
        with open(self.file_path, "w+", encoding="utf-8") as open_file:
            json.dump(dict_to_insert, open_file, indent=4)

        open_file.close()

    def load_public_key(self):
        """Devuelve la clave pública deserializada"""

        with open(self.file_path, "r", encoding="utf-8") as open_file:
            key_pem_dict = json.load(open_file)

        key_pem_bytes = base64.b64decode(key_pem_dict["public_key"])
        key_pem = load_pem_public_key(key_pem_bytes)

        return key_pem

    def load_private_key(self, pwd):
        """Devuelve la clave privada deserializada"""

        with open(self.file_path, "r", encoding="utf-8") as open_file:
            key_pem_dict = json.load(open_file)

        key_pem_bytes = base64.b64decode(key_pem_dict["private_key"])
        key_pem = load_pem_private_key(key_pem_bytes, pwd)

        return key_pem

    def load_certs(self):
        """ Devuelve el certificado del sistema, junto con los certificados
        que forman parte de la cadena de certificación."""
        with open("./PKI_infrastructure/System_cert/System_cert.pem", "rb") as f:
            pem_data = f.read()

        with open("./PKI_infrastructure/System_cert/certs.pem", "rb") as f:
            certs_pem_data = f.read()

        system_cert = x509.load_pem_x509_certificate(pem_data)
        acs_certs = x509.load_pem_x509_certificates(certs_pem_data)

        return system_cert, acs_certs

    def verificar_cadena_certificacion(self, system_cert: Certificate, acs_certs: list[Certificate]):
        """ Verifica toda la cadena de certificación del certificado incluido el del sistema. """
        # Añadir verificaciones de la validez del periodo, si el emisor tiene permitido emitir
        # certificados, si el certificado del emisor tiene una clave pública lo suficientemente
        # fuerte, etc.

        if system_cert.public_key().key_size < 2048:
            raise InvalidCertificate("[ERROR] Este certificado no tiene una longitud de clave adecuada.")

        local_time = datetime.now(timezone.utc)
        # Revisar el periodo del certificado.
        if local_time < system_cert.not_valid_before_utc or local_time > system_cert.not_valid_after_utc:
            raise InvalidCertificate("[ERROR] El periodo del certificado no es válido.")

        for cert in acs_certs:
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise InvalidCertificate(
                    "[ERROR] Los emisores de este certificado no tienen permisos para emitir certificados.")
            if cert.public_key().key_size < 2048:
                raise InvalidCertificate(
                    "[ERROR] Los certificados de los emisores no tienen una longitud de clave adecuada.")
            if local_time < cert.not_valid_before_utc or local_time > cert.not_valid_after_utc:
                raise InvalidCertificate("[ERROR] Los certificados de los emisores no tienen un periodo válido.")

        # Verificar la firma del certificado del banco con la clave pública de la AC LvL 1 Banko Moderno.
        acs_certs[1].public_key().verify(
            system_cert.signature,
            system_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            system_cert.signature_hash_algorithm,
        )

        # Verificamos la firma del certificado de la AC LvL 1 Banko Moderno.
        # ACs_certs[1].verify_directly_issued_by(ACs_certs[0])
        acs_certs[0].public_key().verify(
            acs_certs[1].signature,
            acs_certs[1].tbs_certificate_bytes,
            padding.PKCS1v15(),
            acs_certs[1].signature_hash_algorithm,
        )

        # Verificar firma de AC Root también
        acs_certs[0].public_key().verify(
            acs_certs[0].signature,
            acs_certs[0].tbs_certificate_bytes,
            padding.PKCS1v15(),
            acs_certs[0].signature_hash_algorithm,
        )

        # No verificamos el certificado de la AC Root Banko moderno ya que es la AC raíz y
        # elegimos confiar en ella.