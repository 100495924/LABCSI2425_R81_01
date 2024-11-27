import base64
import json

from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


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
