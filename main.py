class bank_user:
    def __init__(self, doc_id, bank_num, nombre, apellidos, salt, pwd_hash, direccion, credito):
        self.doc_id = doc_id
        self.bank_num = bank_num
        self.nombre = nombre
        self.apellidos = apellidos
        self.salt = salt
        self.pwd_hash = pwd_hash
        self.direccion = direccion
        self.credito = credito


class Bank:
    def register(self):
        print("Registrando\n"
              "Inserte sus datos:\n"
              "Número de identidad: \n")
        doc_id = input("")




    def log_in(self):
        print("Logueando")

    def bank_loop(self):
        account_loop = True
        logued_in_loop = True

        while account_loop:
            print("¿Qué quieres hacer?\n"
                  "1_Registrar una cuenta\n"
                  "2_Entrar a una cuenta\n"
                  "3_Salir\n")
            user_input = input("")

            if user_input == "1":
                self.register()
            elif user_input == "2":
                self.log_in()
            elif user_input == "3":
                account_loop = False
                logued_in_loop = False

        while logued_in_loop:
            print("¿Qué quieres hacer con tu dinero?\n"
                  "Crédito: {}".format(credito))

        print("¡Hasta la próxima!")


bank_loop()


"""
Para el registro y logueo del usuario se usará Scrypt, para almacenar las 
contraseñas de los usuarios.

Código ejemplo: 
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
salt = os.urandom(16)
# Registro
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
key = kdf.derive(b"my great password")  <-- NO ESCRIBIR CONTRASEÑAS EN EL CÓDIGO
# Logueo
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
Al verificar la contraseña, es bueno usar excepciones (try) para 
avisar al usuario en el caso de que la contraseña que ha 
introducido en el login no coincide con su contraseña ya registrada.
kdf.verify(b"my great password", key)
"""