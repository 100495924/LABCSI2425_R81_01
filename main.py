import os
import random

class BankUser:
    def __init__(self, doc_id, nombre, apellidos, pwd, direccion, credito):
        self.doc_id = doc_id
        self.nombre = nombre
        self.apellidos = apellidos
        self.direccion = direccion
        self.credito = credito

        self.salt = os.urandom(16)
        self.pwd_hash = hash(pwd)  # Habrá que usar un hash de la librería Scrypt.
        generated_bank_num = str(random.randint(0, 9999999999999999999999))
        # Verificar que el número del banco que se va a generar no existe.
        self.bank_num = "ES" + generated_bank_num


class BankInstance:
    def __init__(self):

        self.users = []     # Todos los usuarios que el sistema maneja.

    def search_user(self, user_doc_id):
        for i in range(len(self.users)):
            user = self.users[i]
            if user.doc_id == user_doc_id:
                return user
            return None




    def register(self):
        # Verificar que no hay ya un usuario con los mismos datos.
        print("Registrando\n"
              "Inserte sus datos:\n"
              "Número de identidad: ")
        doc_id_user = input("")
        print("Nombre: ")
        nombre_user = input("")
        print("Apellidos: ")
        apellido_user = input("")
        print("Dirección: ")
        direccion_user = input("")
        print("Inserta tu saldo inicial: ")
        credito_user = int(input(""))

        pwd_loop = True
        while pwd_loop:
            print("Escribe tu contraseña: ")
            user_pwd = input("")
            print("Repite la contraseña: ")
            user_pwd_repeat = input("")
            if user_pwd != user_pwd_repeat:
                print("Las contraseñas no coinciden.")
            else:
                print("Usuario registrado con éxito.")
                pwd_loop = False

        bank_user = BankUser(doc_id_user, nombre_user, apellido_user, user_pwd,
                             direccion_user, credito_user)
        self.users.append(bank_user)


    def log_in(self):
        user_to_login = None
        print("Logueando\n"
              "Introduce tus datos de inicio de sesión:\n")
        doc_id_loop = True
        while doc_id_loop:
            login_doc_id = input("Documento de Identidad: \n")
            user_to_login = self.search_user(login_doc_id)
            if user_to_login is None:
                print("¡Cuenta no encontrada!")
            else:
                doc_id_loop = False

        pwd_loop = True
        while pwd_loop:
            login_pwd = input("Contraseña: \n")
            if hash(login_pwd) == user_to_login.pwd_hash:   # Sustituir hash()
                print("¡Bienvenido de vuelta!")
                pwd_loop = False
            else:
                print("¡Contraseña incorrecta!")


    def bank_loop(self):
        account_loop = True
        logued_in_loop = True

        while account_loop:
            print("¿Qué quieres hacer?\n"
                  "1_Registrar una cuenta\n"
                  "2_Entrar a una cuenta\n"
                  "3_Salir")
            user_input = input("")

            if user_input == "1":
                self.register()
            elif user_input == "2":
                self.log_in()
            elif user_input == "3":
                account_loop = False
                logued_in_loop = False

        """
        while logued_in_loop:
            print("¿Qué quieres hacer con tu dinero?\n"
                  "Crédito: {}".format(credito))
        """
        print("¡Hasta la próxima!")


banko = BankInstance()
banko.bank_loop()


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