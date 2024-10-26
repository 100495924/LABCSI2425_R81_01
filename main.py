"""
- Terminar la gestión de contraseñas.
- hasheo de contraseñas.
- almacenar los datos (json).
- cifrado y autenticado.
Cada usuario con su key, que servirá para extraer y descifrar sus datos del json master
"""

import os
import random
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class BankUser:
    def __init__(self, doc_id, nombre, apellidos, pwd, direccion, credito):
        self.doc_id = doc_id
        self.nombre = nombre
        self.apellidos = apellidos
        self.direccion = direccion
        self.credito = credito

        # Investigar si los salt pueden coincidir con urandom()
        self.salt = os.urandom(16)
        self.pwd_hash = hash(pwd)  # Habrá que usar un hash de la librería Scrypt.
        generated_bank_num = str(random.randint(1000000000000000000000, 9999999999999999999999))
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
            # Revisar el formato de la contraseña.
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
        # Autenticar usuario.
        kdf = Scrypt(
            salt=bank_user.salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )

        key = kdf.derive(user_pwd)

        self.users.append(bank_user)
        return bank_user


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
            # esto ta mal >:V, usar try: kdf.verify() para ello (manejando excepciones)
            if hash(login_pwd) == user_to_login.pwd_hash:   # Sustituir hash()
                print("¡Bienvenido de vuelta!")
                pwd_loop = False
            else:
                print("¡Contraseña incorrecta!")
        return user_to_login


    def bank_loop(self):
        user_bank = None
        bank_loop = True

        while bank_loop:
            print("¿Qué quieres hacer?\n"
                  "1_Registrar una cuenta\n"
                  "2_Entrar a una cuenta\n"
                  "3_Salir")
            user_input = input("")

            if user_input == "1":
                user_bank = self.register()
                self.user_space_loop(user_bank)
            elif user_input == "2":
                user_bank = self.log_in()
                self.user_space_loop(user_bank)

            elif user_input == "3":
                bank_loop = False


        print("¡Hasta la próxima!")

    def user_space_loop(self, user):
        user_space_loop = True

        while user_space_loop:
            print("¿Qué quieres hacer?\n"
                  "1_Gestionar mi dinero\n"
                  "2_Revisar tus datos\n"
                  "3_Sacar certificado\n"
                  "4_Cerrar la sesión")
            user_input = input("")

            if user_input == "1":
                # Gestionar dinero
                print("Gestionar dinero")
            elif user_input == "2":
                # Revisar datos.
                print("Revisar datos")
            elif user_input == "3":
                # Sacar certificado.
                print("Sacar certificado")
            elif user_input == "4":
                # Cerrar la sesión.
                user_space_loop = False
            else:
                print("Opción inválida.")

    def money_loop(self, user):
        money_loop = True

        while money_loop:
            print("Crédito: {}".format(user.credito))
            print("¿Qué quieres hacer con tú dinero?\n"
                  "1_Sacar dinero de mi cuenta\n"
                  "2_Meter dinero a mi cuenta\n"
                  "3_Atrás")
            user_input = input("")

            if user_input == "1":
                dinero_a_sacar = int(input("¿Cuánto dinero quieres sacar? "))
                if user.credito - dinero_a_sacar >= 0:
                    print("Has sacado {} €".format(dinero_a_sacar))
                    user.credito -= dinero_a_sacar
                else:
                    print("No puedes sacar más dinero del que tienes.")
            elif user_input == "2":
                dinero_a_meter = int(input("¿Cuánto dinero quieres meter?"))
                print("Has metido {} €".format(dinero_a_meter))
                user.credito += dinero_a_meter
            elif user_input == "3":
                money_loop = False
            else:
                print("Opción inválida")





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