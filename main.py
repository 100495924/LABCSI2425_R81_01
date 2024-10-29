"""
- Terminar la gestión de contraseñas.
- hasheo de contraseñas.
- almacenar los datos (json).
- cifrado y autenticado.
Cada usuario con su key, que servirá para extraer y descifrar sus datos del json master
"""

import os
import random
import re
import json
import base64
from email.errors import InvalidDateDefect

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_PWD = b"Patata_96"
MASTER_SALT = b';\x16\xdeW\x19~\xcc\x96\x7f\xa2&\x9d\x1a/%:'
kdf = Scrypt(
    salt=MASTER_SALT,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
MASTER_KEY = kdf.derive(MASTER_PWD)


class InvalidDataError(Exception):
    pass


class BankInstance:
    def __init__(self):
        pass

    # FUNCIONES RELATIVAS AL BANK_LOOP

    def bank_loop(self):
        """Menú inicial, relativo a la creación y acceso de cuentas"""
        bank_loop = True

        print("*** ¡BIENVENIDO/A AL BANKO MODERNO! ***")
        print("Fundado por Adrian y María en 2024")

        while bank_loop:
            print("\n¿Qué quieres hacer?\n"
                  "1_Registrar una cuenta\n"
                  "2_Iniciar sesión\n"
                  "3_Salir")
            user_input = input("")

            if user_input == "1":
                user = self.register()
                # Si al registrarse se introduce un documento de identidad no correspondiente a un usuario ya existente
                if user is not None:
                    self.user_space_loop(user)
            elif user_input == "2":
                user = self.log_in()
                if user == -1:
                    print("(!) Se hicieron demasiados intentos incorrectos. Inténtalo de nuevo más tarde.")
                    return
                # Si el usuario le da a enter, sale del proceso de log in
                elif user != 0:
                    self.user_space_loop(user)
            elif user_input == "3":
                # Salir
                bank_loop = False
            else:
                print("(!) Opción inválida")

        print("¡Hasta la próxima!")

    def register(self):
        print("\nRegistrando\n"
              "Inserta tus datos")

        doc_id_user = self.validate_doc_id()
        if doc_id_user is None:
            return None

        nombre_user = self.validate_campo_obligatorio("\nNombre:\n", False)
        apellido_user = self.validate_campo_obligatorio("\nApellidos:\n", False)
        email_user = self.validate_email()

        print("\nDirección:")

        dir_calle = self.validate_campo_obligatorio("\t- Calle: ", False)
        dir_numero = self.validate_campo_obligatorio("\t- Número: ", True)
        dir_piso, dir_puerta = self.validate_piso_puerta()
        dir_codigo_postal = self.validate_campo_obligatorio("\t- Código postal: ", True)
        dir_localidad = self.validate_campo_obligatorio("\t- Localidad: ", False)
        dir_provincia = self.validate_campo_obligatorio("\t- Provincia: ", False)
        dir_pais = self.validate_campo_obligatorio("\t- País: ", False)

        # Se construye un único string de "dirección" que contenga los datos introducidos anteriormente
        if dir_piso != "" and dir_puerta != "":
            direccion_user = (f"Calle {dir_calle}, {dir_numero}, {dir_piso}-{dir_puerta}, "
                              f"{dir_codigo_postal}, {dir_localidad}, {dir_provincia}, {dir_pais}")
        else:
            direccion_user = (f"Calle {dir_calle}, {dir_numero}, {dir_codigo_postal}, {dir_localidad}, "
                              f"{dir_provincia}, {dir_pais}")

        user_pwd = self.validate_pwd("\nEscribe tu contraseña: ")
        credito_user = int(self.validate_campo_obligatorio("\nInserta tu saldo inicial:\n", True))

        # Se genera un diccionario a partir de los datos introducidos
        user = self.generate_user_dict(doc_id_user, nombre_user, apellido_user, email_user,
                                       direccion_user, user_pwd, credito_user)
        # Se añade el nuevo usuario al sistema
        self.create_user_json(user)

        print("\n** ¡Usuario registrado con éxito! **")
        print("Número de cuenta asignado:", user["BankNum"])

        return user

    def validate_doc_id(self):
        doc_id_loop = True
        while doc_id_loop:
            doc_id_user = input("\nDNI o NIE:\n")
            if doc_id_user == "":
                print("(!) Campo obligatorio")
            elif not self.check_regex_doc_id(doc_id_user):
                print("(!) Documento inválido")
            elif self.search_user_json("DocID", doc_id_user) is not None:
                print("(!) Parece que ya tienes una cuenta con nosotros")
                return None
            else:
                doc_id_loop = False
        return doc_id_user

    def check_regex_doc_id(self, doc_id_user):
        # Validar formato
        regex_dni = re.compile(r'^[0-9]{8}[A-Z]{1}$')
        regex_nie = re.compile(r'^[XYZ]{1}[0-9]{7,8}[A-Z]{1}$')

        regex_matches_dni = regex_dni.fullmatch(doc_id_user)
        regex_matches_nie = regex_nie.fullmatch(doc_id_user)

        if not regex_matches_dni and not regex_matches_nie:
            return False

        # Validad caracter de control
        valid_characters = {"0": "T", "1": "R", "2": "W", "3": "A", "4": "G", "5": "M",
                            "6": "Y", "7": "F", "8": "P", "9": "D", "10": "X", "11": "B",
                            "12": "N", "13": "J", "14": "Z", "15": "S", "16": "Q", "17": "V",
                            "18": "H", "19": "L", "20": "C", "21": "K", "22": "E"}

        if regex_matches_dni:
            id_number = int(doc_id_user[0:8])
        elif len(doc_id_user) == 9:
            id_number = int(doc_id_user[1:8])
        else:
            id_number = int(doc_id_user[1:9])

        id_module = str(id_number % 23)

        if doc_id_user[-1] != valid_characters[id_module]:
            return False

        return True

    def validate_campo_obligatorio(self, mensaje_input: str, is_numerico: bool):
        loop = True
        while loop:
            input_user = input(mensaje_input)
            if input_user == "":
                print("(!) Campo obligatorio")
            elif is_numerico:
                try:
                    int(input_user)
                    loop = False
                except ValueError:
                    print("(!) No se ha introducido un número")
            else:
                loop = False

        return input_user

    def validate_email(self) -> str:
        email_loop = True
        while email_loop:
            email_user = input("\nEmail:\n")
            if email_user == "":
                print("(!) Campo obligatorio")
            elif not self.check_regex_email(email_user):
                print("(!) Email electrónico inválido, debe seguir el formato nombre@dominio.net")
            else:
                email_loop = False
        return email_user

    def check_regex_email(self, email_user: str) -> bool:
        regex_email = re.compile(r'^.+@.+[.].+$')
        regex_matches_email = regex_email.fullmatch(email_user)
        return regex_matches_email

    def validate_piso_puerta(self) -> tuple:
        dir_piso_puerta_loop = True
        while dir_piso_puerta_loop:
            dir_piso = input("\t- Piso (si aplica): ")
            # El piso debe ser un número
            try:
                int(dir_piso)
                dir_puerta = input("\t- Puerta (si aplica): ")
                if (dir_piso != "" and dir_puerta != "") or (dir_piso == "" and dir_puerta == ""):
                    dir_piso_puerta_loop = False
                else:
                    print("(!) Los campos Piso y Puerta deben estar ambos rellenos o ambos vacíos")
            except ValueError:
                print("(!) No se ha introducido un número")

        return dir_piso, dir_puerta

    def validate_pwd(self, msg_print: str) -> str:
        pwd_loop = True
        while pwd_loop:
            print(msg_print)
            print("Debe contener al menos 12 caracteres, incluyendo:")
            print("\t- 1 mayúscula\n \t- 1 minúscula\n \t- 1 número\n \t- 1 caracter especial")

            user_pwd = input("")
            output_validate_pwd = self.check_regex_pwd(user_pwd)

            if output_validate_pwd == "":
                user_pwd_repeat = input("Repite la contraseña:\n")
                if user_pwd != user_pwd_repeat:
                    print("(!) Las contraseñas no coinciden.\n")
                else:
                    pwd_loop = False
            elif output_validate_pwd == "length":
                print("(!) Contraseña inválida. Debe tener una longitud mínima de 12 caracteres\n")
            else:
                print("(!) Contraseña inválida. No contiene al menos 1 " + output_validate_pwd + "\n")

        return user_pwd

    def check_regex_pwd(self, user_pwd: str) -> str:
        # Validar longitud
        if len(user_pwd) < 12:
            return "length"

        # Validar la inclusión de ciertos caracteres
        regex_mayuscula = r'[A-Z]'
        regex_minuscula = r'[a-z]'
        regex_numero = r'[0-9]'
        regex_especial = r'[!"#$%&\'()*+,-./:;<=>?@\[\]^_`{|}~]'

        if re.search(regex_mayuscula, user_pwd) is None:
            return "mayúscula"
        elif re.search(regex_minuscula, user_pwd) is None:
            return "minúscula"
        elif re.search(regex_numero, user_pwd) is None:
            return "número"
        elif re.search(regex_especial, user_pwd) is None:
            return "caracter especial"

        return ""

    def log_in(self) -> dict | int:
        """Devuelve un diccionario con los datos del usuario si se loguea con éxito, 0 si se cancela la operación,
        -1 si se termina el número de intentos para introducir una contraseña"""
        user_to_login = None

        print("\nLogueando\n"
              "Introduce tus datos de inicio de sesión\n"
              "(para ir atrás, presiona enter en cualquier momento)\n")

        doc_id_loop = True
        while doc_id_loop:
            login_doc_id = input("Documento de Identidad: \n")
            # El usuario presiona enter
            if login_doc_id == "":
                return 0
            # Se chequea si existe algún usuario registrado con ese documento de identidad
            user_to_login = self.search_user_json("DocID", login_doc_id)
            if user_to_login is None:
                print("(!) ¡Cuenta no encontrada!")
            else:
                doc_id_loop = False

        pwd_loop = True
        num_intentos = 3
        while pwd_loop and num_intentos > 0:
            login_pwd = input("\nContraseña: \n")
            # El usuario presiona enter
            if login_pwd == "":
                return 0

            # Se verifica que la contraseña coincide
            # Para ello, usamos la salt almacenada en el json asociada a ese usuario
            kdf = Scrypt(
                salt=base64.b64decode(user_to_login["Salt"]),
                length=32,
                n=2 ** 14,
                r=8,
                p=1,
            )
            # Coincide
            try:
                kdf.verify(login_pwd.encode(), base64.b64decode(user_to_login["Pwd"]))
                print("¡Bienvenido de vuelta!")
                pwd_loop = False
            # No coincide
            # Al alcanzar el máximo número de intentos, se finaliza la ejecución de la app
            except InvalidKey:
                num_intentos -= 1
                if num_intentos > 1:
                    print(f"(!) ¡Contraseña incorrecta! Te quedan {num_intentos} intentos")
                elif num_intentos == 1:
                    print(f"(!) ¡Contraseña incorrecta! Te queda {num_intentos} intento")

        # Intentos agotados
        if num_intentos == 0:
            return -1

        return user_to_login

    def decrypt_data(self, user: dict, data_key: str):
        """ Función para desencriptar un dato del usuario"""
        data_nonce_key = data_key + "Nonce"
        try:
            if data_key not in user.keys():
                raise InvalidDataError("The data_key is not in the user")
        except InvalidDataError:
            raise

        # Primero hay que desencriptar la clave del usuario.
        master_aesgcm = AESGCM(MASTER_KEY)
        user_key_nonce = base64.b64decode(user["UserKeyNonce"])
        user_key_ciphertext = base64.b64decode(user["UserKey"])
        user_key = master_aesgcm.decrypt(user_key_nonce, user_key_ciphertext, None)

        # Ya podemos desencriptar el dato del usuario que necesitamos.
        user_aesgcm = AESGCM(user_key)
        data_nonce = base64.b64decode(user[data_nonce_key])
        data_ciphertext = base64.b64decode(user[data_key])
        data = user_aesgcm.decrypt(data_nonce, data_ciphertext, None)

        # Volvemos a encriptar el dato con un nuevo nonce.
        new_data_nonce = os.urandom(12)
        new_data_ciphertext = user_aesgcm.encrypt(new_data_nonce, data, None)
        user[data_nonce_key] = base64.b64encode(new_data_nonce).decode('utf-8')
        user[data_key] = base64.b64encode(new_data_ciphertext).decode('utf-8')

        # Actualizamos los valores del json.
        self.update_user_json(user, [data_key, data_nonce_key])

        return data

    def modify_cipher_data(self, user: dict, data_key: str, new_data_val):
        """Encriptar el dato nuevo con un nuevo nonce y sustituir los
        valores respectivos del user"""
        """ Función para modificar un dato cifrado del usuario."""
        data_nonce_key = data_key + "Nonce"
        try:
            if data_key not in user.keys():
                raise InvalidDataError("The data_key is not in the user")
        except InvalidDataError:
            raise

        # Primero hay que desencriptar la clave del usuario.
        master_aesgcm = AESGCM(MASTER_KEY)
        user_key_nonce = base64.b64decode(user["UserKeyNonce"])
        user_key_ciphertext = base64.b64decode(user["UserKey"])
        user_key = master_aesgcm.decrypt(user_key_nonce, user_key_ciphertext, None)

        # Generamos nuevo nonce.
        new_data_nonce = os.urandom(12)
        user_aesgcm = AESGCM(user_key)

        # Encriptamos el dato modificado.
        new_data_ciphertext = user_aesgcm.encrypt(new_data_nonce, (str(new_data_val)).encode(encoding='utf-8'), None)

        #Cambiamos los valores en el usuario.
        user[data_nonce_key] = base64.b64encode(new_data_nonce).decode('utf-8')
        user[data_key] = base64.b64encode(new_data_ciphertext).decode('utf-8')

        # Actualizamos los valores del json.
        self.update_user_json(user, [data_key, data_nonce_key])

    # FUNCIONES RELATIVAS AL USER_SPACE_LOOP

    def user_space_loop(self, user: dict) -> None:
        """Menú que aparece una vez el usuario se registra o inicia sesión"""
        user_space_loop = True

        while user_space_loop:
            print("\n¿Qué quieres hacer?\n"
                  "1_Gestionar mi dinero\n"
                  "2_Revisar mis datos\n"
                  "3_Sacar certificado\n"
                  "4_Eliminar cuenta\n"
                  "5_Cerrar sesión")
            user_input = input("")

            if user_input == "1":
                self.money_loop(user)
            elif user_input == "2":
                print("\nRevisar datos")
                revisar_out = self.revisar_datos(user)
                # Se introdujo la contraseña incorrecta demasiadas veces, se cierra la sesión para proteger la cuenta
                if revisar_out == -1:
                    user_space_loop = False
            elif user_input == "3":
                print("\nSacar certificado (futura funcionalidad)")
            elif user_input == "4":
                user_space_loop = self.eliminar_cuenta(user)
            elif user_input == "5":
                # Cerrar sesión
                user_space_loop = False
            else:
                print("(!) Opción inválida\n")

    def eliminar_cuenta(self, user: dict) -> bool:
        confirmacion_input = input("¿Estás seguro/a de que quieres eliminar tu cuenta? (s/n) ")
        if confirmacion_input == "s":
            print("Eliminando cuenta...")
            self.delete_user_json(user)
            print("Cuenta eliminada con éxito")
            return False
        return True

    def money_loop(self, user: dict) -> None:
        """Menú para gestionar el dinero de la cuenta"""
        money_loop = True

        while money_loop:
            # Desencriptamos la información referente al crédito del usuario.
            user_credito = int(self.decrypt_data(user, "Credito"))
            print(f"\nCrédito actual: {user_credito}€")
            print("¿Qué quieres hacer con tu dinero?\n"
                  "1_Sacar dinero de mi cuenta\n"
                  "2_Meter dinero a mi cuenta\n"
                  "3_Atrás")
            user_input = input("")

            if user_input == "1":
                self.sacar_dinero(user, user_credito)
            elif user_input == "2":
                self.meter_dinero(user, user_credito)
            elif user_input == "3":
                money_loop = False
            else:
                print("(!) Opción inválida")

    def sacar_dinero(self, user: dict, credito: int) -> None:
        sacar_loop = True
        while sacar_loop:
            dinero_a_sacar = input("\n¿Cuánto dinero quieres sacar? \n(para cancelar la operación, presiona enter)\n")
            if dinero_a_sacar == "":
                sacar_loop = False
            else:
                try:
                    dinero_a_sacar = int(dinero_a_sacar)
                    if credito - dinero_a_sacar >= 0:
                        credito -= dinero_a_sacar
                        self.modify_cipher_data(user, "Credito", str(credito))
                        print(f"Has sacado {dinero_a_sacar}€")
                        sacar_loop = False
                    else:
                        print("(!) No puedes sacar más dinero del que tienes")
                except ValueError:
                    print("(!) No se ha introducido un número")

    def meter_dinero(self, user: dict, credito: int) -> None:
        meter_loop = True
        while meter_loop:
            dinero_a_meter = input("\n¿Cuánto dinero quieres meter? \n(para cancelar la operación, presiona enter)\n")
            if dinero_a_meter == "":
                meter_loop = False
            else:
                try:
                    dinero_a_meter = int(dinero_a_meter)
                    credito += dinero_a_meter
                    self.modify_cipher_data(user, "Credito", credito)
                    print(f"Has metido {dinero_a_meter}€")
                    meter_loop = False
                except ValueError:
                    print("(!) No se ha introducido un número")

    def revisar_datos(self, user: dict):
        revisar_datos_loop = True
        while revisar_datos_loop:
            user_email = self.decrypt_data(user, "Email").decode('utf-8')
            user_direccion = self.decrypt_data(user, "Direccion").decode('utf-8')
            user_credito = self.decrypt_data(user, "Credito").decode('utf-8')
            print("\nEstos son los datos que guardamos de ti:\n"
                  f"Número de cuenta*: {user['BankNum']}\n"
                  f"DNI/NIE*: {user['DocID']}\n"
                  f"Nombre: {user['Nombre']}\n"
                  f"Apellidos: {user['Apellidos']}\n"
                  f"Email: {user_email}\n"
                  f"Dirección: {user_direccion}\n"
                  f"Credito*: {user_credito}€\n"
                  "Contraseña: **********\n"
                  "NOTA: Los datos marcados con '*' no se "
                  "podrán modificar.")
            dato_a_modificar = input("\n¿Quieres modificar algún dato? \n(para cancelar la operación, presiona enter)\n")
            if dato_a_modificar == "":
                revisar_datos_loop = False
            elif dato_a_modificar.lower() == "nombre":
                self.modificar_nombre(user)
            elif dato_a_modificar.lower() == "apellidos":
                self.modificar_apellidos(user)
            elif dato_a_modificar.lower() == "email":
                self.modificar_email(user)
            elif dato_a_modificar.lower() == "direccion":
                self.modificar_direccion(user)
            elif dato_a_modificar.lower() == "contraseña":
                modificar_contraseña_out = self.modificar_contraseña(user)
                if modificar_contraseña_out == -1:
                    return -1
            else:
                print("(!) No se ha introducido un nombre de campo válido.")

    def modificar_nombre(self, user: dict):
        modificar_nombre_loop = True
        while modificar_nombre_loop:
            nuevo_valor = input(
                "\nInserta el nuevo valor para Nombre: \n(para cancelar la operación, presiona enter)\n")
            if nuevo_valor == "":
                modificar_nombre_loop = False
            else:
                user["Nombre"] = nuevo_valor
                self.update_user_json(user, ["Nombre"])
                print("\n¡Nombre modificado con éxito!")
                modificar_nombre_loop = False

    def modificar_apellidos(self, user: dict):
        modificar_apellido_loop = True
        while modificar_apellido_loop:
            nuevo_valor = input(
                "\nInserta el nuevo valor para Apellidos: \n(para cancelar la operación, presiona enter)\n")
            if nuevo_valor == "":
                modificar_apellido_loop = False
            else:
                user["Apellidos"] = nuevo_valor
                self.update_user_json(user, ["Apellidos"])
                print("\n¡Apellidos modificados con éxito!")
                modificar_apellido_loop = False

    def modificar_email(self, user: dict):
        modificar_email_loop = True
        while modificar_email_loop:
            nuevo_valor = input(
                "\nInserta el nuevo valor para Email: \n(para cancelar la operación, presiona enter)\n")
            if nuevo_valor == "":
                modificar_email_loop = False
            elif not self.check_regex_email(nuevo_valor):
                print("(!) Email inválido, debe seguir el formato nombre@dominio.net")
            else:
                self.modify_cipher_data(user, "Email", nuevo_valor)
                print("\n¡Email modificado con éxito!")
                modificar_email_loop = False

    def modificar_direccion(self, user: dict):
        print("\nInserta el nuevo valor para Dirección:")
        dir_calle = self.validate_campo_obligatorio("\t- Calle: ", False)
        dir_numero = self.validate_campo_obligatorio("\t- Número: ", True)
        dir_piso, dir_puerta = self.validate_piso_puerta()
        dir_codigo_postal = self.validate_campo_obligatorio("\t- Código postal: ", True)
        dir_localidad = self.validate_campo_obligatorio("\t- Localidad: ", False)
        dir_provincia = self.validate_campo_obligatorio("\t- Provincia: ", False)
        dir_pais = self.validate_campo_obligatorio("\t- País: ", False)

        # Se construye un único string de "dirección" que contenga los datos introducidos anteriormente
        if dir_piso != "" and dir_puerta != "":
            nuevo_valor = (f"Calle {dir_calle}, {dir_numero}, {dir_piso}-{dir_puerta}, "
                           f"{dir_codigo_postal}, {dir_localidad}, {dir_provincia}, {dir_pais}")
        else:
            nuevo_valor = (f"Calle {dir_calle}, {dir_numero}, {dir_codigo_postal}, {dir_localidad}, "
                           f"{dir_provincia}, {dir_pais}")
        self.modify_cipher_data(user, "Direccion", nuevo_valor)
        print("\n¡Dirección modificada con éxito!")

        # Aa0@aaaaaaaaaaaaa Aa0@aaaaaaaaaaaab

    def modificar_contraseña(self, user: dict):
        # Pedirle al usuario su contraseña actual
        modificar_contraseña_loop = True
        num_intentos = 3
        while modificar_contraseña_loop and num_intentos > 0:
            actual_contraseña = input("\nIntroduce tu actual contraseña:"
                                      "\n(para cancelar la operación, presiona enter)\n")
            if actual_contraseña == "":
                return
            else:
                # Se verifica que la contraseña coincide
                kdf_actual = Scrypt(
                    salt=base64.b64decode(user["Salt"]),
                    length=32,
                    n=2 ** 14,
                    r=8,
                    p=1,
                )
                # Coincide
                try:
                    kdf_actual.verify(actual_contraseña.encode(), base64.b64decode(user["Pwd"]))
                    modificar_contraseña_loop = False
                # No coincide
                # Al alcanzar el máximo número de intentos, se cierra sesión para proteger la cuenta
                except InvalidKey:
                    num_intentos -= 1
                    if num_intentos > 1:
                        print(f"(!) ¡Contraseña incorrecta! Te quedan {num_intentos} intentos")
                    elif num_intentos == 1:
                        print(f"(!) ¡Contraseña incorrecta! Te queda {num_intentos} intento")
                    elif num_intentos == 0:
                        print("(!) Se hicieron demasiados intentos incorrectos. Cerrando sesión.")
                        return -1
        # Pedirle al usuario una nueva contraseña, generar un nuevo salt y actualizar el JSON
        nueva_contraseña = self.validate_pwd("\nEscribe tu nueva contraseña: ")
        # Generar un nuevo salt único
        salt_loop = True
        while salt_loop:
            salt_binary = os.urandom(16)  # type = bytes
            salt = base64.b64encode(salt_binary).decode('utf-8')  # type = str
            # Verificar que salt no existe
            if self.search_user_json("Salt", salt) is None:
                salt_loop = False

        # Se genera la clave derivada de la contraseña usando el nuevo salt
        kdf_nueva = Scrypt(
            salt=salt_binary,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        pwd_binary = nueva_contraseña.encode()  # contraseña en claro en binario
        pwd_kdf_binary = kdf_nueva.derive(pwd_binary)  # clave derivada en binario
        pwd_kdf = base64.b64encode(pwd_kdf_binary).decode('utf-8')  # string en base64 que puede ser almacenado

        user["Pwd"] = pwd_kdf
        user["Salt"] = salt
        self.update_user_json(user, ["Pwd", "Salt"])

        print("\n¡Contraseña modificada con éxito!")

    # FUNCIONES RELATIVAS AL JSON

    def generate_user_dict(self, doc_id, nombre, apellidos, email, direccion, pwd: str, credito) -> dict:
        """Introduce los datos de registro de cuenta en un diccionario, la estructura de datos más adecuada para
        más adelante trabajar con archivos json, así como otros datos generados automáticamente"""

        # El sistema genera un número de cuenta único para el usuario
        bank_num_loop = True
        while bank_num_loop:
            generated_bank_num = str(random.randint(1000000000000000000000, 9999999999999999999999))
            bank_num = "ES" + generated_bank_num
            # Verificar que el número del banco que se quiere asignar no existe en ningún otro usuario
            if self.search_user_json("BankNum", bank_num) is None:
                bank_num_loop = False

        # No podemos almacenar la contraseña del usuario en claro
        # Usaremos una key derivation function en su lugar

        # El sistema genera un salt único
        salt_loop = True
        while salt_loop:
            salt_binary = os.urandom(16)  # type = bytes
            salt = base64.b64encode(salt_binary).decode('utf-8')  # type = str
            # Verificar que salt no existe
            if self.search_user_json("Salt", salt) is None:
                salt_loop = False

        # Se genera la clave derivada de la contraseña usando el salt único del usuario
        kdf = Scrypt(
            salt=salt_binary,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        pwd_binary = pwd.encode()  # contraseña en claro en binario
        pwd_kdf_binary = kdf.derive(pwd_binary)  # clave derivada en binario
        pwd_kdf = base64.b64encode(pwd_kdf_binary).decode('utf-8')  # string en base64 que puede ser almacenado

        # cifrar los datos con AES_GCM.
        datos_a_cifrar = [email, direccion, str(credito)]
        nonce_array = []
        datos_cifrados = []

        # generamos una clave para el usuario.
        user_key = AESGCM.generate_key(bit_length=128)

        aesgcm = AESGCM(user_key)

        for i in range(len(datos_a_cifrar)):
            # Pasamos el dato a binario.
            #datos_a_cifrar[i] = base64.b64decode(datos_a_cifrar[i])
            datos_a_cifrar[i] = (datos_a_cifrar[i]).encode(encoding='utf-8')
            # Generamos un nonce para cada dato.
            nonce_array.append(os.urandom(12))
            # Encriptamos.
            ciphertext = aesgcm.encrypt(nonce_array[i], datos_a_cifrar[i], None)
            datos_cifrados.append(ciphertext)

        # Ciframos la clave de usuario con la MASTER_KEY.
        user_key_nonce = os.urandom(12)
        master_aesgcm = AESGCM(MASTER_KEY)
        user_key_ciphertext = master_aesgcm.encrypt(user_key_nonce, user_key, None)

        user_dict = {
            "BankNum": bank_num,
            "DocID": doc_id,
            "Nombre": nombre,
            "Apellidos": apellidos,
            "EmailNonce": base64.b64encode(nonce_array[0]).decode('utf-8'),
            "Email": base64.b64encode(datos_cifrados[0]).decode('utf-8'),
            "DireccionNonce": base64.b64encode(nonce_array[1]).decode('utf-8'),
            "Direccion": base64.b64encode(datos_cifrados[1]).decode('utf-8'),
            "CreditoNonce": base64.b64encode(nonce_array[2]).decode('utf-8'),
            "Credito": base64.b64encode(datos_cifrados[2]).decode('utf-8'),
            "Pwd": pwd_kdf,
            "Salt": salt,
            "UserKeyNonce": base64.b64encode(user_key_nonce).decode('utf-8'),
            "UserKey": base64.b64encode(user_key_ciphertext).decode('utf-8')
        }

        return user_dict

    def create_user_json(self, user_dict: dict) -> None:
        """Añade un nuevo usuario al archivo json"""
        file_path = "database.json"

        # Abrir en modo read and write
        with open(file_path, "r+", encoding="utf-8") as open_file:
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

    def delete_user_json(self, user_dict: dict) -> None:
        """Elimina un usuario con todos sus datos del archivo json"""
        file_path = "database.json"

        with open(file_path, "r+", encoding="utf-8") as open_file:
            json_data = json.load(open_file)
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
        file_path = "database.json"

        with open(file_path, "r+", encoding="utf-8") as open_file:
            json_data = json.load(open_file)
            open_file.seek(0)
            open_file.truncate(0)

            for user in json_data:
                if user["BankNum"] == user_dict["BankNum"]:
                    for key in keys:
                        user[key] = user_dict[key]

            json.dump(json_data, open_file, indent=4)

        open_file.close()

    def search_user_json(self, key, value) -> dict | None:
        """Buscar el usuario que contenga el valor (key, value) si existe"""
        file_path = "database.json"

        # Abrir el archivo en modo read only
        with open(file_path, "r", encoding="utf-8") as open_file:
            json_data = json.load(open_file)

        # Recorre todos los usuarios en busca de un match y lo devuelve al encontrarlo
        for user in json_data:
            if user[key] == value:
                open_file.close()
                return user

        # No se encontró un usuario con esas características
        open_file.close()
        return None


banko = BankInstance()
banko.bank_loop()
