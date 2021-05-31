from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from file_manager import *


def encrypt_message(message="Hello World", path_key='privateKey.pem'):
    # Leer archivo
    msg = bytes(message, encoding='utf-8')

    #   Abrir llave publica A
    f = open(path_key, 'r')
    privKey_A = RSA.importKey(f.read())
    f.close()

    #   Cifrar usando llave publica A
    encryptor = PKCS1_OAEP.new(privKey_A)
    encrypted = encryptor.encrypt(msg)
    print(encrypted)
    return encrypted
    #   Escribit txt
    #f = open('message_C.txt', 'wb')
    # f.write(encrypted)
    # f.close()


def decrypt_message(message="", path_key="publicKey.pem"):
    #   Abrir llave privada A
    f = open(path_key, 'r')
    pubKey_B = RSA.importKey(f.read())
    #publicKey_B = pubKey_B.publickey()

    #   Decifrar con privada A
    cipher = PKCS1_OAEP.new(pubKey_B)
    message = cipher.decrypt(message)
    return message

    #   Escribir mensaje
    #f = open('message_C_D.txt', 'w')
    # f.write(str(message.decode("utf-8")))
    # f.close()


def main():
    encrypt_message()
    decrypt_message()


if __name__ == "__main__":
    main()
