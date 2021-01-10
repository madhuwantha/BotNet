from Crypto.PublicKey import RSA
import urllib
import base64


def encript(msg):
    with open('keys/pub', 'r') as content_file:
        f_pub = content_file.read()

    keyPub = RSA.importKey(f_pub)
    crypto_msg = keyPub.encrypt(str(msg), 32)
    return base64.b64decode(crypto_msg[0])