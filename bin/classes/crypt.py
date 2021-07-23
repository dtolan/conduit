from Crypto.Cipher import AES
from Crypto import Random
from pprint import pprint
import base64


class Crypt:
    def __init__(self, key):
        self.key = key.encode('utf-8')

    def encrypt(self, value):
        encoded_value = value.ljust(256).encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        string_nonce = str(base64.b64encode(nonce), 'utf-8')
        encrypted, tag = cipher.encrypt_and_digest(encoded_value)
        string_encrypted = str(base64.b64encode(encrypted), 'utf-8')
        string_tag = str(base64.b64encode(tag), 'utf-8')
        return "|".join([string_encrypted, string_tag, string_nonce])

    def decrypt(self, value):
        [string_encrypted, string_tag, string_nonce] = value.split('|')
        nonce = base64.b64decode(string_nonce)
        encrypted = base64.b64decode(string_encrypted)
        tag = base64.b64decode(string_tag)
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(encrypted)
        try:
            cipher.verify(tag)
        except ValueError:
            return
        return plaintext.decode('utf-8').rstrip()
