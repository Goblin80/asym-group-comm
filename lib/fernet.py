from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from lib.serial import encode, decode


class FRNET_Wrapper:
    def __init__(self, password):

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'pepper',
            iterations=10000,
            backend=default_backend()
        )

        key = encode(kdf.derive(password))
        self._fernet = Fernet(key)

    def encrypt(self, payload):
        return self._fernet.encrypt(payload)

    def decrypt(self, payload):
        return self._fernet.decrypt(payload)

    def decode(self, payload):
        return decode(payload)

    def key_decrypt(self, key):
        return self.decrypt(self.decode(key))
