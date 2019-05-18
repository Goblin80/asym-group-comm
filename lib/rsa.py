from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from lib.serial import encode, decode


class Public():

    def __init__(self, pem):
        self.key = self.load(pem)

    def encrypt(self, payload):
        return self.key.encrypt(payload,
                                padding.OAEP(
                                    mgf=padding.MGF1(
                                        algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                ))

    def verify(self, signature, payload):
        try:
            self.key.verify(signature,
                            payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                 salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256())
        except InvalidSignature:
            return False
        return True


    def load(self, pem):
        return serialization.load_pem_public_key(pem, default_backend())

    def export(self):
        pass


class Private():

    def __init__(self, pem=None, password=None):

        if pem is None:
            self.key = self.generate()
        else:
            self.key = self.load(pem, password)

    def generate(self, size=1024):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )

    def decrypt(self, payload):
        return self.key.decrypt(payload,
                                padding.OAEP(
                                    mgf=padding.MGF1(
                                        algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                ))

    def sign(self, payload):
        return self.key.sign(payload,
                             padding.PSS(
                                 mgf=padding.MGF1(hashes.SHA256()),
                                 salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def load(self, pem, password):
        return serialization.load_pem_private_key(pem,
                                                  password=password,
                                                  backend=default_backend())

    def export(self):
        pem = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        return pem


def load_CA_private():
    return open("CA.private", "rb").read()


def load_CA_public():
    return open("CA.public", "rb").read()
