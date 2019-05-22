from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from lib.serial import encode, decode


class Public():

    def __init__(self, pem):
        self.key = self.load(pem)

    def verify(self, signature, payload):
        try:
            self.key.verify(signature, payload,
                            ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True

    def load(self, pem):
        return serialization.load_pem_public_key(pem, default_backend())

    def export(self):
        return self.key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


class Private():

    def __init__(self, pem=None, password=None):

        if pem is None:
            self.key = self.generate()
        else:
            self.key = self.load(pem, password)

    def generate(self):
        return ec.generate_private_key(ec.SECP256K1(), default_backend())

    def deduce_public(self):
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, payload):
        return self.key.sign(payload, ec.ECDSA(hashes.SHA256()))

    def load(self, pem, password=None):
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
