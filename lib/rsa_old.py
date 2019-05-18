from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes

from lib.serial import encode, decode
KEY_SZ = 1024


class RSA_Wrapper:

    def __init__(self, pem, password=None):
        self.key = load_private(pem, password)

    def sign(self, payload):

        signature = self.key.sign(payload,
                                  padding.PSS(
                                      mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature


def export(key):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        encryption_algorithm=serialization.NoEncryption())
    return pem


def load_private(pem, password=None):
    return serialization.load_pem_private_key(pem,
                                              password=password,
                                              backend=default_backend())


def load_public(pem):
    return serialization.load_pem_public_key(pem, default_backend())


def load_private_file(file, password=None):
    return load_private(open(file, "rb").read(), password)


def generate_private():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SZ,
        backend=default_backend()
    )

    return export(private_key)


def load_CA_private():
    return open("CA.private", "rb").read()


def load_CA_public():
    return open("CA.public", "rb").read()
    # with open("CA.public", "rb") as key_file:
    #     CA_public = serialization.load_pem_public_key(
    #         key_file.read(),
    #         backend=default_backend()
    #     )
    # return CA_public
