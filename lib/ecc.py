from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


private_key = ec.generate_private_key(ec.SECP256K1, default_backend())

public_key = private_key.public_key()

serialized_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    # encryption_algorithm=serialization.BestAvailableEncryption(b'pass')
    encryption_algorithm=serialization.NoEncryption()
)


serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


CA_private = ec.generate_private_key(ec.SECP256K1, default_backend())


serialized_CA_private = CA_private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    # encryption_algorithm=serialization.BestAvailableEncryption(b'pass')
    encryption_algorithm=serialization.NoEncryption()
)


CA_public = CA_private.public_key()


signature = CA_private.sign(serialized_private_key, ec.ECDSA(hashes.SHA256()))



try:
    CA_public.verify(signature, serialized_private_key, ec.ECDSA(hashes.SHA256()))
    print("its fine")
except InvalidSignature:
    print("Whoops")




