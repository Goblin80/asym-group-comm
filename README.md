# Asymmetric Group Communication

Multi-client encrypted communication service.

## Description

1. Clients asks certificate authority (CA_server.py) to generate `RSA` keys for them.

1. CA generates `RSA` keys and signs them using `SECP256K1`'s elliptic curve.

1. CA sends `RSA` keys and signature to the clients after symmetrically encrypting them,

1. `Fernet` used as the symmetric encryption method of choice (`AES` in `CBC` mode with 128-bit key) after agreeing on a shared key using `Diffie-Hellman`'s key exchange.

1. Upon receiving keys, client verify the key's signature.

1. Public keys generated are kept in a registry maintained by CA for transparency.

1. Clients communicate directly with each other.


## Install dependencies

``$ pip install -r requirements.txt``

## Usage
* CA : `FLASK_APP=CA_server.py flask run -p 5000`
* Client: `FLASK_APP=app.py flask run -p 5001`