from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes


from flask import Flask, jsonify
import requests

import lib.rsa as RSA
from lib.dh import DH_Wrapper
from  lib.fernet import FRNET_Wrapper


app = Flask(__name__)

def generate_rsa_private(dh_key):

    f = FRNET_Wrapper(dh_key)


    rsa_private = RSA.Private()

    CA_private = RSA.load_CA_private()
    CA = RSA.Private(CA_private)
    rsa_key_encrypted = f.encrypt(rsa_private.export())

    return rsa_key_encrypted, CA.sign(rsa_private.export())


@app.route("/dh/agree/<int:peer_y>")
def generate_shared_secret(peer_y):
    d = DH_Wrapper()
    shared_secret = d.calc_shared_key(peer_y)
    # print(DH.encode(shared_secret))

    return jsonify({'public': d.y})


@app.route("/rsa/request/<int:peer_y>/<int:modulus>")
def generate_rsa_private_encrypted(peer_y, modulus):

    print(peer_y)
    print(modulus)

    d = DH_Wrapper(modulus)
    shared_secret = d.calc_shared_key(peer_y)

    rsa_key_encrypted, signature = generate_rsa_private(shared_secret)

    # print(signature)

    return jsonify({'peer_y': d.y, 'rsa': RSA.encode(rsa_key_encrypted), 'signature': RSA.encode(signature)})
