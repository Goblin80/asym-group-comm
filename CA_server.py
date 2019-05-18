from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes


from flask import Flask, jsonify
import requests

import lib.rsa as RSA
from lib.dh import DH_Wrapper
from lib.fernet import FRNET_Wrapper

from lib.user import User

app = Flask(__name__)


def generate_rsa_pair(dh_key):

    f = FRNET_Wrapper(dh_key)

    rsa_private = RSA.Private()

    CA = RSA.Private(RSA.load_CA_private())

    rsa_public = RSA.Public(rsa_private.deduce_public())

    rsa_private_encrypted = f.encrypt(rsa_private.export())

    # should sign public
    return rsa_private_encrypted, rsa_public, CA.sign(rsa_private.export()),


userList = []


@app.route("/rsa/request/<int:peer_y>/<int:modulus>/<name>/<int:port>")
def generate_rsa_private_encrypted(peer_y, modulus, name, port):

    d = DH_Wrapper(modulus)
    shared_secret = d.calc_shared_key(peer_y)

    rsa_key_encrypted, rsa_public, signature = generate_rsa_pair(shared_secret)

    userList.append({'name': name,
                     'port': port,
                     'public': rsa_public.export().decode()})

    return jsonify({'peer_y': d.y, 'rsa': RSA.encode(rsa_key_encrypted), 'signature': RSA.encode(signature)})


@app.route("/registry")
def view_registry():
    return jsonify({'users': userList})
