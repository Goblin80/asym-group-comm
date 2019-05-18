from flask import Flask, jsonify
import requests
import base64

import lib.rsa as RSA
from lib.dh import DH_Wrapper
from lib.fernet import FRNET_Wrapper

from lib.serial import encode, decode

app = Flask(__name__)


CA_PORT = 5000


# @app.route("/dh")

def request_dh():
    d = DH_Wrapper()
    res = requests.get(f'http://localhost:{CA_PORT}/dh/agree/{d.y}').json()

    shared_secret = d.calc_shared_key(int(res['public']))
    k = encode(shared_secret)
    print(k)

    return shared_secret
    # return jsonify({'hoba':  k})

# @app.route('/')
# def decrypt():

#     f = FR.FRNET_Wrapper(b'hoba')

#     payload = f.decrypt(f.decode(hoba))

#     # print(payload)
#     return jsonify({'yalla' : payload.decode()})


def request_rsa_key_securly():

    d = DH_Wrapper()
    res = requests.get(f'http://localhost:{CA_PORT}/rsa/request/{d.y}').json()
    peer_y = int(res['peer_y'])

    shared_key = d.calc_shared_key(peer_y)

    f = FRNET_Wrapper(shared_key)
    rsa_key_encrypted = res['rsa']

    rsa_key = f.key_decrypt(rsa_key_encrypted)

    sig = res['signature']

    sig = f.decode(sig)


    r = RSA.Private(rsa_key)
    CA_public = RSA.load_CA_public()

    print(CA_public)
    CA = RSA.Public(CA_public)
    # CA.key.

    print(CA.verify(sig , r.export()))



    # print(rsa_key)


request_rsa_key_securly()
