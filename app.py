from flask import Flask, jsonify
import requests
import base64

import lib.rsa as RSA
from lib.dh import DH_Wrapper
from lib.fernet import FRNET_Wrapper

from lib.user import User
from lib.message import Message

from lib.serial import encode, decode

app = Flask(__name__)

CA_HOST, CA_PORT = 'localhost', 5000


currentUser = User('Alice', 5001)
mailbox = []
usersMap = {}


@app.route("/mailbox/<ciphertext>")
def receive_msg(ciphertext):
    print(ciphertext)

    mailbox.append(currentUser.decrypt(ciphertext))

    return jsonify({'status': 'Message received'})


@app.route("/broadcast/<message>")
def broadcast_msg(message):
    for id in usersMap:
        currentUser.send(message, usersMap[id])
    return jsonify({'status': 'Message broadcasted'})

@app.route("/request/<name>/<int:port>")
def request_rsa_key_securly(name, port):
    user = User(name, port) # remove later
    currentUser.name, currentUser.port = name, port

    d = DH_Wrapper()
    res = requests.get(
        f'http://{CA_HOST}:{CA_PORT}/rsa/request/{d.y}/{d.modulus}/{user.name}/{user.port}').json()
    peer_y = int(res['peer_y'])

    shared_key = d.calc_shared_key(peer_y)

    f = FRNET_Wrapper(shared_key)
    rsa_key_encrypted = res['rsa']

    rsa_key = f.key_decrypt(rsa_key_encrypted)

    currentUser.private = RSA.Private(rsa_key)
    currentUser.public = RSA.Public(currentUser.private.deduce_public())

    return jsonify({'status' : 'keys generated'})

@app.route("/fetch/users")
def fetch_users():
    res = requests.get(f'http://{CA_HOST}:{CA_PORT}/registry').json()
    for r in res['users']:
        usersMap[r['name']] = User(r['name'], r['port'], r['public'].encode())

    print(usersMap)
    return jsonify({'status' : 'fetch successful'})


@app.route("/fetch/mailbox")
def view_msg():
    return jsonify({'messages' : mailbox})


@app.route("/")
def home():
    return jsonify({'status' : 'homepage'})




# currentUser.private = RSA.Private(open('key1.private', 'rb').read())

# currentUser.public = RSA.Public(open('key1.public', 'rb').read())
# msg = 'hello'

# ciphertext = currentUser.encrypt(msg.encode(),currentUser)
# print(ciphertext)

# plaintext = currentUser.decrypt('Myrgw19PpQ5DTa64kVXG5xqkEhIFNdC4xO4zkXFFYivVWX_-mIcCrRPswy0Tm3e72C6PGTF4T-kD7o9UzgmGpwymtXkhLZ7vfoG754lEAXrhWtYWYsiCPoi4QGWzduofybeEfYfLFZGpobTDDoKUgxQyMno4PXD9r396u9iAwbU=')
# print(plaintext)
