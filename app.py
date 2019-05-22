from flask import Flask, jsonify, render_template, request
import requests
import base64

import lib.rsa as RSA
from lib.dh import DH_Wrapper
from lib.fernet import FRNET_Wrapper

from lib.user import User

from lib.serial import encode, decode

app = Flask(__name__, template_folder='UI')

CA_HOST, CA_PORT = 'localhost', 5000


currentUser = User('', 0)
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
        try:
            currentUser.send(currentUser.name + ": " + message, usersMap[id])
        except:
            print(f"Could not send to user {usersMap[id].name}")
    return jsonify({'status': 'Message broadcasted'})


@app.route("/request/<name>/<int:port>")
def request_rsa_key_securly(name, port):
    currentUser.name, currentUser.port = name, port

    d = DH_Wrapper()
    res = requests.get(
        f'http://{CA_HOST}:{CA_PORT}/rsa/request/{d.y}/{d.modulus}/{currentUser.name}/{currentUser.port}').json()
    peer_y = int(res['peer_y'])

    shared_key = d.calc_shared_key(peer_y)

    f = FRNET_Wrapper(shared_key)
    rsa_key_encrypted = res['rsa']

    rsa_key = f.key_decrypt(rsa_key_encrypted)

    currentUser.private = RSA.Private(rsa_key)
    currentUser.public = RSA.Public(currentUser.private.deduce_public())

    return jsonify({'status': 'keys generated'})


@app.route("/fetch/users")
def fetch_users():
    res = requests.get(f'http://{CA_HOST}:{CA_PORT}/registry').json()
    for r in res['users']:
        usersMap[r['name']] = User(r['name'], r['port'], r['public'].encode())

    return jsonify({'status': 'fetch users successful'})


@app.route("/fetch/mailbox")
def view_msg():

    if(request.remote_addr == '127.0.0.1'):
        fetch_users()  # just to be safe
        return jsonify({'messages': mailbox})
    else:
        print(f"--- unauthorized access attempt --- {request.remote_addr}")
        return jsonify({'error': 'UNAUTHORIZED ACCESS'})


@app.route("/")
def login():
    return render_template('login.html')


@app.route("/home", methods=['POST'])
def home():
    name, port = request.form['name'], request.form['port']
    request_rsa_key_securly(name, port)
    return render_template('client.html', name=currentUser.name, port=currentUser.port)
