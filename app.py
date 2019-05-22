from flask import Flask, jsonify, render_template, request
import requests

import lib.rsa as RSA
import lib.ecc as ECC
from lib.dh import DH_Wrapper
from lib.fernet import FRNET_Wrapper
from lib.user import User
from lib.serial import encode, decode

app = Flask(__name__, template_folder='UI',
            static_url_path='/static', static_folder='UI/static')

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
    rsa_key_encrypted, signature = res['rsa'], res['signature']
    CA = ECC.Public(ECC.load_CA_public())
    rsa_key = f.key_decrypt(rsa_key_encrypted)

    if CA.verify(decode(signature), rsa_key) is True:
        print("Key has been verfied")
    else:
        print("Key smells fishy")

    currentUser.private = RSA.Private(rsa_key)
    currentUser.public = RSA.Public(currentUser.private.deduce_public())

    return jsonify({'status': 'keys generated'})


@app.route("/update/users", methods=['POST'])
def update_users():
    for r in request.get_json()['users']:
        usersMap[r['name']] = User(r['name'], r['port'], r['public'].encode())

    return jsonify({'status': 'users have been updated successful'})


@app.route("/fetch/mailbox")
def view_msg():

    if(request.remote_addr == '127.0.0.1'):
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
