import requests

import lib.rsa as RSA
from lib.message import Message


class User:
    def __init__(self, name, port, public=None, private=None, host='localhost'):
        self.name = name
        self.host = host
        self.port = port

        if public is not None:
            self.public = RSA.Public(public)
        if private is not None:
            self.private = RSA.Private(private)

        self.mailbox = []  # list of messages

    def send(self, msg, user):

        # encrypted = RSA.encode(self.encrypt(msg.encode(), user).encode())
        encrypted = self.encrypt(msg.encode(), user)
        res = requests.get(f'http://{user.host}:{user.port}/mailbox/{encrypted}')
        return res.status_code is 200
        # return encrypted

    def encrypt(self, plaintext, user):  # should also sign message
        return RSA.encode(user.public.encrypt(plaintext))

    def decrypt(self, ciphertext):  # should also verify message

        print(ciphertext)

        return self.private.decrypt(RSA.decode(ciphertext)).decode()
        # return self.private.decrypt(RSA.decode(ciphertext.encode())).decode()

    def verify(self, msg, user):
        pass

    def sign(self, msg):
        pass

    def export(self):
        return {'name': self.name,
                'port': self.port,
                'public': self.public.export().decode(),
                'host': self.host}
