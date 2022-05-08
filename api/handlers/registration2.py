from json import dumps
from logging import info
from unicodedata import name
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from .base import BaseHandler
from logging import info
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

key = "QGkOOzjhDrhPcP1a9sluHTvQMsg4aNFp"
key_bytes = bytes(key, "utf-8")
nonce_bytes = os.urandom(16)
nonce=nonce_bytes.hex()
chacha20_cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce_bytes),
                         mode=None)
chacha20_encryptor = chacha20_cipher.encryptor()
chacha20_encryptor = chacha20_cipher.decryptor()

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
salt = os.urandom(16)
kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)


class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            name = body['name'].lower().strip()
            if not isinstance(name, str):
                raise Exception()
            nm = body.get('name')
            name_bytes = bytes(nm, "utf-8")
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            hashed_name = kdf.derive(name_bytes)
            if nm is None:
                nm = email
            if not isinstance(nm, str):
                raise Exception()
            pnumber = body['pnumber'].strip()
            if not isinstance(pnumber, str):
                raise Exception()
            pn = body.get('pnumber')
            number_bytes = bytes(pn, "utf-8")
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            hashed_pnumber = kdf.derive(number_bytes)
            if pn is None:
                pn = email
            disabilities = body['disabilities'].strip()
            if not isinstance(disabilities, str):
                raise Exception()
            disa = body.get('disabilities')
            disabilities_bytes = bytes(disa, "utf-8")
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            hashed_disabilities = kdf.derive(disabilities_bytes)
            if disa is None:
                disa = email            
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            em = body.get('email')
            email_bytes = bytes(em, "utf-8")
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            hashed_email = kdf.derive(email_bytes)
            if em is None:
                em = email   
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            passw = body.get('password')
            password_bytes = bytes(passw, "utf-8")
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            hashed_password = kdf.derive(password_bytes)
            if passw is None:
                passw = email   
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not name:
            self.send_error(400, message='The name is invalid!')
            return

        if not disabilities:
            self.send_error(400, message='Disa')
            return

        if not pnumber:
            self.send_error(400, message='The number is invalid!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        yield self.db.users.insert_one({
            'Name': hashed_name,
            'Phone number': hashed_pnumber,
            'Disabilities': hashed_disabilities,
            'Email Address': hashed_email,
            'Password': hashed_password,
            'Display Name': display_name
        })

        self.set_status(200)
        self.response['name'] = name
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
