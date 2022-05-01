from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
from .base import BaseHandler
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os

salt = os.urandom(16)
kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)

import json

class Object:
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True)


class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token




    @coroutine
    def post(self):

        salt = yield self.db.users.find_one({
          'email': email
        }, {
          'salt': 1
        })        
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            email = body.get('email')
            email_bytes = bytes(email, "utf-8")
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            password = body.get('password')
            password_bytes = bytes(password, "utf-8")

            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)

            hashed_password = kdf.derive(password_bytes)
            
            if pw is None:
                pw = email
            if not isinstance(pw, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {
          'password': password
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        if user['password'] != password:
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
