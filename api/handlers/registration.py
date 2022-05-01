from json import dumps
from logging import info
from unicodedata import name
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            name = body['name'].lower().strip()
            if not isinstance(name, str):
                raise Exception()
            pnumber = body['pnumber'].strip()
            if not isinstance(pnumber, str):
                raise Exception()
            disabilities = body['disabilities'].strip()
            if not isinstance(disabilities, str):
                raise Exception()               
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
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
            'Name': name,
            'Phone number': pnumber,
            'Disabilities': disabilities,
            'Email Address': email,
            'Password': password,
            'Display Name': display_name
        })

        self.set_status(200)
        self.response['name'] = name
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
