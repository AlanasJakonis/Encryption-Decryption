from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from .base import BaseHandler
from cryptography.fernet import Fernet

key = Fernet.generate_key()
crypter = Fernet(key)

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            name = body['name'].lower().strip()
            bname = bytes(name, 'utf8')
            fname = crypter.encrypt(bname)
            if not isinstance(name, str):
                raise Exception()
            number = body['number'].lower().strip()
            bnumber = bytes(number, 'utf8')
            fnumber = crypter.encrypt(bnumber)
            if not isinstance(number, str):
                raise Exception()
            disabilities = body['disabilities'].lower().strip()
            bdisabilities = bytes(disabilities, 'utf8')
            fdisabilities = crypter.encrypt(bdisabilities)
            if not isinstance(disabilities, str):
                raise Exception()
            email = body['email'].lower().strip()
            bemail = bytes(email, 'utf8')
            femail = crypter.encrypt(bemail)
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            bpassword = bytes(password, 'utf8')
            fpassword = crypter.encrypt(bpassword)
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
        
        decryptname = crypter.decrypt(fname)
        decryptname2 = (str(decryptname, 'utf8'))

        decryptnumber = crypter.decrypt(fnumber)
        decryptnumber2 = (str(decryptnumber, 'utf8'))

        
        decryptdisabilities = crypter.decrypt(fdisabilities)
        decryptdisabilities2 = (str(decryptdisabilities, 'utf8'))

        
        decryptemail = crypter.decrypt(femail)
        decryptemail2 = (str(decryptemail, 'utf8'))

        
        decryptpassword = crypter.decrypt(fpassword)
        decryptpassword2 = (str(decryptpassword, 'utf8'))


        yield self.db.users.insert_one({
            'name': fname,
            'number': fnumber,
            'disabilities': fdisabilities,
            'email': femail,
            'password': fpassword,
            'displayName': display_name
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()