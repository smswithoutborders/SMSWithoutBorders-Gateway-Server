#!/usr/bin/env python3

# Use this for IDEs to check data types
#https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS

from src import sync, rsa, aes
from sockets import ip_grap

from src.users import Users

from src.users_entity import UsersEntity

import os
import json
import logging
import threading
import base64

from SwobBackendPublisher import MySQL, Lib
from SwobBackendPublisher.exceptions import UserDoesNotExist, DuplicateUsersExist

__api_version_number = 2

HOST = os.environ.get("HOST")
SOCK_PORT = os.environ.get("SOCK_PORT")
RSA_PR_KEY = os.environ.get("RSA_PR_KEY")


# Required for BE-Publisher Lib
MYSQL_BE_HOST=os.environ["MYSQL_HOST"] \
        if not os.environ.get("MYSQL_BE_HOST") else os.environ.get("MYSQL_BE_HOST")

MYSQL_BE_USER=os.environ["MYSQL_USER"] \
        if not os.environ.get("MYSQL_BE_USER") else os.environ.get("MYSQL_BE_USER")

MYSQL_BE_PASSWORD=os.environ["MYSQL_PASSWORD"] \
        if not os.environ.get("MYSQL_BE_PASSWORD") else os.environ.get("MYSQL_BE_PASSWORD")
MYSQL_BE_DATABASE= os.environ["MYSQL_DATABASE"] \
        if not os.environ.get("MYSQL_BE_DATABASE") else os.environ.get("MYSQL_BE_DATABASE")

# Required for storing user encryption information
MYSQL_HOST="127.0.0.1" if not os.environ.get("MYSQL_HOST") else os.environ.get("MYSQL_HOST")
MYSQL_USER="root" if not os.environ.get("MYSQL_USER") else os.environ.get("MYSQL_USER")

MYSQL_PASSWORD= os.environ["MYSQL_PASSWORD"]
MYSQL_DATABASE= os.environ["MYSQL_DATABASE"]

"""
For BE-Pub lib
"""
usersBEPUB = UsersEntity(
        mysql_host= MYSQL_BE_HOST,
        mysql_user = MYSQL_BE_USER,
        mysql_password = MYSQL_BE_PASSWORD,
        mysql_database = MYSQL_BE_DATABASE)

BEPubLib = Lib(usersBEPUB.db)

usersEntity = UsersEntity(
        mysql_host= MYSQL_HOST,
        mysql_user = MYSQL_USER,
        mysql_password = MYSQL_PASSWORD,
        mysql_database = MYSQL_DATABASE)

users = Users(usersEntity)

try:
    users.create_database_and_tables__()
except Exception as error:
    logging.exception(error)


app = Flask(__name__)
app.config.from_object(__name__)

CORS(
    app,
    origins="*",
    supports_credentials=True,
)


@app.route('/v%s/sync/users/<user_id>' % (__api_version_number), methods=['GET'])
def get_sync_url(user_id: str):
    """
    TODO: validate user_id before having it in production
    """
    try:
        port = app.config["SOCK_PORT"]

        # print(dir(app.env["HOST"]))
        # TODO:  does not work well with docker
        # host = socket_sessions.get_host(app.config["HOST"])
        host = request.host.split(':')[0]
        sockets_url = sync.get_sockets_sessions_url(user_id=user_id, host=host, port=SOCK_PORT)
    except Exception as error:
        app.logger.exception(error)
        return '', 500
    else:
        return sockets_url, 200

def logging_after_request(response):
    # in here is where we transmit to the logger trace
    # logging.debug(response)
    logging.debug(response.response)
    return response

app.after_request(logging_after_request)

@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>/' % (__api_version_number), methods=['POST'])
def get_users_platforms(user_id: str, session_id: str):
    """
    """
    try:
        data = json.loads(request.data, strict=False)
    except Exception as error:
        logging.exception(error)

        return 'poorly formed json', 400
    else:

        if not 'password' in data:
            return 'missing password', 400

        if not 'public_key' in data:
            return 'missing public key', 400

        '''
        TODO:
            - update the ios app to have mgf1ParameterSpec
            - update the android to have hashingAlgorithm
        '''
        mgf1ParameterSpec = data['mgf1ParameterSpec'] if 'mgf1ParameterSpec' in data else 'sha1'
        hashingAlgorithm = data['hashingAlgorithm'] if 'hashingAlgorithm' in data else 'sha256'

        try:

            user_password = data['password']
            user_public_key = data['public_key']

            decrypted_password = rsa.SecurityRSA.decrypt(user_password, 
                    private_key_filepath=RSA_PR_KEY,
                    mgf1ParameterSpec=mgf1ParameterSpec, hashingAlgorithm=hashingAlgorithm)
        except Exception as error:
            app.logger.exception(error)
            return 'error with decryption', 400
        else:

            user_msisdn_hash = None
            try:
                user_msisdn_hash = BEPubLib.get_phone_number_hash_from_id(user_id=user_id, 
                        password=str(decrypted_password, 'utf-8'))

            except (UserDoesNotExist, DuplicateUsersExist) as error:
                logging.exception(error)
                return '', 403

            user_msisdn_hash = user_msisdn_hash['phoneNumber_hash']
            try:
                user = users.find(msisdn_hash=user_msisdn_hash)
            except Exception as error:
                app.logger.exception(error)
                return '', 500 

            user_shared_key = sync.generate_shared_key()

            user.id = user_id
            user.public_key = user_public_key
            user.msisdn_hash = user_msisdn_hash
            user.shared_key = user_shared_key
            user.mgf1ParameterSpec = mgf1ParameterSpec 
            user.hashingAlgorithm = hashingAlgorithm

            try:
                users.commit(user)
            except Exception as error:
                logging.exception(error)
                return '', 500

            try:
                user_platforms = BEPubLib.get_user_platforms_from_id(user_id=user_id)

                encrypted_shared_key = rsa.SecurityRSA.encrypt_with_key(
                        data=user_shared_key, 
                        public_key=user_public_key,
                        mgf1ParameterSpec=mgf1ParameterSpec, 
                        hashingAlgorithm=hashingAlgorithm)

                #TODO: customize exception just in case issue with encrypting for user

            except Exception as error:
                logging.exception(error)
                return '', 500

            else:
                b64_encoded_shared_key = base64.b64encode(encrypted_shared_key)
                return jsonify({
                    "shared_key": str(b64_encoded_shared_key, 'utf-8'),
                    "user_platforms":user_platforms}), 200


@app.route('/sms/platform/<platform>', methods=['POST'])
def incoming_sms_routing(platform):
    """
    """

    try:
        data = json.loads(request.data, strict=False)
    except Exception as error:
        logging.exception(error)

        return 'poorly formed json', 400
    else:
        if not 'MSISDN' in data:
            return 'missing MSISDN', 400

        if not 'text' in data:
            return 'missing text', 400

        text = data["text"]
        user_msisdn = data["MSISDN"]

        # TODO: consume the lib at this point
        token, user_msisdn_hash = None

        user = users.find(msisdn_hash = user_msisdn_hash)

        shared_key = user.shared_key

        decrypted_text = aes.AESCipher.decrypt(data=text, shared_key=shared_key)

        try:
            publisher.publish(text=text, token=token)
        except Exception as error:
            logging.exception(error)

            return '', 400
        else:
            return 'published!', 200
