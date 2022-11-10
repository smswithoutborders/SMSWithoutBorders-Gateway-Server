#!/usr/bin/env python3

# Use this for IDEs to check data types
#https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS

from src import sync
from sockets import ip_grap

from src.users import Users

from src.users_entity import UsersEntity

import os
import json
import logging
import threading

from SwobBackendPublisher import MySQL, Lib

__api_version_number = 2

HOST = os.environ.get("HOST")
PORT = os.environ.get("PORT")
SOCK_PORT = os.environ.get("SOCK_PORT")
RSA_PR_KEY = os.environ.get("RSA_PR_KEY")


# Required for BE-Publisher Lib
MYSQL_BE_HOST="localhost" if not os.environ.get("MYSQL_BE_HOST") else os.environ.get("MYSQL_BE_HOST")
MYSQL_BE_USER="root" if not os.environ.get("MYSQL_BE_USER") else os.environ.get("MYSQL_BE_USER")
MYSQL_BE_PASSWORD= os.environ["MYSQL_BE_PASSWORD"]
MYSQL_BE_DATABASE= os.environ["MYSQL_BE_DATABASE"]

# Required for storing user encryption information
MYSQL_HOST="localhost" if not os.environ.get("MYSQL_HOST") else os.environ.get("MYSQL_HOST")
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

users_be_pub = Lib(usersBEPUB.db)

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


        # TODO:  does not work well with docker
        host = socket_sessions.get_host(app.config["HOST"])

        sockets_url = sync.get_sockets_sessions_url(user_id=user_id, host=host, port=SOCK_PORT)
    except Exception as error:
        app.logger.exception(error)
        return '', 500
    else:
        return sockets_url, 200


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

            """
            decrypted_password = rsa.decrypt(data['password'], 
                    decryption_hash=decryption_hash, hashingAlgorithm=hashingAlgorithm)
            """
            decrypted_password = None
            
            user_public_key = data['public_key']
            user_msisdn_hash = None

            user = users.find(msisdn_hash=user_msisdn_hash)
            user.id = user_id
            user_shared_key = sync.generate_shared_key()

            user.public_key = user_public_key
            user.msisdn_hash = user_msisdn_hash
            user.shared_key = user_shared_key

            try:
                users.commit(user)
            except Exception as error:
                logging.exception(error)
                return '', 500

            try:
                user_platforms = users.get_platforms(user)

                encrypted_shared_key = rsa.encrypt_with_key(
                        data=shared_key, 
                        public_key=user_public_key,
                        mgf1ParameterSpec=mgf1ParameterSpec, 
                        hashingAlgorithm=hashingAlgorithm)

                #TODO: customize exception just in case issue with encrypting for user

            except Exception as error:
                logging.exception(error)
                return '', 500

            else:
                return jsonify({
                    "shared_key":encrypted_shared_key.decode('utf-8'),
                    "user_platforms":user_platforms}), 200

            # TODO if error decrypting should have 500
            # TODO exception for bad decryption
        except Exception as error:
            logging.exception(error)
            return '', 500 


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

        decrypted_text = AES.decrypt(data=text, shared_key=shared_key)

        try:
            publisher.publish(text=text, token=token)
        except Exception as error:
            logging.exception(error)

            return '', 400
        else:
            return 'published!', 200
