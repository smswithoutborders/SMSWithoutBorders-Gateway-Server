#!/usr/bin/env python3

# Use this for IDEs to check data types
#https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS

from src import sync, ip_grap, socket_sessions
from src.users import Users
from src.users_entity import UsersEntity

import os
import json
import logging
import threading

from SwobBackendPublisher import MySQL, Lib

__api_version_number = 2

RSA_PR_KEY = os.environ.get("RSA_PR_KEY")

HOST = os.environ.get("HOST")
PORT = os.environ.get("PORT")
SOCK_PORT = os.environ.get("SOCK_PORT")

MYSQL_HOST="localhost" if not os.environ.get("MYSQL_HOST") else os.environ.get("MYSQL_HOST")
MYSQL_USER="root" if not os.environ.get("MYSQL_USER") else os.environ.get("MYSQL_USER")
MYSQL_PASSWORD= os.environ["MYSQL_PASSWORD"]
MYSQL_DATABASE= os.environ["MYSQL_DATABASE"]
MYSQL_GATEWAY_SERVER_DATABASE= os.environ["MYSQL_GS_DATABASE"]

"""
For BE-Pub lib
"""
usersBEPUB = UsersEntity(
        mysql_host= MYSQL_HOST,
        mysql_user = MYSQL_USER,
        mysql_password = MYSQL_PASSWORD,
        mysql_database = MYSQL_DATABASE)

users_be_pub = Lib(usersBEPUB.db)

usersEntity = UsersEntity(
        mysql_host= MYSQL_HOST,
        mysql_user = MYSQL_USER,
        mysql_password = MYSQL_PASSWORD,
        mysql_database = MYSQL_GATEWAY_SERVER_DATABASE)

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

"""
@app.route('/sms/platform/<platform>', methods=['POST'])
"""

@app.route('/v%s/sync/users/<user_id>' % (__api_version_number), methods=['GET'])
def get_sync_url(user_id: str):
    """
    TODO: validate user_id before having it in production
    """
    try:
        port = app.config["SOCK_PORT"]
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
            user_public_key = data['public_key']

            decrypted_password = rsa.decrypt(data['password'], 
                    decryption_hash=decryption_hash, hashingAlgorithm=hashingAlgorithm)

            user = users.instance(user_id=user_id)

            try:
                shared_key = sync.generate_shared_key()

                users.store_shared_key(shared_key)

            except Exception as error:
                logging.exception(error)
                return '', 500

            try:
                user_platforms = users.get_platforms()
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
            return '', 500 
