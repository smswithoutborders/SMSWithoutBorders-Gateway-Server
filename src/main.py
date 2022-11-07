#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS

from src import sync, ip_grap, socket_sessions

import os
import json
import logging
import threading

__api_version_number = 2

RSA_PR_KEY = os.environ.get("RSA_PR_KEY")
HOST = os.environ.get("HOST")
PORT = os.environ.get("PORT")
SOCK_PORT = os.environ.get("SOCK_PORT")

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

        decryption_hash = data['decryption_hash'] if 'decryption_hash' in data else 'sha1'
        try:
            decrypted_password = rsa.decrypt(data['password'], decryption_hash=decryption_hash)
            # Figure out exception for error whil decrypting
        except Exception as error:
            return '', 403 

    """
    return jsonify(
            {
                "shared_key": encrypted_shared_key.decode('utf-8'),
                "user_platforms": user_platforms,
                "seeds_url": gateway_server_seeds_url
                }), 200
    """
    return '', 200
